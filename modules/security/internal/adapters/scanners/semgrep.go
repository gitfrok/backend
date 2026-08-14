package scanners

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gitfrok/backend/modules/security/api"
)

// Semgrep adapts Semgrep's native JSON report (semgrep scan --json) to the
// normalized model, class SAST.
//
// Location is content-derived per SPEC-0024: the enclosing content is the
// matched source text itself, sliced from the scanned tree at the report's
// byte offsets. The line and column numbers the report also carries are
// identity-irrelevant by the same spec — they ride only in provenance.
type Semgrep struct {
	// Root is the scanned tree the report's paths are relative to. Empty
	// means the current directory.
	Root string
}

func (Semgrep) Class() api.ScannerClass { return api.ScannerClassSAST }
func (Semgrep) ToolName() string        { return "semgrep" }

// ToolVersion returns the version the report names.
func (Semgrep) ToolVersion(report []byte) string {
	var header struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(report, &header); err != nil {
		return ""
	}
	return header.Version
}

// semgrepReport is the native shape. Only the fields the normalized model
// can absorb are decoded; everything else survives in provenance.
type semgrepReport struct {
	Results []semgrepResult `json:"results"`
}

type semgrepResult struct {
	CheckID string `json:"check_id"`
	Path    string `json:"path"`
	Start   struct {
		Offset int `json:"offset"`
	} `json:"start"`
	End struct {
		Offset int `json:"offset"`
	} `json:"end"`
	Extra struct {
		Severity string `json:"severity"`
	} `json:"extra"`
}

// Parse converts the report. Provenance is the finding's own native object,
// re-marshalled byte-identical-shape with the media type attached
// (SPEC-0025 AC6).
func (s Semgrep) Parse(report []byte) ([]api.RawFinding, error) {
	var native semgrepReport
	if err := json.Unmarshal(report, &native); err != nil {
		return nil, fmt.Errorf("semgrep: decode report: %w", err)
	}
	out := make([]api.RawFinding, 0, len(native.Results))
	for _, r := range native.Results {
		if r.CheckID == "" || r.Path == "" {
			continue
		}
		provenance, err := json.Marshal(r)
		if err != nil {
			return nil, fmt.Errorf("semgrep: provenance: %w", err)
		}
		out = append(out, api.RawFinding{
			RuleID:   r.CheckID,
			Severity: semgrepSeverity(r.Extra.Severity),
			Location: api.Location{
				ArtifactPath:     filepath.ToSlash(r.Path),
				EnclosingContent: s.enclosingContent(r),
			},
			Provenance:          provenance,
			ProvenanceMediaType: provenanceJSON,
		})
	}
	return out, nil
}

// enclosingContent slices the matched source text out of the scanned tree.
// Reading content — never line numbers — is what keeps identity invariant to
// line drift (SPEC-0024 AC2). The report's path is untrusted input: it is
// cleaned and confined to the scanned root before anything reads it. An
// unreadable file degrades to an empty enclosing content rather than
// failing the whole report.
func (s Semgrep) enclosingContent(r semgrepResult) string {
	root := s.Root
	if root == "" {
		root = "."
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return ""
	}
	target := filepath.Join(absRoot, filepath.FromSlash(filepath.Clean("/"+r.Path)))
	if !strings.HasPrefix(target, absRoot+string(filepath.Separator)) && target != absRoot {
		return ""
	}
	data, err := os.ReadFile(target)
	if err != nil {
		return ""
	}
	start, end := r.Start.Offset, r.End.Offset
	if start < 0 || end <= start || end > len(data) {
		return ""
	}
	return strings.TrimSpace(string(data[start:end]))
}

// semgrepSeverity maps Semgrep's three native severities onto the normalized
// scale. The native value itself survives in provenance.
func semgrepSeverity(s string) api.Severity {
	switch strings.ToUpper(s) {
	case "ERROR":
		return api.SeverityHigh
	case "WARNING":
		return api.SeverityMedium
	case "INFO", "INVENTORY":
		return api.SeverityLow
	default:
		return api.SeverityMedium
	}
}
