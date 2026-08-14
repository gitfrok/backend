package scanners

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/gitfrok/backend/modules/security/api"
)

// Gitleaks adapts gitleaks' native JSON report (gitleaks detect -f json) to
// the normalized model, class SECRETS.
//
// Location is content-derived per SPEC-0024: artifact path plus the matched
// content with the secret itself redacted out. The redaction matters twice:
// the secret never becomes part of a finding identity (identities are
// readable, queryable, and carried in events), and two distinct secrets in
// the same file by the same rule still get distinct identities. Commit,
// line numbers, author, and fingerprint are all identity-irrelevant under
// the same spec; they survive only in provenance.
type Gitleaks struct{}

func (Gitleaks) Class() api.ScannerClass { return api.ScannerClassSecrets }
func (Gitleaks) ToolName() string        { return "gitleaks" }

// ToolVersion returns "": gitleaks' report format carries no version. The
// scan descriptor names it out-of-band.
func (Gitleaks) ToolVersion([]byte) string { return "" }

// gitleaksFinding is the native shape of one report entry. Only fields the
// normalized model can absorb are named; the whole entry still rides in
// provenance.
type gitleaksFinding struct {
	RuleID string `json:"RuleID"`
	File   string `json:"File"`
	Match  string `json:"Match"`
	Secret string `json:"Secret"`
}

// Parse converts the report. An empty report is a valid empty report:
// gitleaks prints `[]` when it finds nothing.
func (Gitleaks) Parse(report []byte) ([]api.RawFinding, error) {
	var native []gitleaksFinding
	if err := json.Unmarshal(report, &native); err != nil {
		return nil, fmt.Errorf("gitleaks: decode report: %w", err)
	}
	out := make([]api.RawFinding, 0, len(native))
	for _, f := range native {
		if f.RuleID == "" || f.File == "" {
			continue
		}
		provenance, err := json.Marshal(f)
		if err != nil {
			return nil, fmt.Errorf("gitleaks: provenance: %w", err)
		}
		out = append(out, api.RawFinding{
			RuleID:   f.RuleID,
			Severity: api.SeverityHigh,
			Location: api.Location{
				ArtifactPath:     filepath.ToSlash(f.File),
				EnclosingContent: redactSecret(f.Match, f.Secret),
			},
			Provenance:          provenance,
			ProvenanceMediaType: provenanceJSON,
		})
	}
	return out, nil
}

// redactSecret removes the secret value from the matched content so the
// identity input set never carries secret material.
func redactSecret(match, secret string) string {
	s := strings.TrimSpace(match)
	if secret != "" {
		s = strings.ReplaceAll(s, secret, "[REDACTED]")
	}
	return s
}
