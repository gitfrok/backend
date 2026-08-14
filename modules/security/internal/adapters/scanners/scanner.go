// Package scanners adapts scanner-native reports to the normalized finding
// model (SPEC-0024 AC1). The adapters are dumb parsers: they translate a
// tool's JSON report into RawFindings and carry the tool-native payload
// into provenance bytes. They never compute identities — identity is the
// service's job (SPEC-0025 AC3) — and no scanner-specific field survives
// into the normalized shape: whatever a tool knows beyond rule, severity,
// and content-derived location crosses only inside Provenance (SPEC-0024
// AC6).
package scanners

import (
	"github.com/gitfrok/backend/modules/security/api"
)

// Scanner is the port every scanner adapter satisfies. One adapter per tool;
// the normalized model is what everything downstream sees.
type Scanner interface {
	// Class is the scanner class the tool reports under (SPEC-0024 AC1).
	Class() api.ScannerClass
	// ToolName is the tool's identity. Part of the finding identity input
	// set: the same defect reported by two tools is two findings
	// (SPEC-0024 AC3).
	ToolName() string
	// ToolVersion reports the version the report itself names, or "" when
	// the format carries none. Version is NOT an identity input — an
	// upgrade re-reports the same defect — but it names what scanned.
	ToolVersion(report []byte) string
	// Parse converts one native report into normalized findings. The
	// per-finding native payload round-trips byte-for-byte in Provenance
	// under its media type.
	Parse(report []byte) ([]api.RawFinding, error)
}

// All is the adapter registry the composition root and the live proofs draw
// from. Adding a tool is an addition here, never a change to an adapter.
func All() []Scanner {
	return []Scanner{Semgrep{}, Gitleaks{}}
}

// provenanceJSON is the media type every native payload here carries: each
// adapter re-marshals the finding's own native object, so provenance
// round-trips with its type (SPEC-0025 AC6).
const provenanceJSON = "application/json"
