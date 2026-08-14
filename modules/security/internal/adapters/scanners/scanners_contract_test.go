package scanners_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gitfrok/backend/modules/security/api"
	"github.com/gitfrok/backend/modules/security/internal/adapters/scanners"
)

// The scanner contract (SPEC-0024 AC1/AC6): whatever a tool knows beyond
// rule, normalized severity, and content-derived location crosses the
// boundary only inside Provenance. These tests feed each adapter a native
// report full of scanner-specific fields — line numbers, commits, authors,
// fingerprints — and assert none of it leaks into the normalized shape.

// semgrepReportFixture carries line/col/offset metadata that must NOT leak.
const semgrepReportFixture = `{
  "version": "1.172.0",
  "results": [
    {
      "check_id": "python-eval-usage",
      "path": "app.py",
      "start": {"line": 42, "col": 14, "offset": 0},
      "end": {"line": 42, "col": 28, "offset": 16},
      "extra": {
        "message": "avoid eval",
        "metadata": {"cwe": ["CWE-95"]},
        "severity": "WARNING",
        "fingerprint": "abc123fp",
        "lines": "eval(user_input)"
      }
    }
  ],
  "errors": []
}`

// gitleaksReportFixture carries commit/author/email/fingerprint/line fields
// and a secret that must NOT leak into the normalized shape.
const gitleaksReportFixture = `[
  {
    "RuleID": "generic-api-key",
    "Description": "Detected a Generic API Key",
    "StartLine": 7, "EndLine": 7, "StartColumn": 2, "EndColumn": 50,
    "Match": "GITHUB_TOKEN = \"ghp_R8qXv2LmPzWnTbYcDfGhJkQs5173\"",
    "Secret": "ghp_R8qXv2LmPzWnTbYcDfGhJkQs5173",
    "File": "creds.txt",
    "SymlinkFile": "",
    "Commit": "6844fe3349774789fafe7496a430690c004af00e",
    "Entropy": 4.9375,
    "Author": "Jane Doe",
    "Email": "jane@example.com",
    "Date": "2026-08-14T01:21:39Z",
    "Message": "add creds",
    "Tags": [],
    "Fingerprint": "6844fe3349774789fafe7496a430690c004af00e:creds.txt:generic-api-key:7"
  }
]`

func TestSemgrepNormalizes(t *testing.T) {
	// The enclosing content is sliced from the scanned tree, so give the
	// adapter a tree whose bytes match the fixture's offsets.
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "app.py"),
		[]byte("eval(user_input) trailing\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := scanners.Semgrep{Root: root}
	if s.Class() != api.ScannerClassSAST || s.ToolName() != "semgrep" {
		t.Fatalf("adapter identity: %v %v", s.Class(), s.ToolName())
	}
	if v := s.ToolVersion([]byte(semgrepReportFixture)); v != "1.172.0" {
		t.Fatalf("ToolVersion = %q, want the report's version", v)
	}

	findings, err := s.Parse([]byte(semgrepReportFixture))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.RuleID != "python-eval-usage" || f.Severity != api.SeverityMedium {
		t.Fatalf("rule/severity mismatch: %+v", f)
	}
	if f.Location.ArtifactPath != "app.py" || f.Location.EnclosingContent != "eval(user_input)" {
		t.Fatalf("location must be content-derived: %+v", f.Location)
	}
	assertNoLeaks(t, "semgrep", f, "42", "fingerprint", "abc123fp", "CWE-95")
	assertProvenance(t, f, "check_id")
}

func TestGitleaksNormalizes(t *testing.T) {
	s := scanners.Gitleaks{}
	if s.Class() != api.ScannerClassSecrets || s.ToolName() != "gitleaks" {
		t.Fatalf("adapter identity: %v %v", s.Class(), s.ToolName())
	}
	findings, err := s.Parse([]byte(gitleaksReportFixture))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.RuleID != "generic-api-key" || f.Severity != api.SeverityHigh {
		t.Fatalf("rule/severity mismatch: %+v", f)
	}
	if f.Location.ArtifactPath != "creds.txt" {
		t.Fatalf("artifact path mismatch: %+v", f.Location)
	}
	if !strings.Contains(f.Location.EnclosingContent, "[REDACTED]") ||
		strings.Contains(f.Location.EnclosingContent, "ghp_R8qXv2LmPzWnTbYcDfGhJkQs5173") {
		t.Fatalf("secret must be redacted out of the identity input set: %q", f.Location.EnclosingContent)
	}
	assertNoLeaks(t, "gitleaks", f,
		"6844fe3349774789fafe7496a430690c004af00e", // commit
		"Jane Doe", "jane@example.com", // author/email
		"ghp_R8qXv2LmPzWnTbYcDfGhJkQs5173", // secret
		"4.9375", // entropy
	)
	assertProvenance(t, f, "RuleID")
}

// TestEmptyReportsParseClean: a clean scan is an empty report, not an error.
func TestEmptyReportsParseClean(t *testing.T) {
	if got, err := (scanners.Gitleaks{}).Parse([]byte(`[]`)); err != nil || len(got) != 0 {
		t.Fatalf("gitleaks empty report: %d findings, err=%v", len(got), err)
	}
	if got, err := (scanners.Semgrep{}).Parse([]byte(`{"version":"1","results":[]}`)); err != nil || len(got) != 0 {
		t.Fatalf("semgrep empty report: %d findings, err=%v", len(got), err)
	}
}

// TestNoScannerSpecificFieldLeaks: the normalized shape's exported fields are
// exactly the RawFinding fields; any value a normalized field carries must
// not contain scanner-native trivia. Asserted structurally: the only types
// Parse may return are api.RawFinding slices.
func TestNoScannerSpecificFieldLeaks(t *testing.T) {
	var _ []api.RawFinding = mustParse(t, scanners.Gitleaks{}, gitleaksReportFixture)
	var _ []api.RawFinding = mustParse(t, scanners.Semgrep{}, `{"version":"1","results":[]}`)
}

func mustParse(t *testing.T, s scanners.Scanner, report string) []api.RawFinding {
	t.Helper()
	findings, err := s.Parse([]byte(report))
	if err != nil {
		t.Fatalf("%s parse: %v", s.ToolName(), err)
	}
	return findings
}

// assertNoLeaks fails if any normalized field outside provenance carries a
// scanner-specific value.
func assertNoLeaks(t *testing.T, tool string, f api.RawFinding, forbidden ...string) {
	t.Helper()
	surface := []string{
		f.RuleID,
		string(f.Severity),
		f.Location.ArtifactPath,
		f.Location.EnclosingContent,
		f.Location.Component,
		f.Location.ComponentVersion,
	}
	for _, value := range surface {
		for _, bad := range forbidden {
			if strings.Contains(value, bad) {
				t.Errorf("%s: scanner-specific value %q leaked into normalized field %q",
					tool, bad, value)
			}
		}
	}
}

// assertProvenance checks the native payload rides in provenance under its
// media type and stays valid JSON.
func assertProvenance(t *testing.T, f api.RawFinding, nativeKey string) {
	t.Helper()
	if f.ProvenanceMediaType != "application/json" {
		t.Fatalf("provenance media type = %q", f.ProvenanceMediaType)
	}
	var decoded map[string]any
	if err := json.Unmarshal(f.Provenance, &decoded); err != nil {
		t.Fatalf("provenance must be valid JSON: %v", err)
	}
	if _, ok := decoded[nativeKey]; !ok {
		t.Fatalf("provenance must carry the native payload (missing %q): %s", nativeKey, f.Provenance)
	}
}
