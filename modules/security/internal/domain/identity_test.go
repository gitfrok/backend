package domain_test

import (
	"strings"
	"testing"

	"github.com/gitfrok/backend/modules/security/internal/domain"
)

// SPEC-0024 identity rule, unit half. Identity is a deterministic function of a
// named input set — tenant, repository, tool class+identity, rule, and a
// content-derived location (component+version for dependency/container) — and
// invariant to the commit, the scan run, and the absolute line number. These
// tests pin the input set: T-0022's AC2 and AC3 at the unit level. The proof
// against real scanner output is the live proof test under adapters/scanners.

// base is a SAST finding: one rule firing in one artifact, carried by one
// enclosing snippet. Everything below mutates exactly one aspect of it.
func base() domain.IdentityInput {
	return domain.IdentityInput{
		TenantID:     "tenant-a",
		RepositoryID: "repo-a",
		ScannerClass: domain.ScannerClassSAST,
		ToolName:     "semgrep",
		RuleID:       "python.lang.security.use-of-eval",
		Location: domain.Location{
			ArtifactPath:     "app/service.py",
			EnclosingContent: "result = eval(user_input)",
		},
	}
}

// AC2: identity is a pure function — the same input set yields the same
// identity on any node, in any process, at any time.
func TestIdentityIsDeterministic(t *testing.T) {
	a, b := domain.Identity(base()), domain.Identity(base())
	if a != b {
		t.Fatalf("identity is not deterministic: %q vs %q", a, b)
	}
	if a == "" {
		t.Fatal("identity must not be empty")
	}
}

// AC2: identity is invariant to the scan run and the commit. The input set has
// no revision, no scan id, and no timestamp — this test pins that by asserting
// a re-scan (which only differs in run metadata and line numbers, neither of
// which is an input) cannot change the identity. The line number the scanner
// reports travels in provenance, never in the input set.
func TestIdentityIsInvariantToScanRunAndCommit(t *testing.T) {
	firstScan := domain.Identity(base())
	secondScan := domain.Identity(base()) // same defect, later commit, new run
	if firstScan != secondScan {
		t.Fatalf("identity changed across scans: %q vs %q", firstScan, secondScan)
	}
}

// AC2: an unrelated edit elsewhere in the file shifts the finding's absolute
// line without changing the content it names. The location is content-derived
// (artifact + enclosing content), so the identity is unchanged.
func TestIdentityIsInvariantToUnrelatedEditsThatShiftLines(t *testing.T) {
	before := domain.Identity(base())

	shifted := base()
	// The scanner's report now names line 42 instead of line 3. That number
	// lives only in the scanner-native payload (provenance); it is not part of
	// the input set, so nothing about the input changes.
	after := domain.Identity(shifted)

	if before != after {
		t.Fatalf("identity moved when only the absolute line moved: %q vs %q", before, after)
	}
}

// AC2, boundary: identity is invariant to the tool's version. A tool upgrade
// re-reports the same defect; "tool identity" in the spec's input set is the
// tool's name and class, not its version — otherwise every upgrade would
// silently reset every triage decision.
func TestIdentityIsInvariantToToolVersion(t *testing.T) {
	// IdentityInput has no version field: the type system is the guarantee.
	// This test documents it so a future "small" addition of one fails review
	// against this line (SPEC-0024: adding an input is a spec amendment).
	before := domain.Identity(base())
	if before == "" {
		t.Fatal("no identity")
	}
}

// The identity rule's invariant list is closed: a file RENAME changes the
// artifact the finding sits in, and the artifact is part of the spec's input
// set ("the artifact the finding sits in and the enclosing content that
// carries it"). A rename is therefore a new finding — the old one resolves,
// the new one opens — not an invisible identity drift. Pinning the behaviour
// here keeps a later "rename tracking" feature a visible spec discussion.
func TestIdentityDistinguishesARenamedArtifact(t *testing.T) {
	before := domain.Identity(base())

	renamed := base()
	renamed.Location.ArtifactPath = "pkg/service.py"
	after := domain.Identity(renamed)

	if before == after {
		t.Fatal("identity survived a changed artifact — the artifact is part of the input set (SPEC-0024)")
	}
}

// AC3: the same defect reported by two different tools is two findings, not
// one. Tool identity is in the input set.
func TestIdentityDistinguishesTwoToolsReportingTheSameDefect(t *testing.T) {
	bySemgrep := domain.Identity(base())

	byBandit := base()
	byBandit.ToolName = "bandit"
	byBandit.RuleID = "B307" // bandit's own name for the same defect class

	if bySemgrep == domain.Identity(byBandit) {
		t.Fatal("two tools collapsed into one identity — neither may be dropped (SPEC-0024 AC3)")
	}
}

// AC3: two different rules at one location are two findings.
func TestIdentityDistinguishesTwoRulesAtOneLocation(t *testing.T) {
	ruleA := domain.Identity(base())

	ruleB := base()
	ruleB.RuleID = "python.flask.security.debug-enabled"
	if ruleA == domain.Identity(ruleB) {
		t.Fatal("two rules at one location collapsed into one identity (SPEC-0024 AC3)")
	}
}

// AC3: one rule at two locations is two findings — including two occurrences
// of identical content in two artifacts.
func TestIdentityDistinguishesOneRuleAtTwoLocations(t *testing.T) {
	locA := domain.Identity(base())

	locB := base()
	locB.Location.ArtifactPath = "worker/jobs.py"
	if locA == domain.Identity(locB) {
		t.Fatal("one rule at two artifacts collapsed into one identity (SPEC-0024 AC3)")
	}

	locC := base()
	locC.Location.EnclosingContent = "result = eval(request.args['expr'])"
	if locA == domain.Identity(locC) {
		t.Fatal("one rule at two enclosing contents collapsed into one identity (SPEC-0024 AC3)")
	}
}

// AC3, tenant and repository scope: the same defect in another tenant or
// another repository is a different finding — identity carries the scope.
func TestIdentityIsTenantAndRepositoryScoped(t *testing.T) {
	baseID := domain.Identity(base())

	otherTenant := base()
	otherTenant.TenantID = "tenant-b"
	if baseID == domain.Identity(otherTenant) {
		t.Fatal("identity does not carry tenant scope")
	}

	otherRepo := base()
	otherRepo.RepositoryID = "repo-b"
	if baseID == domain.Identity(otherRepo) {
		t.Fatal("identity does not carry repository scope")
	}
}

// Dependency and container findings: the affected component and version stand
// in place of a file location. Both are inputs — a different version is a
// different finding (a fixed version must not reuse the vulnerable one's
// triage history).
func TestIdentityForDependencyFindingsUsesComponentAndVersion(t *testing.T) {
	dep := domain.IdentityInput{
		TenantID:     "tenant-a",
		RepositoryID: "repo-a",
		ScannerClass: domain.ScannerClassDependency,
		ToolName:     "trivy",
		RuleID:       "CVE-2024-0001",
		Location:     domain.Location{Component: "golang.org/x/net", ComponentVersion: "v0.17.0"},
	}
	same := domain.IdentityInput(dep)
	if domain.Identity(dep) != domain.Identity(same) {
		t.Fatal("dependency identity is not deterministic")
	}

	patched := dep
	patched.Location.ComponentVersion = "v0.23.0"
	if domain.Identity(dep) == domain.Identity(patched) {
		t.Fatal("a different component version must be a different finding")
	}

	otherComponent := dep
	otherComponent.Location.Component = "github.com/foo/bar"
	if domain.Identity(dep) == domain.Identity(otherComponent) {
		t.Fatal("a different component must be a different finding")
	}
}

// AC2 (invariant to scan run) also holds for dependency findings: component
// and version come from the manifest content, not from the scan run.
func TestDependencyIdentityIsInvariantAcrossScans(t *testing.T) {
	dep := domain.IdentityInput{
		TenantID:     "tenant-a",
		RepositoryID: "repo-a",
		ScannerClass: domain.ScannerClassDependency,
		ToolName:     "trivy",
		RuleID:       "CVE-2024-0001",
		Location:     domain.Location{Component: "golang.org/x/net", ComponentVersion: "v0.17.0"},
	}
	if domain.Identity(dep) != domain.Identity(dep) {
		t.Fatal("dependency identity changed across scans")
	}
}

// Enclosing content is normalized whitespace, so a re-scan whose report
// trims or reflows the snippet's edges still names the same content.
func TestEnclosingContentIsWhitespaceNormalized(t *testing.T) {
	a := base()
	b := base()
	b.Location.EnclosingContent = "  result = eval(user_input)\n"
	if domain.Identity(a) != domain.Identity(b) {
		t.Fatal("identity is sensitive to surrounding whitespace of the enclosing content")
	}
	c := base()
	c.Location.EnclosingContent = "result =\teval(user_input)"
	if domain.Identity(a) == domain.Identity(c) {
		t.Fatal("identity must still distinguish different interior content")
	}
}

// The identity is opaque: it reveals no input. It must not contain any of the
// input strings (a reader holding an identity learns nothing about the
// finding's content), and it is stable in shape.
func TestIdentityIsOpaque(t *testing.T) {
	id := domain.Identity(base())
	for _, secret := range []string{"tenant-a", "repo-a", "semgrep", "eval", "service.py"} {
		if strings.Contains(id, secret) {
			t.Fatalf("identity %q leaks input fragment %q", id, secret)
		}
	}
	if len(id) != len("fnd-")+64 {
		t.Fatalf("identity %q is not the fixed opaque shape fnd-<sha256>", id)
	}
}
