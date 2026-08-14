package opa

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gitfrok/backend/modules/policy/api"
)

// request returns a well-formed request the fixture bundle grants. Each test mutates one field, so
// a failure names the field responsible.
func request() api.Request {
	return api.Request{
		TenantID: "acme",
		Subject:  api.Subject{ID: "u-1", TenantID: "acme", Roles: []string{"reader"}},
		Action:   "repo.read",
		Resource: api.Resource{Type: "repository", ID: "repo-1"},
		Context:  map[string]string{},
	}
}

func newPDP(t *testing.T) *PDP {
	t.Helper()
	p, err := New(filepath.Join("testdata", "bundle"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

// --- SPEC-0002 AC1: deny-by-default ------------------------------------------------------------

// The zero request is the sharpest form: nothing was asserted, so nothing is granted. It must be a
// clean denial and not an error — an evaluation failure and a policy denial are different events,
// and only one of them means "the PDP is broken".
func TestZeroRequestIsDenied(t *testing.T) {
	p := newPDP(t)
	got, err := p.Decide(t.Context(), api.Request{})
	if err != nil {
		t.Fatalf("Decide: unexpected error %v", err)
	}
	if got.Allowed {
		t.Error("the zero request was allowed; deny-by-default is not holding")
	}
	if got.Reason == "" {
		t.Error("a denial with no reason")
	}
}

func TestUnknownActionIsDenied(t *testing.T) {
	p := newPDP(t)
	req := request()
	req.Action = "repo.exfiltrate"
	got, err := p.Decide(t.Context(), req)
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if got.Allowed {
		t.Error("an action no rule mentions was allowed")
	}
}

func TestGrantedActionIsAllowed(t *testing.T) {
	p := newPDP(t)
	got, err := p.Decide(t.Context(), request())
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if !got.Allowed {
		t.Fatalf("the fixture's granted action was denied (reason %q); the allow path is untested "+
			"if this fails, and every other assertion here would pass vacuously", got.Reason)
	}
}

// --- The input mapping actually reaches the policy ----------------------------------------------

// Every field the port accepts must arrive in the document the policy evaluates. A mapping that
// silently dropped `roles` would make the PDP deny everything, and a mapping that dropped
// `action` would make it answer the wrong question — the second is the dangerous one, because
// the answer still looks like a decision.
func TestRequestFieldsReachThePolicy(t *testing.T) {
	p := newPDP(t)
	// The fixture grants only when BOTH action and roles arrive. Denying after removing each in
	// turn shows the policy saw them in the passing case.
	for _, tc := range []struct {
		name   string
		mutate func(*api.Request)
	}{
		{"roles dropped", func(r *api.Request) { r.Subject.Roles = nil }},
		{"action dropped", func(r *api.Request) { r.Action = "" }},
		{"wrong role", func(r *api.Request) { r.Subject.Roles = []string{"stranger"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := request()
			tc.mutate(&req)
			got, err := p.Decide(t.Context(), req)
			if err != nil {
				t.Fatalf("Decide: %v", err)
			}
			if got.Allowed {
				t.Error("allowed, but this input should not satisfy the fixture's grant")
			}
		})
	}
}

// A nil Context map must not break evaluation. Callers will pass one.
func TestNilContextIsUsable(t *testing.T) {
	p := newPDP(t)
	req := request()
	req.Context = nil
	if _, err := p.Decide(t.Context(), req); err != nil {
		t.Fatalf("a nil Context should be a usable request, got %v", err)
	}
}

// --- SPEC-0002 AC2: the bundle is versioned ------------------------------------------------------

func TestDecisionCarriesBundleRevision(t *testing.T) {
	p := newPDP(t)
	got, err := p.Decide(t.Context(), request())
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if got.PolicyRevision != "test-rev-1" {
		t.Errorf("PolicyRevision = %q, want the fixture manifest's %q", got.PolicyRevision, "test-rev-1")
	}
}

// A bundle with no manifest has no revision, and a PEP would key its cache on "" — so a policy
// change would invalidate nothing. Refuse at construction rather than serve uncacheable decisions
// that look cacheable.
func TestBundleWithoutRevisionIsRefused(t *testing.T) {
	_, err := New(filepath.Join("testdata", "bundle-no-manifest"))
	if err == nil {
		t.Fatal("a bundle with no manifest revision was accepted")
	}
	if !errors.Is(err, ErrNoRevision) {
		t.Errorf("error = %v, want it to wrap ErrNoRevision so callers can tell this apart "+
			"from an unreadable directory", err)
	}
}

func TestBrokenBundleIsRefusedAtConstruction(t *testing.T) {
	if _, err := New(filepath.Join("testdata", "bundle-broken")); err == nil {
		t.Fatal("a bundle that does not compile was accepted; the PDP would start and deny everything")
	}
}

func TestMissingBundleDirIsRefused(t *testing.T) {
	if _, err := New(filepath.Join("testdata", "no-such-dir")); err == nil {
		t.Fatal("a nonexistent bundle directory was accepted")
	}
}

// _test.rego files are governance's tests of the policy, not part of what ships. The fixture's
// test file references a rule that does not exist, so a loader that included it would fail to
// compile — which is what makes this a real assertion rather than a claim about file counts.
func TestBundleExcludesTestFiles(t *testing.T) {
	p := newPDP(t)
	for path := range p.modules {
		if strings.HasSuffix(path, "_test.rego") {
			t.Errorf("bundle contains %s; policy test files must not ship", path)
		}
	}
	if len(p.modules) == 0 {
		t.Fatal("no modules loaded at all — the check above would pass vacuously")
	}
}

// --- Every decision is individually identified ---------------------------------------------------

func TestDecisionIDIsUniquePerDecision(t *testing.T) {
	p := newPDP(t)
	seen := make(map[string]bool)
	for range 100 {
		got, err := p.Decide(t.Context(), request())
		if err != nil {
			t.Fatalf("Decide: %v", err)
		}
		if got.DecisionID == "" {
			t.Fatal("decision has no id; the audit event recording it could not be correlated")
		}
		if seen[got.DecisionID] {
			t.Fatalf("decision id %q reused — two decisions would be indistinguishable in the "+
				"audit trail", got.DecisionID)
		}
		seen[got.DecisionID] = true
	}
}

// --- Failure is a denial, never a fallthrough -----------------------------------------------------

// api.DecisionPoint promises that on error the Decision is the *zero value*, so a caller who
// ignores the error is still denied — ignoring the error being the most common way an
// authorization check gets bypassed. These are the ways a loaded bundle can still fail to produce
// a usable answer.
//
// A cancelled context is deliberately not one of the cases: OPA evaluates a policy this small
// without reaching a cancellation check, so a test built on it would assert a timing accident
// rather than the contract. These fixtures fail deterministically.
func TestEvaluationFailureReturnsZeroDecision(t *testing.T) {
	for _, tc := range []struct {
		name    string
		bundle  string
		wantErr error
	}{
		{"decision undefined", "bundle-no-decision", ErrUndefinedDecision},
		{"decision is not an object", "bundle-decision-not-object", nil},
		{"allow is not a bool", "bundle-allow-not-bool", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := New(filepath.Join("testdata", tc.bundle))
			if err != nil {
				t.Fatalf("New(%s): %v", tc.bundle, err)
			}

			got, err := p.Decide(t.Context(), request())
			if err == nil {
				t.Fatal("no error from a policy that cannot produce a decision")
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Errorf("error = %v, want it to wrap %v", err, tc.wantErr)
			}
			if got.Allowed || got.Reason != "" || got.PolicyRevision != "" || got.DecisionID != "" ||
				got.InputDigest != "" || got.Mode != "" || got.ReliedUponTriage != nil {
				t.Errorf("returned a partially-populated decision %+v; it must be the zero "+
					"value so an ignored error still denies", got)
			}
		})
	}
}

// --- Composition: the real governance bundle loads ------------------------------------------------

// The fixtures above prove the evaluator works. This proves it works on the actual policy — which
// can only be checked where both repos are checked out, so it skips when run standalone.
//
// The skip is deliberate and narrow: governance's own CI already builds that bundle with `opa
// build` and runs its suite, so nothing here is the *only* check on it. What this adds is that
// THIS loader, with its test-file filter and its revision requirement, accepts it.
func TestRealGovernanceBundleLoads(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "..", "..", "..", "governance", "policies")
	if _, err := os.Stat(filepath.Join(dir, ".manifest")); err != nil {
		t.Skipf("governance/policies not checked out beside backend/ (%v); "+
			"the composition-level check is the super-repo's", err)
	}

	p, err := New(dir)
	if err != nil {
		t.Fatalf("the real governance bundle does not load: %v", err)
	}
	if p.revision == "" {
		t.Error("the real bundle carries no revision")
	}

	// And it denies by default, which is the one property this adapter is entitled to assume.
	got, err := p.Decide(t.Context(), api.Request{})
	if err != nil {
		t.Fatalf("Decide against the real bundle: %v", err)
	}
	if got.Allowed {
		t.Error("the real policy allowed the zero request")
	}
}
