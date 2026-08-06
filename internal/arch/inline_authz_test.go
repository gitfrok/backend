package arch

import (
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestNoInlinePermissionChecks is the SPEC-0002 AC4 fitness function: the shipped tree contains no
// authorization logic outside the Policy context.
//
// modules/policy and internal/arch are excluded by ScanAuthz itself — one is where the decision
// belongs, the other is this checker, which necessarily spells out the patterns it looks for.
func TestNoInlinePermissionChecks(t *testing.T) {
	root := repoRoot(t)
	fset := token.NewFileSet()
	var found []Violation

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			// gen/ is generated from contracts and hand-editing it is forbidden anyway;
			// testdata holds the fixtures that must fail.
			case "gen", "testdata", "node_modules", ".git":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		vs, err := ScanAuthz(fset, path)
		if err != nil {
			return err
		}
		found = append(found, vs...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, v := range found {
		t.Errorf("inline permission check: %s: %s (%s) — authorization belongs to the PDP "+
			"(invariant 2, ADR-0006). If this genuinely decides no access, waive it on the line "+
			"with //arch:allow-inline-authz <reason>", v.File, v.Import, v.Rule)
	}
}

// TestInlinePermissionChecksAreRejected: each bad fixture must be caught. Without this the tree
// scan above would pass vacuously if the matcher were broken — the same reverse test the other
// boundary rules carry.
func TestInlinePermissionChecksAreRejected(t *testing.T) {
	for _, tc := range []struct {
		fixture string
		want    string
	}{
		{"bad_inline_authz_func.go.txt", "func hasPermission"},
		{"bad_inline_authz_role.go.txt", `comparison against role "owner"`},
	} {
		t.Run(tc.fixture, func(t *testing.T) {
			file := placeFixture(t, tc.fixture, "modules/example/internal/app")
			vs, err := ScanAuthz(token.NewFileSet(), file)
			if err != nil {
				t.Fatal(err)
			}
			if len(vs) == 0 {
				t.Fatalf("%s produced no violation; the gate is vacuous", tc.fixture)
			}
			var got []string
			for _, v := range vs {
				if v.Rule != RuleInlinePermissionCheck {
					t.Errorf("rule = %q, want %q", v.Rule, RuleInlinePermissionCheck)
				}
				got = append(got, v.Import)
			}
			if !slices.Contains(got, tc.want) {
				t.Errorf("violations %v, want one naming %q", got, tc.want)
			}
		})
	}
}

// TestLegitimateCodeIsNotRejected is the other half, and it matters as much. A rule that fires on
// correct code is waived everywhere within a week, and a rule waived everywhere is off.
func TestLegitimateCodeIsNotRejected(t *testing.T) {
	for _, fixture := range []string{
		"good_authz_via_pdp.go.txt",
		"good_ordinary_names.go.txt",
		"good_inline_authz_waived.go.txt",
	} {
		t.Run(fixture, func(t *testing.T) {
			file := placeFixture(t, fixture, "modules/example/internal/app")
			vs, err := ScanAuthz(token.NewFileSet(), file)
			if err != nil {
				t.Fatal(err)
			}
			for _, v := range vs {
				t.Errorf("false positive: %s flagged %q", fixture, v.Import)
			}
		})
	}
}

// The waiver must be narrow. If it covered a whole function or file, a second inline check would
// drift in underneath an exception granted for the first one and nobody would see it.
func TestWaiverDoesNotCoverTheRestOfTheFile(t *testing.T) {
	src := `package fixture

func label(role string) string {
	//arch:allow-inline-authz display label only
	if role == "owner" {
		return "Owner"
	}
	// No waiver here.
	if role == "member" {
		return "Member"
	}
	return role
}
`
	file := filepath.Join(t.TempDir(), "fixture.go")
	if err := os.WriteFile(file, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	vs, err := ScanAuthz(token.NewFileSet(), file)
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) != 1 {
		t.Fatalf("got %d violations %v, want exactly 1 — the waived line excused, the other not", len(vs), vs)
	}
	if !strings.Contains(vs[0].Import, "member") {
		t.Errorf("violation %q, want the unwaived \"member\" comparison", vs[0].Import)
	}
}

// A bare marker with no reason must not silence the rule. The reason is the part review assesses;
// without it the waiver is just a way to switch the gate off quietly.
func TestWaiverWithoutAReasonDoesNotCount(t *testing.T) {
	src := `package fixture

func label(role string) string {
	//arch:allow-inline-authz
	if role == "owner" {
		return "Owner"
	}
	return role
}
`
	file := filepath.Join(t.TempDir(), "fixture.go")
	if err := os.WriteFile(file, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	vs, err := ScanAuthz(token.NewFileSet(), file)
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) != 1 {
		t.Errorf("got %d violations, want 1: a waiver with no reason must not count", len(vs))
	}
}

// The Policy context is where authorization logic belongs, so the rule must not fire there — else
// the only correct place to write it would be the one place the gate forbids.
func TestPolicyModuleIsExempt(t *testing.T) {
	file := placeFixture(t, "bad_inline_authz_role.go.txt", "modules/policy/internal/app")
	vs, err := ScanAuthz(token.NewFileSet(), file)
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) != 0 {
		t.Errorf("the Policy context was flagged: %v", vs)
	}
}
