package arch

import (
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// repoRoot returns the backend module root (two levels up from internal/arch).
func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Clean(filepath.Join(wd, "..", ".."))
}

// TestNoBoundaryViolations is the fitness function: the real backend tree must contain no
// cross-module internal imports, no infra imports inside domain, and no infra imports on a
// module's api/ surface (invariants 14, 16, 20).
func TestNoBoundaryViolations(t *testing.T) {
	root := repoRoot(t)
	fset := token.NewFileSet()
	var found []Violation
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "gen", "testdata", "node_modules", ".git":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		vs, err := Scan(fset, path)
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
		t.Errorf("boundary violation: %s imports %s (%s)", v.File, v.Import, v.Rule)
	}
}

// placeFixture writes a testdata fixture at relDir under a temp tree and returns its path, so a
// forbidden edge is checked through exactly the same code path as real source.
func placeFixture(t *testing.T, fixture, relDir string) string {
	t.Helper()
	content, err := os.ReadFile(filepath.Join("testdata", fixture))
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), filepath.FromSlash(relDir))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "fixture.go")
	if err := os.WriteFile(file, content, 0o644); err != nil {
		t.Fatal(err)
	}
	return file
}

// TestForbiddenEdgesAreRejected is the reverse test for T-0002 AC1, AC2 and AC4: each fixture
// deliberately violates one rule and must be caught. Without these the tree scan above would pass
// vacuously if the checker were broken.
func TestForbiddenEdgesAreRejected(t *testing.T) {
	cases := []struct {
		name    string
		fixture string
		relDir  string
		want    string
	}{
		{
			name:    "AC1 domain imports infra",
			fixture: "bad_domain_infra.go.txt",
			relDir:  "modules/repository/internal/domain",
			want:    RuleDomainImportsInfra,
		},
		{
			name:    "AC2 module imports another module's internal",
			fixture: "bad_cross_module_internal.go.txt",
			relDir:  "modules/repository/internal/app",
			want:    RuleCrossModuleInternal,
		},
		{
			name:    "AC4 api package imports infra",
			fixture: "bad_api_infra.go.txt",
			relDir:  "modules/repository/api",
			want:    RuleAPIExposesInfra,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			file := placeFixture(t, tc.fixture, tc.relDir)
			vs, err := Scan(token.NewFileSet(), file)
			if err != nil {
				t.Fatal(err)
			}
			if !hasRule(vs, tc.want) {
				t.Errorf("expected rule %q to fire, got %v", tc.want, vs)
			}
		})
	}
}

// TestLegitimateCodeIsAccepted guards against a checker so blunt it blocks correct code: an api/
// package over standard-library types, and a domain package importing its own module's internal.
func TestLegitimateCodeIsAccepted(t *testing.T) {
	cases := []struct {
		name    string
		fixture string
		relDir  string
	}{
		{"clean api surface", "good_api.go.txt", "modules/repository/api"},
		{"domain using own module internal", "good_domain.go.txt", "modules/repository/internal/domain"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			file := placeFixture(t, tc.fixture, tc.relDir)
			vs, err := Scan(token.NewFileSet(), file)
			if err != nil {
				t.Fatal(err)
			}
			if len(vs) != 0 {
				t.Errorf("expected no violations, got %v", vs)
			}
		})
	}
}

func hasRule(vs []Violation, rule string) bool {
	for _, v := range vs {
		if v.Rule == rule {
			return true
		}
	}
	return false
}
