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
// cross-module internal imports and no infra imports inside domain (invariants 14, 16).
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

// TestFixtureIsRejected proves the checker actually fails on a reverse/forbidden edge — a
// domain file that imports another module's internal AND pulls in infrastructure. Without
// this, a broken checker would pass TestNoBoundaryViolations vacuously.
func TestFixtureIsRejected(t *testing.T) {
	content, err := os.ReadFile(filepath.Join("testdata", "bad_repository_domain.go.txt"))
	if err != nil {
		t.Fatal(err)
	}
	// Place the fixture at a realistic module-domain path so both rules can fire.
	dir := filepath.Join(t.TempDir(), "modules", "repository", "internal", "domain")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "bad.go")
	if err := os.WriteFile(file, content, 0o644); err != nil {
		t.Fatal(err)
	}

	vs, err := Scan(token.NewFileSet(), file)
	if err != nil {
		t.Fatal(err)
	}
	rules := map[string]bool{}
	for _, v := range vs {
		rules[v.Rule] = true
	}
	if !rules["cross-module-internal-import"] {
		t.Error("expected cross-module-internal-import violation, got none")
	}
	if !rules["domain-imports-infra"] {
		t.Error("expected domain-imports-infra violation, got none")
	}
}
