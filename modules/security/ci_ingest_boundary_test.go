package security_test

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// TestSecurityDoesNotImportTheCIContext is the boundary gate SPEC-0037 (G5)
// states: CI writes the report, Security reads it through a composed port —
// no cross-context import. The ingester defines its own job and report
// shapes and the composition root adapts the CI context onto them, so this
// module's non-test sources must name no package under modules/ci. The
// internal/arch budget gates the same separation by fan-out; this test names
// the specific rule.
func TestSecurityDoesNotImportTheCIContext(t *testing.T) {
	const forbidden = "github.com/gitfrok/backend/modules/ci"
	// Test files are exempt: the integration test composes both modules
	// exactly as cmd/ does, from the outside, through their module surfaces.
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imp := range file.Imports {
			value := strings.Trim(imp.Path.Value, `"`)
			if value == forbidden || strings.HasPrefix(value, forbidden+"/") {
				t.Errorf("%s imports %s: Security reads CI jobs and scan reports only through composed ports (SPEC-0037 G5)", path, value)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the security module: %v", err)
	}
}
