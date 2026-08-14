// The Code Search module's one route to repository content is the Repository/Git contract
// surface — GetTree and GetFile over the RepositoryReader client (SPEC-0035 AC7, ADR-0022). The
// arch fitness suite holds modules out of each other's internals in general; this test holds
// THIS module to its specific claim: no file reaches Git storage or another context's tables,
// and the contract's generated clients are confined to the one adapter package built to carry
// them. A future shortcut — a storage handle here, a contract client there — fails the build.
package codesearch_test

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const modulePath = "github.com/gitfrok/backend"

// forbiddenEverywhere are import prefixes no codesearch file may carry, in production code or
// tests: Git storage internals, another context's internals, and the generated wire clients
// outside the one adapter allowed to hold them.
func classify(importPath, rel string) string {
	switch {
	case strings.HasPrefix(importPath, modulePath+"/modules/repository/internal"):
		return "codesearch must not import the Repository context's internals (invariant 14)"
	case strings.HasPrefix(importPath, modulePath+"/platform/git"),
		strings.Contains(importPath, "git-storaged"):
		return "codesearch reaches content through the Repository contract, never Git storage directly (ADR-0022, SPEC-0035 AC7)"
	case strings.HasPrefix(importPath, modulePath+"/gen/proto/repository"):
		// The composition root's one constructor alias is the module-root pattern every module
		// follows (see modules/repository/module.go): cmd/ cannot name internal packages, so the
		// root exposes the adapter. Everywhere else the contract client is forbidden.
		if rel != "module.go" && !strings.HasPrefix(rel, "internal/adapters/repocontent/") {
			return "the Repository contract client belongs only in internal/adapters/repocontent"
		}
	case strings.HasPrefix(importPath, modulePath+"/gen/proto/search"):
		if !strings.HasPrefix(rel, "internal/adapters/grpc/") {
			return "the Search contract types belong only in internal/adapters/grpc"
		}
	}
	return ""
}

// TestContentOnlyThroughTheRepositoryContract walks every Go file in the module and fails on any
// import that opens a route to repository content other than the RepositoryReader contract in
// its one adapter.
func TestContentOnlyThroughTheRepositoryContract(t *testing.T) {
	fset := token.NewFileSet()
	var violations []string

	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		rel, err := filepath.Rel(".", path)
		if err != nil {
			return err
		}
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imp := range f.Imports {
			importPath, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				return err
			}
			if reason := classify(importPath, filepath.ToSlash(rel)); reason != "" {
				violations = append(violations, rel+": imports "+importPath+" — "+reason)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk module: %v", err)
	}
	for _, v := range violations {
		t.Error(v)
	}
}
