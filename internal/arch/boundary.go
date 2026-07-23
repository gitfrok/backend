// Package arch holds fitness functions that enforce the architecture invariants (ADR-0022,
// ADR-0025). T-0001 ships the stubs below; T-0002/T-0009 extend them into full CI gates.
package arch

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// ModulePath is this repo's Go module path; cross-module rules key off it.
const ModulePath = "github.com/gitfrok/backend"

// infraMarkers are import substrings a domain package must never pull in (invariant 16).
var infraMarkers = []string{
	"database/sql", "jackc/pgx", "lib/pq",
	"net/http", "google.golang.org/grpc",
	"redpanda", "twmb/franz-go", "opa", "open-policy-agent", "zitadel",
}

var moduleInternalRe = regexp.MustCompile(`^` + regexp.QuoteMeta(ModulePath) + `/modules/([^/]+)/internal/`)

// Violation is one broken architecture rule at a source location.
type Violation struct {
	File   string
	Import string
	Rule   string
}

// importsOf parses a single Go source file and returns its import paths.
func importsOf(fset *token.FileSet, path string) ([]string, error) {
	f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(f.Imports))
	for _, spec := range f.Imports {
		p, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			continue
		}
		out = append(out, p)
	}
	return out, nil
}

// checkFile applies the boundary rules to one file, given the module it lives in ("" if none).
func checkFile(file, owningModule string, imports []string) []Violation {
	var vs []Violation
	inDomain := strings.Contains(filepath.ToSlash(file), "/internal/domain/")
	for _, imp := range imports {
		if m := moduleInternalRe.FindStringSubmatch(imp); m != nil {
			if owningModule == "" || m[1] != owningModule {
				vs = append(vs, Violation{File: file, Import: imp, Rule: "cross-module-internal-import"})
			}
		}
		if inDomain {
			for _, marker := range infraMarkers {
				if strings.Contains(imp, marker) {
					vs = append(vs, Violation{File: file, Import: imp, Rule: "domain-imports-infra"})
				}
			}
		}
	}
	return vs
}

var owningModuleRe = regexp.MustCompile(`/modules/([^/]+)/`)

// owningModuleOf returns the module directory a file belongs to, or "" for non-module code.
func owningModuleOf(file string) string {
	if m := owningModuleRe.FindStringSubmatch(filepath.ToSlash(file)); m != nil {
		return m[1]
	}
	return ""
}

// Scan walks a Go source file and returns any boundary violations. Callers pass one file
// at a time so fixtures (kept outside the build tree) can be checked identically to real code.
func Scan(fset *token.FileSet, file string) ([]Violation, error) {
	imports, err := importsOf(fset, file)
	if err != nil {
		return nil, err
	}
	return checkFile(file, owningModuleOf(file), imports), nil
}
