// Package arch holds fitness functions that enforce the architecture invariants (ADR-0022,
// ADR-0025). T-0001 shipped the first two rules; T-0002 adds api/ purity and the per-rule
// fixtures, and wires the whole set into CI. T-0009 extends this to extraction-readiness.
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

// Rule names. Stable strings: CI output and the fixtures in testdata both key off them.
const (
	// RuleCrossModuleInternal fires when code reaches into another module's internal/* instead
	// of going through that module's api/ package or the in-process bus (invariant 14).
	RuleCrossModuleInternal = "cross-module-internal-import"
	// RuleDomainImportsInfra fires when a module's domain layer imports infrastructure —
	// dependencies point inward only (invariant 16).
	RuleDomainImportsInfra = "domain-imports-infra"
	// RuleAPIExposesInfra fires when a module's api/ package imports infrastructure. A type can
	// only appear in an exported signature if its package is imported, so import purity is what
	// keeps the api/ surface infra-free (invariant 20) and the module extractable (ADR-0026).
	RuleAPIExposesInfra = "api-exposes-infra"
)

// infraMarkers are import substrings a domain package must never pull in (invariant 16).
var infraMarkers = []string{
	"database/sql", "jackc/pgx", "lib/pq",
	"net/http", "google.golang.org/grpc",
	"redpanda", "twmb/franz-go", "opa", "open-policy-agent", "zitadel",
}

var moduleInternalRe = regexp.MustCompile(`^` + regexp.QuoteMeta(ModulePath) + `/modules/([^/]+)/internal/`)

// moduleAPIDirRe matches a file living on a module's public api/ surface.
var moduleAPIDirRe = regexp.MustCompile(`/modules/[^/]+/api/`)

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
	slash := filepath.ToSlash(file)
	inDomain := strings.Contains(slash, "/internal/domain/")
	inAPI := moduleAPIDirRe.MatchString(slash)
	for _, imp := range imports {
		if m := moduleInternalRe.FindStringSubmatch(imp); m != nil {
			if owningModule == "" || m[1] != owningModule {
				vs = append(vs, Violation{File: file, Import: imp, Rule: RuleCrossModuleInternal})
			}
		}
		if !isInfra(imp) {
			continue
		}
		if inDomain {
			vs = append(vs, Violation{File: file, Import: imp, Rule: RuleDomainImportsInfra})
		}
		if inAPI {
			vs = append(vs, Violation{File: file, Import: imp, Rule: RuleAPIExposesInfra})
		}
	}
	return vs
}

// isInfra reports whether an import path names infrastructure the inner layers must not touch.
func isInfra(imp string) bool {
	for _, marker := range infraMarkers {
		if strings.Contains(imp, marker) {
			return true
		}
	}
	return false
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
