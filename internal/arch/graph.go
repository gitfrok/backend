package arch

import (
	"fmt"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

// This file holds the T-0009 extraction-readiness checks. T-0002 asks whether a single file breaks
// a boundary; these ask whether the tree as a whole is still separable into services (ADR-0026).
// Three questions, all answered from the import graph:
//
//   - AC1 isolation: could this module be lifted out on its own? Only if nothing it transitively
//     reaches belongs to another module's internals.
//   - AC2 acyclicity: could the modules be deployed independently? Not if two depend on each other.
//   - AC3 api purity: would extracting a module change its callers? It would if its public surface
//     transitively drags in infrastructure — the gap T-0002 left open, where an api/ package is
//     clean itself but re-exports through a helper that is not.
//
// The graph is built by parsing imports, not by shelling out to the toolchain, so it works on a
// tree that does not compile yet — which is the state a fitness function most needs to speak up in.

// Package is one Go package in this repo, as seen from its imports.
type Package struct {
	// ImportPath is the full path, e.g. github.com/gitfrok/backend/modules/repository/api.
	ImportPath string
	// Module is the modules/<ctx> directory this package belongs to, or "" for platform, cmd,
	// gen and internal packages outside a module.
	Module string
	// IsAPI reports whether this package is a module's public in-process surface.
	IsAPI bool
	// IsInternal reports whether this package sits under an internal/ directory.
	IsInternal bool
	// Imports are the package's import paths, in-repo and external, from non-test files only.
	Imports []string
}

// Graph is the repo's package import graph, plus the module view derived from it.
type Graph struct {
	packages map[string]*Package
	modules  []string
}

// skipDirs are never part of the architecture: generated code has its own rules, testdata holds
// deliberately-broken fixtures, and the rest is not ours.
var skipDirs = map[string]bool{
	"testdata": true, "node_modules": true, ".git": true, ".github": true,
}

// LoadGraph parses every non-test Go file under root and returns the package graph.
//
// Test files are excluded on purpose. A test may legitimately import anything — the contract test
// for the Repository events reads the generated protobuf package, for instance — but a test is not
// part of the surface a caller compiles against, so counting it would make api purity unachievable
// without making it more true.
func LoadGraph(root string) (*Graph, error) {
	g := &Graph{packages: make(map[string]*Package)}
	seenModule := make(map[string]bool)

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		rel, err := filepath.Rel(root, filepath.Dir(path))
		if err != nil {
			return err
		}
		importPath := ModulePath
		if rel != "." {
			importPath += "/" + filepath.ToSlash(rel)
		}

		p, ok := g.packages[importPath]
		if !ok {
			p = &Package{
				ImportPath: importPath,
				Module:     owningModuleOf(path),
				IsAPI:      moduleAPIDirRe.MatchString(filepath.ToSlash(path)),
				IsInternal: strings.Contains(filepath.ToSlash(path), "/internal/"),
			}
			g.packages[importPath] = p
			if p.Module != "" && !seenModule[p.Module] {
				seenModule[p.Module] = true
				g.modules = append(g.modules, p.Module)
			}
		}

		imports, err := importsOf(token.NewFileSet(), path)
		if err != nil {
			return fmt.Errorf("parsing %s: %w", path, err)
		}
		p.Imports = appendUnique(p.Imports, imports...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(g.modules)
	return g, nil
}

// Modules returns the module names, sorted.
func (g *Graph) Modules() []string { return append([]string(nil), g.modules...) }

// Package returns the package at an import path, or nil.
func (g *Graph) Package(importPath string) *Package { return g.packages[importPath] }

// packagesOf returns every package belonging to a module.
func (g *Graph) packagesOf(module string) []*Package {
	var out []*Package
	for _, p := range g.packages {
		if p.Module == module {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ImportPath < out[j].ImportPath })
	return out
}

// reach walks the in-repo import closure from the given roots, calling visit for every package
// reached and the path taken to reach it. External imports terminate a branch: they are inspected
// by the caller but not traversed.
func (g *Graph) reach(roots []*Package, visit func(p *Package, path []string)) {
	seen := make(map[string]bool)
	var walk func(p *Package, path []string)
	walk = func(p *Package, path []string) {
		if seen[p.ImportPath] {
			return
		}
		seen[p.ImportPath] = true
		path = append(path, p.ImportPath)
		visit(p, path)
		for _, imp := range p.Imports {
			if next, ok := g.packages[imp]; ok {
				walk(next, path)
			}
		}
	}
	for _, r := range roots {
		walk(r, nil)
	}
}

// IsolationViolation is a module reaching into another module's internals, directly or through
// any number of hops. Such a module cannot be lifted into its own service as it stands.
type IsolationViolation struct {
	Module string
	// Reached is the offending package.
	Reached string
	// Path is the import chain from the module to it, which is what makes an indirect
	// violation actionable rather than merely reported.
	Path []string
}

// CheckIsolation answers AC1: every module's transitive closure stays inside its own internals.
//
// Go's internal/ rule already blocks the direct edge and T-0002 catches it per file. What is new
// here is depth: A → platform helper → B/internal compiles today and is invisible to both, yet it
// pins A and B into the same binary forever.
func (g *Graph) CheckIsolation() []IsolationViolation {
	var out []IsolationViolation
	for _, m := range g.modules {
		g.reach(g.packagesOf(m), func(p *Package, path []string) {
			if p.IsInternal && p.Module != "" && p.Module != m {
				out = append(out, IsolationViolation{Module: m, Reached: p.ImportPath, Path: path})
			}
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Module != out[j].Module {
			return out[i].Module < out[j].Module
		}
		return out[i].Reached < out[j].Reached
	})
	return out
}

// ModuleEdges returns the module-level dependency graph: which modules each module depends on.
func (g *Graph) ModuleEdges() map[string][]string {
	edges := make(map[string][]string, len(g.modules))
	for _, m := range g.modules {
		edges[m] = nil
	}
	for _, p := range g.packages {
		if p.Module == "" {
			continue
		}
		for _, imp := range p.Imports {
			dep, ok := g.packages[imp]
			if !ok || dep.Module == "" || dep.Module == p.Module {
				continue
			}
			edges[p.Module] = appendUnique(edges[p.Module], dep.Module)
		}
	}
	for m := range edges {
		sort.Strings(edges[m])
	}
	return edges
}

// FindCycle answers AC2: it returns one module cycle as the sequence of modules involved, closing
// back on the first, or nil when the graph is acyclic.
//
// A cycle is not a style problem. Two modules that depend on each other cannot be deployed or
// extracted separately, so it silently removes the option ADR-0026 exists to keep open.
func (g *Graph) FindCycle() []string {
	edges := g.ModuleEdges()
	const (
		unvisited = 0
		onStack   = 1
		done      = 2
	)
	state := make(map[string]int, len(edges))
	var stack []string

	var visit func(m string) []string
	visit = func(m string) []string {
		state[m] = onStack
		stack = append(stack, m)
		for _, dep := range edges[m] {
			switch state[dep] {
			case onStack:
				// Trim the stack to where the cycle opened, then close it.
				for i, s := range stack {
					if s == dep {
						return append(append([]string(nil), stack[i:]...), dep)
					}
				}
			case unvisited:
				if c := visit(dep); c != nil {
					return c
				}
			}
		}
		stack = stack[:len(stack)-1]
		state[m] = done
		return nil
	}

	for _, m := range g.modules {
		if state[m] == unvisited {
			if c := visit(m); c != nil {
				return c
			}
		}
	}
	return nil
}

// APILeak is a module whose public surface transitively reaches infrastructure.
type APILeak struct {
	Module string
	// Import is the infrastructure import that was reached.
	Import string
	// Path is the chain from the module's api/ package to the package that imports it. A
	// single-element path means the api/ package imports infra directly (the T-0002 AC4 case).
	Path []string
}

// CheckAPIPurity answers AC3: nothing reachable from a module's api/ surface touches
// infrastructure.
//
// T-0002 AC4 checks the api/ package's own imports and noted the hole it left: a type can be
// re-exported through an intermediate package, so the api/ file stays clean while the surface does
// not. Following the closure closes it. Extraction has to be invisible to callers (invariant 20),
// and it cannot be if the surface names a pgx row or a grpc client.
func (g *Graph) CheckAPIPurity() []APILeak {
	var out []APILeak
	for _, m := range g.modules {
		var roots []*Package
		for _, p := range g.packagesOf(m) {
			if p.IsAPI {
				roots = append(roots, p)
			}
		}
		if roots == nil {
			continue
		}
		g.reach(roots, func(p *Package, path []string) {
			for _, imp := range p.Imports {
				if isInfra(imp) {
					out = append(out, APILeak{Module: m, Import: imp, Path: path})
				}
			}
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Module != out[j].Module {
			return out[i].Module < out[j].Module
		}
		return out[i].Import < out[j].Import
	})
	return out
}

// FanIn counts the modules depending on each module; FanOut counts the modules each depends on.
// ADR-0026 reads these as extraction signals: a module nothing depends on is cheap to lift out,
// and one that depends on many is a sign the boundary is in the wrong place (ADR-0022).
func (g *Graph) FanIn() map[string]int {
	in := make(map[string]int, len(g.modules))
	for _, m := range g.modules {
		in[m] = 0
	}
	for _, deps := range g.ModuleEdges() {
		for _, d := range deps {
			in[d]++
		}
	}
	return in
}

// FanOut counts the modules each module depends on.
func (g *Graph) FanOut() map[string]int {
	out := make(map[string]int, len(g.modules))
	for m, deps := range g.ModuleEdges() {
		out[m] = len(deps)
	}
	return out
}

// appendUnique appends values not already present, preserving order.
func appendUnique(dst []string, vals ...string) []string {
	for _, v := range vals {
		if !slices.Contains(dst, v) {
			dst = append(dst, v)
		}
	}
	return dst
}

// FormatPath renders an import chain for a failure message.
func FormatPath(path []string) string {
	short := make([]string, 0, len(path))
	for _, p := range path {
		short = append(short, strings.TrimPrefix(p, ModulePath+"/"))
	}
	return strings.Join(short, " → ")
}
