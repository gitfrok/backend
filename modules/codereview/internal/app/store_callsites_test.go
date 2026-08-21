package app

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// SPEC-0061 AC7 — the call-site pairing the durable adapter's scoping depends on.
//
// ADR-0080 decision 1 scopes each store call from whichever source carries the tenant: an argument, a
// field of the aggregate, or the request context. That works because the call sites divide cleanly —
// the four tenant-less methods (Get, PutReview, Reviews, Seen) are reached only from request paths,
// where the gRPC door has already called tenancy.WithTenant, and the event path calls only methods
// that carry a tenant explicitly.
//
// The ADR records that division as the thing it is most likely to be wrong about, because it is one
// refactor away from not holding: a future caller reaching Get from a bus handler would get a runtime
// refusal rather than a compile error. So the division is asserted here, by reading this package's own
// source, and a change that breaks it fails a test instead of a tenant.
//
// The assertion's own shape is ADR-0084 decision 5: the event entry points are DERIVED from the bus
// subscription call sites rather than named here, so a second bus handler is covered the day it is
// written; and the store-call selector is qualified by receiver type, so the ImportService's
// identically-shaped `store` field — a different port entirely — does not match.

// tenantlessMethods carry no tenant argument, so the adapter must read one from the context.
var tenantlessMethods = []string{"Get", "PutReview", "Reviews", "Seen"}

// funcInfo is one declaration with the facts the walk needs: the receiver's type
// and the name its parameter goes by, so a selector like s.store.Get can be
// attributed to the type that actually holds it.
type funcInfo struct {
	decl     *ast.FuncDecl
	recvType string // "" for a plain function
	recvName string // "" for a plain function
}

func TestTenantlessStoreCallsAreUnreachableFromTheEventPath(t *testing.T) {
	fset := token.NewFileSet()
	pkg := parseAppPackage(t, fset)

	entries := eventEntryPoints(t, pkg)

	// Map every function in the package to the Code Review store methods it calls and the methods it
	// calls on its own receiver, so reachability is a walk rather than a guess about naming.
	storeCalls := map[string][]string{}
	calls := map[string][]string{}
	for name, fn := range pkg {
		ast.Inspect(fn.decl, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if isStoreSelector(sel, fn) {
				storeCalls[name] = append(storeCalls[name], sel.Sel.Name)
				return true
			}
			// A method call on this function's own receiver, whatever that
			// receiver is: s.something(...) attributed to the type holding s.
			if fn.recvName != "" {
				if inner, ok := sel.X.(*ast.Ident); ok && inner.Name == fn.recvName {
					calls[name] = append(calls[name], fn.recvType+"."+sel.Sel.Name)
				}
			}
			return true
		})
	}

	for _, entry := range entries {
		if _, ok := pkg[entry]; !ok {
			t.Fatalf("%s is subscribed on the bus but is not in this package any more — this test is asserting a shape that moved", entry)
		}
		for _, reached := range reachableFrom(entry, calls) {
			for _, method := range storeCalls[reached] {
				if slices.Contains(tenantlessMethods, method) {
					t.Errorf("the event path reaches store.%s from %s (via %s), and that method carries no tenant.\n"+
						"platform/bus puts no tenant in the context, so the durable adapter would refuse it at runtime.\n"+
						"Either pass the tenant explicitly, or widen the Store port — ADR-0080 refused widening it, "+
						"and this is the evidence that would reopen that decision.", method, entry, reached)
				}
			}
		}
	}
}

// The other half of the pairing: the tenant-less methods must still be called from somewhere, or the
// adapter's context-scoping branch is dead code and this test is guarding nothing.
func TestTenantlessStoreMethodsAreStillUsed(t *testing.T) {
	fset := token.NewFileSet()
	pkg := parseAppPackage(t, fset)

	used := map[string]bool{}
	for _, fn := range pkg {
		ast.Inspect(fn.decl, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && isStoreSelector(sel, fn) {
					used[sel.Sel.Name] = true
				}
			}
			return true
		})
	}
	for _, method := range tenantlessMethods {
		if !used[method] {
			t.Errorf("store.%s is never called — either it left the port, or this test's selector no longer sees it", method)
		}
	}
}

// eventEntryPoints derives the functions reached from the bus rather than from a verified request:
// every handler handed to bus.Subscribe or bus.SubscribeTyped in this package. platform/bus puts no
// tenant in the context, so anything these reach must carry its own. Naming them here instead would
// leave the next subscription unguarded the day it is written (ADR-0084 decision 5).
func eventEntryPoints(t *testing.T, pkg map[string]funcInfo) []string {
	t.Helper()
	seen := map[string]bool{}
	var entries []string
	for _, fn := range pkg {
		ast.Inspect(fn.decl, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkgIdent, ok := sel.X.(*ast.Ident)
			if !ok || pkgIdent.Name != "bus" || !strings.HasPrefix(sel.Sel.Name, "Subscribe") {
				return true
			}
			for _, arg := range call.Args {
				handler, ok := arg.(*ast.SelectorExpr)
				if !ok {
					continue
				}
				recv, ok := handler.X.(*ast.Ident)
				if !ok || fn.recvName == "" || recv.Name != fn.recvName {
					continue
				}
				entry := fn.recvType + "." + handler.Sel.Name
				if !seen[entry] {
					seen[entry] = true
					entries = append(entries, entry)
				}
			}
			return true
		})
	}
	if len(entries) == 0 {
		t.Fatal("no bus subscriptions found — either the event path moved out of this package, or this test no longer sees it")
	}
	return entries
}

// parseAppPackage returns every function and method in this package, keyed by receiver and name.
//
// The receiver is part of the key because this package has several types with a `Get` — the service
// and the in-memory store among them — and a map keyed on the bare name silently keeps whichever was
// parsed last. That is not a hypothetical: the first version of this test reported that
// `store.Get` was never called, because memoryStore.Get had overwritten Service.Get.
func parseAppPackage(t *testing.T, fset *token.FileSet) map[string]funcInfo {
	t.Helper()
	dirEntries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading package: %v", err)
	}
	out := map[string]funcInfo{}
	for _, entry := range dirEntries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(".", name), nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			info := funcInfo{decl: fn}
			if fn.Recv != nil && len(fn.Recv.List) > 0 {
				info.recvName = nameOf(fn.Recv.List[0].Names)
				info.recvType = receiverTypeName(fn.Recv.List[0].Type)
			}
			out[qualify(fn)] = info
		}
	}
	if len(out) == 0 {
		t.Fatal("no functions parsed — the test is reading the wrong directory")
	}
	return out
}

func nameOf(names []*ast.Ident) string {
	if len(names) == 0 {
		return ""
	}
	return names[0].Name
}

// receiverTypeName reduces a receiver type expression to its type's own name:
// Service for *Service.
func receiverTypeName(expr ast.Expr) string {
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	if ident, ok := expr.(*ast.Ident); ok {
		return ident.Name
	}
	return ""
}

// qualify names a declaration by its receiver type and its own name — "Service.Get", or "openFor"
// for a plain function.
func qualify(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return fn.Name.Name
	}
	recvType := receiverTypeName(fn.Recv.List[0].Type)
	if recvType == "" {
		return fn.Name.Name
	}
	return recvType + "." + fn.Name.Name
}

// isStoreSelector reports whether a call is the Code Review service calling its
// own store port — receiver.store.Method(...) where the receiver is a *Service.
//
// The receiver-type qualification is deliberate (ADR-0084 decision 5): this
// package also has an ImportService with a field named `store`, and matching any
// receiver that happens to be called s would count that different port against
// this one's pairing.
func isStoreSelector(sel *ast.SelectorExpr, fn funcInfo) bool {
	if fn.recvType != "Service" {
		return false
	}
	inner, ok := sel.X.(*ast.SelectorExpr)
	if !ok || inner.Sel.Name != "store" {
		return false
	}
	receiver, ok := inner.X.(*ast.Ident)
	return ok && receiver.Name == fn.recvName
}

// reachableFrom walks the call graph from one entry point, including the entry itself.
func reachableFrom(entry string, calls map[string][]string) []string {
	seen := map[string]bool{entry: true}
	queue := []string{entry}
	var out []string
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		out = append(out, current)
		for _, next := range calls[current] {
			if !seen[next] {
				seen[next] = true
				queue = append(queue, next)
			}
		}
	}
	return out
}
