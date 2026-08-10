package arch_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/gitfrok/backend/internal/arch"
)

// T-0009 AC1–AC3. Each check is asserted three ways, matching the standard T-0002 set: it holds
// over the real tree, it fires on a fixture that breaks it, and it stays quiet on a fixture that
// is merely unusual. Without the middle one a green gate proves nothing.

// realGraph loads the backend tree.
func realGraph(t *testing.T) *arch.Graph {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	g, err := arch.LoadGraph(filepath.Clean(filepath.Join(wd, "..", "..")))
	if err != nil {
		t.Fatalf("LoadGraph: %v", err)
	}
	return g
}

// fixtureGraph writes a synthetic tree and loads it through exactly the same code path as real
// source. Each entry maps a package directory to the import paths its file declares.
func fixtureGraph(t *testing.T, pkgs map[string][]string) *arch.Graph {
	t.Helper()
	root := t.TempDir()
	for dir, imports := range pkgs {
		full := filepath.Join(root, filepath.FromSlash(dir))
		if err := os.MkdirAll(full, 0o755); err != nil {
			t.Fatal(err)
		}
		var b strings.Builder
		b.WriteString("package " + filepath.Base(dir) + "\n\nimport (\n")
		for _, imp := range imports {
			b.WriteString("\t_ \"" + imp + "\"\n")
		}
		b.WriteString(")\n")
		if err := os.WriteFile(filepath.Join(full, "pkg.go"), []byte(b.String()), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	g, err := arch.LoadGraph(root)
	if err != nil {
		t.Fatalf("LoadGraph: %v", err)
	}
	return g
}

func mod(path string) string { return arch.ModulePath + "/" + path }

// --- AC1: isolation -------------------------------------------------------------------------

// TestRealTreeModulesAreIsolated is the gate: no module reaches another's internals, at any depth.
func TestRealTreeModulesAreIsolated(t *testing.T) {
	for _, v := range realGraph(t).CheckIsolation() {
		t.Errorf("module %q reaches %s — extraction would not be possible.\n  via %s",
			v.Module, v.Reached, arch.FormatPath(v.Path))
	}
}

// TestIsolationCatchesAnIndirectReach is the case T-0002 cannot see: A does not import B/internal,
// it imports a shared helper that does. It compiles, and it welds A and B together.
func TestIsolationCatchesAnIndirectReach(t *testing.T) {
	g := fixtureGraph(t, map[string][]string{
		"modules/alpha/api":         {mod("platform/helper")},
		"platform/helper":           {mod("modules/beta/internal/app")},
		"modules/beta/internal/app": {},
		"modules/beta/api":          {},
	})

	vs := g.CheckIsolation()
	if len(vs) == 0 {
		t.Fatal("want the indirect reach into beta's internals caught")
	}
	if vs[0].Module != "alpha" || !strings.HasSuffix(vs[0].Reached, "modules/beta/internal/app") {
		t.Errorf("unexpected violation %+v", vs[0])
	}
	if len(vs[0].Path) < 3 {
		t.Errorf("want the full chain reported for an indirect reach, got %v", vs[0].Path)
	}
}

// TestIsolationAllowsApiAndPlatform: the two legitimate cross-module routes must not be flagged,
// or the gate would block the architecture it is defending.
func TestIsolationAllowsApiAndPlatform(t *testing.T) {
	g := fixtureGraph(t, map[string][]string{
		"modules/alpha/internal/app": {mod("modules/beta/api"), mod("platform/bus"), "context"},
		"modules/alpha/api":          {},
		"modules/beta/api":           {},
		"platform/bus":               {},
	})
	if vs := g.CheckIsolation(); len(vs) != 0 {
		t.Errorf("api/ and platform/ use must be allowed, got %+v", vs)
	}
}

// TestIsolationAllowsAModuleReachingItsOwnInternals guards the obvious false positive.
func TestIsolationAllowsAModuleReachingItsOwnInternals(t *testing.T) {
	g := fixtureGraph(t, map[string][]string{
		"modules/alpha":                 {mod("modules/alpha/internal/app")},
		"modules/alpha/internal/app":    {mod("modules/alpha/internal/domain")},
		"modules/alpha/internal/domain": {},
		"modules/alpha/api":             {},
	})
	if vs := g.CheckIsolation(); len(vs) != 0 {
		t.Errorf("a module's own composition root must be allowed, got %+v", vs)
	}
}

// --- AC2: acyclicity ------------------------------------------------------------------------

// TestRealTreeModuleGraphIsAcyclic is the gate.
func TestRealTreeModuleGraphIsAcyclic(t *testing.T) {
	if c := realGraph(t).FindCycle(); c != nil {
		t.Errorf("module dependency cycle: %s — these modules cannot be deployed or extracted "+
			"separately", strings.Join(c, " → "))
	}
}

// TestFindCycleCatchesAMutualDependency covers the two-module case.
func TestFindCycleCatchesAMutualDependency(t *testing.T) {
	g := fixtureGraph(t, map[string][]string{
		"modules/alpha/internal/app": {mod("modules/beta/api")},
		"modules/alpha/api":          {},
		"modules/beta/internal/app":  {mod("modules/alpha/api")},
		"modules/beta/api":           {},
	})
	c := g.FindCycle()
	if c == nil {
		t.Fatal("want the alpha ↔ beta cycle caught")
	}
	if c[0] != c[len(c)-1] {
		t.Errorf("a reported cycle must close on itself, got %v", c)
	}
}

// TestFindCycleCatchesALongerLoop: three-module loops are the ones review misses.
func TestFindCycleCatchesALongerLoop(t *testing.T) {
	g := fixtureGraph(t, map[string][]string{
		"modules/alpha/internal/app": {mod("modules/beta/api")},
		"modules/alpha/api":          {},
		"modules/beta/internal/app":  {mod("modules/gamma/api")},
		"modules/beta/api":           {},
		"modules/gamma/internal/app": {mod("modules/alpha/api")},
		"modules/gamma/api":          {},
	})
	if c := g.FindCycle(); c == nil {
		t.Error("want the three-module cycle caught")
	}
}

// TestFindCycleAcceptsADiamond: shared dependencies are not cycles, and a checker that says
// otherwise would push people to duplicate code.
func TestFindCycleAcceptsADiamond(t *testing.T) {
	g := fixtureGraph(t, map[string][]string{
		"modules/alpha/internal/app": {mod("modules/beta/api"), mod("modules/gamma/api")},
		"modules/alpha/api":          {},
		"modules/beta/internal/app":  {mod("modules/delta/api")},
		"modules/beta/api":           {},
		"modules/gamma/internal/app": {mod("modules/delta/api")},
		"modules/gamma/api":          {},
		"modules/delta/api":          {},
	})
	if c := g.FindCycle(); c != nil {
		t.Errorf("a diamond is acyclic, got %v", c)
	}
}

// --- AC3: api purity ------------------------------------------------------------------------

// TestRealTreeAPISurfacesAreInfraFree is the gate.
func TestRealTreeAPISurfacesAreInfraFree(t *testing.T) {
	for _, l := range realGraph(t).CheckAPIPurity() {
		t.Errorf("module %q exposes infrastructure %s on its api/ surface — extracting it would "+
			"change its callers.\n  via %s", l.Module, l.Import, arch.FormatPath(l.Path))
	}
}

// TestAPIPurityCatchesATransitiveLeak is the hole T-0002 AC4 left open and named: the api/ file
// itself imports nothing suspicious, but what it re-exports through does.
func TestAPIPurityCatchesATransitiveLeak(t *testing.T) {
	g := fixtureGraph(t, map[string][]string{
		"modules/alpha/api":   {mod("modules/alpha/types")},
		"modules/alpha/types": {"github.com/jackc/pgx/v5"},
	})
	ls := g.CheckAPIPurity()
	if len(ls) == 0 {
		t.Fatal("want the re-exported pgx dependency caught")
	}
	if len(ls[0].Path) < 2 {
		t.Errorf("want the chain reported, got %v", ls[0].Path)
	}
}

// TestAPIPurityCatchesGeneratedGRPCStubs: generated code is infrastructure too. An api/ package
// handing out a grpc client is the same leak with a friendlier import path, and the direct check
// misses it because the path names this repo.
func TestAPIPurityCatchesGeneratedGRPCStubs(t *testing.T) {
	g := fixtureGraph(t, map[string][]string{
		"modules/alpha/api":  {mod("gen/proto/agent/v1")},
		"gen/proto/agent/v1": {"google.golang.org/grpc"},
	})
	if ls := g.CheckAPIPurity(); len(ls) == 0 {
		t.Error("want an api/ surface reaching generated grpc stubs caught")
	}
}

// TestAPIPurityIgnoresInfraBehindTheModuleBoundary: adapters exist to touch infrastructure. Only
// what the api/ surface can reach is in scope, or the rule would forbid the architecture.
func TestAPIPurityIgnoresInfraBehindTheModuleBoundary(t *testing.T) {
	g := fixtureGraph(t, map[string][]string{
		"modules/alpha/api":                     {"context"},
		"modules/alpha/internal/adapters/pgsql": {"github.com/jackc/pgx/v5"},
	})
	if ls := g.CheckAPIPurity(); len(ls) != 0 {
		t.Errorf("an adapter may import infrastructure, got %+v", ls)
	}
}

// --- graph shape ----------------------------------------------------------------------------

// TestFanCountsDescribeTheRealTree: the AC4 report is only as good as its inputs, so the counts
// are asserted against the dependency this repo actually has — codesearch reads repository.
func TestFanCountsDescribeTheRealTree(t *testing.T) {
	g := realGraph(t)
	edges := g.ModuleEdges()
	if !slices.Contains(edges["codesearch"], "repository") {
		t.Errorf("codesearch depends on repository; edges say %v", edges["codesearch"])
	}
	if got := g.FanOut()["repository"]; got != 0 {
		t.Errorf("repository must not depend on another module, fan-out = %d (%v)",
			got, edges["repository"])
	}
	if got := g.FanIn()["repository"]; got < 1 {
		t.Errorf("repository fan-in = %d, want at least codesearch", got)
	}
}

// TestGraphExcludesTestFiles pins the deliberate exclusion: the Repository contract test imports
// the generated protobuf package, and counting test imports would make api purity unreachable
// without making the surface any cleaner.
func TestGraphExcludesTestFiles(t *testing.T) {
	p := realGraph(t).Package(mod("modules/repository/api"))
	if p == nil {
		t.Fatal("repository/api not in the graph")
	}
	for _, imp := range p.Imports {
		if strings.Contains(imp, "/gen/") {
			t.Errorf("test-only import %q leaked into the graph", imp)
		}
	}
}
