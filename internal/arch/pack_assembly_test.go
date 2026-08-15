package arch_test

import (
	"slices"
	"testing"

	"github.com/gitfrok/backend/internal/arch"
)

// SPEC-0042 AC4 (T-0037): evidence-pack assembly structurally cannot reach
// in-process stores. Asserted the standard three ways: the real tree holds
// the property, a fixture that breaks it fires, and a fixture that merely
// reads durable surfaces stays quiet. Without the middle one a green gate
// proves nothing.

// TestPackAssemblyReachesNoInProcessStores is the gate: the audit
// app+domain closure — where the residency section is assembled — has no
// edge to the agent or residency in-memory stores, at any depth. The pack
// is structurally unable to read process memory, so what it cites can only
// be durable state.
func TestPackAssemblyReachesNoInProcessStores(t *testing.T) {
	for _, v := range realGraph(t).CheckPackAssemblyReachesNoInProcessStores() {
		t.Errorf("pack assembly reaches the in-process store %s — the residency section could cite process memory.\n  via %s",
			v.Reached, arch.FormatPath(v.Path))
	}
}

// TestPackAssemblyCatchesADirectMemoryReach is the refactor this check
// exists to refuse: the residency section starts reading the in-memory
// declaration store "because it is right there".
func TestPackAssemblyCatchesADirectMemoryReach(t *testing.T) {
	for _, target := range []string{
		mod("modules/residency/internal/adapters/memory"),
		mod("modules/agent/internal/adapters/memory"),
	} {
		g := fixtureGraph(t, map[string][]string{
			"modules/audit/internal/app": {target},
		})
		vs := g.CheckPackAssemblyReachesNoInProcessStores()
		if len(vs) == 0 {
			t.Fatalf("assembly importing %s produced no violation", target)
		}
		if vs[0].Reached != target {
			t.Fatalf("violation names %s, want %s", vs[0].Reached, target)
		}
	}
}

// TestPackAssemblyCatchesAnIndirectMemoryReach is the depth case: the
// assembly package itself stays clean, but a helper it trusts reads process
// memory. The closure walk is what catches it.
func TestPackAssemblyCatchesAnIndirectMemoryReach(t *testing.T) {
	g := fixtureGraph(t, map[string][]string{
		"modules/audit/internal/app":    {mod("platform/projectionhelper")},
		"platform/projectionhelper":     {mod("modules/residency/internal/adapters/memory")},
		"modules/audit/internal/domain": {},
	})
	vs := g.CheckPackAssemblyReachesNoInProcessStores()
	if len(vs) == 0 {
		t.Fatal("indirect reach through a platform helper produced no violation")
	}
	// The reported chain must make the hop visible, not just the endpoint.
	if !slices.Contains(vs[0].Path, mod("platform/projectionhelper")) {
		t.Fatalf("violation path %v does not name the intermediate helper", vs[0].Path)
	}
}

// TestPackAssemblyAcceptsDurableReads keeps the check honest: the assembly
// reading contract surfaces and durable projections — exactly its sanctioned
// shape — produces no finding.
func TestPackAssemblyAcceptsDurableReads(t *testing.T) {
	g := fixtureGraph(t, map[string][]string{
		"modules/audit/internal/app": {
			mod("modules/audit/internal/domain"),
			mod("modules/residency/api"),
			mod("platform/db"),
		},
		"modules/audit/internal/domain": {},
		"modules/residency/api":         {},
		"platform/db":                   {},
	})
	if vs := g.CheckPackAssemblyReachesNoInProcessStores(); len(vs) != 0 {
		t.Fatalf("durable-only assembly flagged: %+v", vs)
	}
}
