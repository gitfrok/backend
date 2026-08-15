package arch

import (
	"slices"
	"sort"
)

// Evidence-pack assembly isolation — SPEC-0042 AC4 (T-0037).
//
// The pack's residency section must be reproducible from durable state: a
// pack assembled after a control-plane restart cites what one assembled
// before it would (ADR-0062). That property is only ENFORCED — not merely
// reviewed — when the assembly path is structurally unable to read process
// memory. The in-process stores are the shape process memory takes here:
// the agent and residency modules' memory adapters. An import edge from the
// pack-assembly packages to one of them would let a future refactor answer
// the residency section from a store that dies with the process, and no
// review reliably catches a refactor. This check makes the edge a failing
// gate instead.
//
// The general isolation rule (CheckIsolation) already forbids one module
// reaching another's internals, but at module granularity and by review
// ancestry; this check names the specific assembly packages and the
// specific volatile stores, so the property under test is the one on
// screen when the failure fires.

// packAssemblyRoots are the packages the evidence pack's sections — the
// residency section among them — are assembled in.
var packAssemblyRoots = []string{
	ModulePath + "/modules/audit/internal/app",
	ModulePath + "/modules/audit/internal/domain",
}

// packAssemblyForbiddenStores are the in-process stores the assembly path
// must never reach, directly or through any number of hops.
var packAssemblyForbiddenStores = []string{
	ModulePath + "/modules/agent/internal/adapters/memory",
	ModulePath + "/modules/residency/internal/adapters/memory",
}

// PackAssemblyViolation is one route from the pack-assembly path to an
// in-process store.
type PackAssemblyViolation struct {
	// Reached is the forbidden in-process store the closure touched.
	Reached string
	// Path is the import chain from an assembly package to the package that
	// carries the offending edge, which is what makes the finding
	// actionable rather than merely reported.
	Path []string
}

// CheckPackAssemblyReachesNoInProcessStores answers SPEC-0042 AC4: the
// transitive import closure of the pack-assembly packages contains no edge
// to an in-process store — the pack is structurally unable to read process
// memory, so a residency section it produces can only cite durable state.
func (g *Graph) CheckPackAssemblyReachesNoInProcessStores() []PackAssemblyViolation {
	var roots []*Package
	for _, ip := range packAssemblyRoots {
		if p := g.Package(ip); p != nil {
			roots = append(roots, p)
		}
	}
	var out []PackAssemblyViolation
	g.reach(roots, func(p *Package, path []string) {
		for _, forbidden := range packAssemblyForbiddenStores {
			// Either the closure lands ON a volatile store, or one reached
			// package imports one — both are the same broken property.
			if p.ImportPath == forbidden || slices.Contains(p.Imports, forbidden) {
				out = append(out, PackAssemblyViolation{
					Reached: forbidden,
					Path:    append([]string(nil), path...),
				})
			}
		}
	})
	sort.Slice(out, func(i, j int) bool {
		if out[i].Reached != out[j].Reached {
			return out[i].Reached < out[j].Reached
		}
		return FormatPath(out[i].Path) < FormatPath(out[j].Path)
	})
	return out
}
