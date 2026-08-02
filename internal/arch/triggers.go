package arch

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// T-0009 AC4. ADR-0026 says a module is promoted to a service when a trigger fires, never on a
// schedule — but only one of its four triggers is mechanically observable. Scaling profile,
// blast-radius and team ownership are judgement calls; build/test time and coupling are not.
// This file measures the observable ones so that judgement starts from numbers.
//
// The report is emitted on every CI run rather than only on breach: the useful signal is the
// trend, and nobody can see a trend that is only recorded once it is already a problem.

// Budgets are the thresholds a trigger signal is compared against.
//
// The values come from ADR-0030 (Accepted) — the "agreed budget" ADR-0026 trigger 4 refers to and
// never stated. They are set where they catch a real regression without firing on ordinary growth,
// and ADR-0030 schedules a revisit at Phase-1 exit, when the monolith holds the git plane rather
// than two modules.
//
// Raising one is a decision, not a fix: change ADR-0030 first, then these. A breach means the
// build is past its budget or a boundary is in the wrong place; the answer may legitimately be
// "make it faster" rather than "extract something", and under BYO each extraction adds a pod to
// the customer's cluster (G8).
type Budgets struct {
	// MonolithBuildSeconds bounds a cold `go build` of the product packages. Crossing it means
	// the binary has grown past what one build can serve — ADR-0026 trigger 4.
	MonolithBuildSeconds float64
	// MonolithTestSeconds bounds the product test suite, the other half of trigger 4.
	MonolithTestSeconds float64
	// ModuleFanOut bounds how many other modules one module may depend on. Not an ADR-0026
	// trigger itself: it is the ADR-0022 cohesion signal that says the boundary is in the wrong
	// place, which is worth catching before it is answered by extracting the wrong thing.
	ModuleFanOut int
}

// DefaultBudgets are the ADR-0030 thresholds described above.
func DefaultBudgets() Budgets {
	return Budgets{
		MonolithBuildSeconds: 120,
		MonolithTestSeconds:  300,
		ModuleFanOut:         5,
	}
}

// ModuleSignal is the per-module half of the report.
type ModuleSignal struct {
	Module string `json:"module"`
	// Packages is the module's size in packages — the crudest growth signal, and the one that
	// moves first.
	Packages int `json:"packages"`
	// FanIn is how many modules depend on this one. High fan-in makes extraction expensive:
	// every dependant becomes a network caller.
	FanIn int `json:"fan_in"`
	// FanOut is how many modules this one depends on.
	FanOut int `json:"fan_out"`
	// DependsOn names them, so a fan-out breach is actionable without re-deriving the graph.
	DependsOn []string `json:"depends_on"`
	// BuildSeconds is how long this module alone takes to build. Zero when not measured.
	BuildSeconds float64 `json:"build_seconds"`
}

// Report is the ADR-0026 trigger report.
type Report struct {
	MonolithBuildSeconds float64        `json:"monolith_build_seconds"`
	MonolithTestSeconds  float64        `json:"monolith_test_seconds"`
	Modules              []ModuleSignal `json:"modules"`
	Budgets              Budgets        `json:"budgets"`
	// Breaches lists every budget crossed, empty when none.
	Breaches []string `json:"breaches"`
	// Measured reports whether timings were taken; the graph half of the report is always real.
	Measured bool `json:"measured"`
}

// productPackages are the patterns the monolith budget covers: the code that ships. internal/ is
// excluded because it is this tooling, and timing the fitness functions inside the fitness
// functions measures the wrong thing (and recurses).
var productPackages = []string{"./cmd/...", "./modules/...", "./platform/...", "./gen/..."}

// BuildReport assembles the trigger report from the graph. When measure is false the timings are
// left at zero and only the coupling budgets are evaluated — that is the fast path for local runs;
// CI measures.
func BuildReport(ctx context.Context, g *Graph, dir string, b Budgets, measure bool) (Report, error) {
	edges := g.ModuleEdges()
	fanIn, fanOut := g.FanIn(), g.FanOut()

	rep := Report{Budgets: b, Measured: measure}
	for _, m := range g.Modules() {
		rep.Modules = append(rep.Modules, ModuleSignal{
			Module:    m,
			Packages:  len(g.packagesOf(m)),
			FanIn:     fanIn[m],
			FanOut:    fanOut[m],
			DependsOn: edges[m],
		})
	}

	if measure {
		var err error
		if rep.MonolithBuildSeconds, err = timeCommand(ctx, dir, append([]string{"build"}, productPackages...)); err != nil {
			return rep, fmt.Errorf("timing the monolith build: %w", err)
		}
		if rep.MonolithTestSeconds, err = timeCommand(ctx, dir, append([]string{"test", "-count=1"}, productPackages...)); err != nil {
			return rep, fmt.Errorf("timing the monolith tests: %w", err)
		}
		for i, ms := range rep.Modules {
			// -a would give a cold number but costs minutes; the relative cost between modules
			// is what the trend needs, and this keeps the gate affordable on every PR.
			secs, err := timeCommand(ctx, dir, []string{"build", "./modules/" + ms.Module + "/..."})
			if err != nil {
				return rep, fmt.Errorf("timing the %s build: %w", ms.Module, err)
			}
			rep.Modules[i].BuildSeconds = secs
		}
	}

	rep.Breaches = rep.breaches()
	return rep, nil
}

// breaches evaluates every budget and returns one line per crossing.
func (r Report) breaches() []string {
	var out []string
	if r.Measured {
		if r.MonolithBuildSeconds > r.Budgets.MonolithBuildSeconds {
			out = append(out, fmt.Sprintf(
				"monolith build took %.1fs, budget %.0fs — ADR-0026 trigger 4",
				r.MonolithBuildSeconds, r.Budgets.MonolithBuildSeconds))
		}
		if r.MonolithTestSeconds > r.Budgets.MonolithTestSeconds {
			out = append(out, fmt.Sprintf(
				"monolith tests took %.1fs, budget %.0fs — ADR-0026 trigger 4",
				r.MonolithTestSeconds, r.Budgets.MonolithTestSeconds))
		}
	}
	for _, m := range r.Modules {
		if m.FanOut > r.Budgets.ModuleFanOut {
			out = append(out, fmt.Sprintf(
				"module %q depends on %d modules (%s), budget %d — the boundary is likely in the "+
					"wrong place (ADR-0022)",
				m.Module, m.FanOut, strings.Join(m.DependsOn, ", "), r.Budgets.ModuleFanOut))
		}
	}
	sort.Strings(out)
	return out
}

// JSON renders the report for a CI artifact.
func (r Report) JSON() ([]byte, error) { return json.MarshalIndent(r, "", "  ") }

// String renders the report as a table for a CI log.
func (r Report) String() string {
	var b strings.Builder
	b.WriteString("ADR-0026 extraction-trigger report\n")
	if r.Measured {
		fmt.Fprintf(&b, "  monolith: build %.1fs (budget %.0fs), test %.1fs (budget %.0fs)\n",
			r.MonolithBuildSeconds, r.Budgets.MonolithBuildSeconds,
			r.MonolithTestSeconds, r.Budgets.MonolithTestSeconds)
	} else {
		b.WriteString("  monolith: not measured (short mode)\n")
	}
	fmt.Fprintf(&b, "  %-14s %5s %7s %8s %9s  %s\n", "module", "pkgs", "fan-in", "fan-out", "build", "depends on")
	for _, m := range r.Modules {
		build := "-"
		if r.Measured {
			build = fmt.Sprintf("%.1fs", m.BuildSeconds)
		}
		deps := strings.Join(m.DependsOn, ", ")
		if deps == "" {
			deps = "-"
		}
		fmt.Fprintf(&b, "  %-14s %5d %7d %8d %9s  %s\n", m.Module, m.Packages, m.FanIn, m.FanOut, build, deps)
	}
	for _, br := range r.Breaches {
		fmt.Fprintf(&b, "  BUDGET: %s\n", br)
	}
	return b.String()
}

// timeCommand runs a go subcommand in dir and returns its wall-clock duration in seconds.
func timeCommand(ctx context.Context, dir string, args []string) (float64, error) {
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = dir
	start := time.Now()
	out, err := cmd.CombinedOutput()
	elapsed := time.Since(start).Seconds()
	if err != nil {
		return elapsed, fmt.Errorf("go %s: %w\n%s", strings.Join(args, " "), err, out)
	}
	return elapsed, nil
}
