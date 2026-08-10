package arch_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gitfrok/backend/internal/arch"
)

// reportPath is where the CI artifact lands. Gitignored: it is a measurement, not source.
const reportPath = "arch-report.json"

// TestExtractionTriggerReport is the AC4 gate. It emits the ADR-0026 trigger signals on every run
// and fails when one crosses its budget, so an extraction conversation is started by data rather
// than by somebody noticing the build got slow.
//
// Timings are skipped under -short (they shell out to the toolchain); the coupling signals are
// always real, so the gate never passes without checking anything.
func TestExtractionTriggerReport(t *testing.T) {
	root := repoRootOf(t)
	g, err := arch.LoadGraph(root)
	if err != nil {
		t.Fatalf("LoadGraph: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	rep, err := arch.BuildReport(ctx, g, root, arch.DefaultBudgets(), !testing.Short())
	if err != nil {
		t.Fatalf("BuildReport: %v", err)
	}

	// The log is where a human reads the trend on a PR.
	t.Log("\n" + rep.String())

	data, err := rep.JSON()
	if err != nil {
		t.Fatalf("rendering the report: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, reportPath), data, 0o644); err != nil {
		t.Fatalf("writing %s: %v", reportPath, err)
	}

	for _, b := range rep.Breaches {
		t.Errorf("extraction trigger: %s", b)
	}
}

// TestReportCoversEveryModule: a report that quietly omits a module would hide the one that is
// about to breach.
func TestReportCoversEveryModule(t *testing.T) {
	root := repoRootOf(t)
	g, err := arch.LoadGraph(root)
	if err != nil {
		t.Fatalf("LoadGraph: %v", err)
	}
	rep, err := arch.BuildReport(context.Background(), g, root, arch.DefaultBudgets(), false)
	if err != nil {
		t.Fatalf("BuildReport: %v", err)
	}

	if len(rep.Modules) != len(g.Modules()) {
		t.Fatalf("report has %d modules, tree has %d", len(rep.Modules), len(g.Modules()))
	}
	for _, m := range rep.Modules {
		if m.Packages == 0 {
			t.Errorf("module %q reported with no packages", m.Module)
		}
	}
}

// TestBudgetBreachIsReported is the reverse test: with a budget set below what the tree already
// does, the gate must fail. Without this, a report that never breaches proves nothing.
func TestBudgetBreachIsReported(t *testing.T) {
	root := repoRootOf(t)
	g, err := arch.LoadGraph(root)
	if err != nil {
		t.Fatalf("LoadGraph: %v", err)
	}

	// codesearch depends on repository, so a fan-out budget of zero must breach.
	impossible := arch.Budgets{MonolithBuildSeconds: 120, MonolithTestSeconds: 300, ModuleFanOut: 0}
	rep, err := arch.BuildReport(context.Background(), g, root, impossible, false)
	if err != nil {
		t.Fatalf("BuildReport: %v", err)
	}
	if len(rep.Breaches) == 0 {
		t.Fatal("want a fan-out breach reported under an impossible budget")
	}
	// Every module with a dependency breaches under a zero budget, so assert on the set rather
	// than on the first line: the order of Breaches follows the module order in the graph, and a
	// newly added module must not make this test fail for the wrong reason.
	named := false
	for _, breach := range rep.Breaches {
		if strings.Contains(breach, "codesearch") {
			named = true
			break
		}
	}
	if !named {
		t.Errorf("want the breaching module named, got %q", rep.Breaches)
	}
}

// TestReportIsSerialisable: CI uploads the JSON, so a change to the shape must not silently
// produce something unreadable.
func TestReportIsSerialisable(t *testing.T) {
	root := repoRootOf(t)
	g, err := arch.LoadGraph(root)
	if err != nil {
		t.Fatalf("LoadGraph: %v", err)
	}
	rep, err := arch.BuildReport(context.Background(), g, root, arch.DefaultBudgets(), false)
	if err != nil {
		t.Fatalf("BuildReport: %v", err)
	}
	data, err := rep.JSON()
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	for _, want := range []string{"fan_in", "fan_out", "depends_on", "budgets", "breaches"} {
		if !strings.Contains(string(data), want) {
			t.Errorf("report JSON is missing %q", want)
		}
	}
}

// repoRootOf returns the backend module root.
func repoRootOf(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Clean(filepath.Join(wd, "..", ".."))
}
