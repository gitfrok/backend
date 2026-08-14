package arch

import (
	"os"
	"path/filepath"
	"testing"
)

// TestNoControlPlaneDialsDataPlane is the SPEC-0039 AC4 fitness assertion: the real backend
// tree must contain no control-plane component that dials a data-plane address. Outbound-only
// is an assertion, not a convention — this test fails the moment one is added.
func TestNoControlPlaneDialsDataPlane(t *testing.T) {
	root := repoRoot(t)
	violations, err := CheckNoDataPlaneDial(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	for _, v := range violations {
		t.Errorf("AC4 violated: %s opens an outbound dial (%s) — the control plane never dials a data plane", v.File, v.Marker)
	}
}

// TestNoDataPlaneDialGateCanFail proves the assertion is not vacuous: a control-plane file that
// dials out must be caught. A fitness function that cannot fail is not a fitness function.
func TestNoDataPlaneDialGateCanFail(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "modules", "agent")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// A production-shaped file (NOT _test.go) that dials a data-plane address.
	dialer := filepath.Join(dir, "sneaky.go")
	src := "package agent\n\nimport \"net\"\n\nfunc f() { net.Dial(\"tcp\", \"10.0.0.5:9000\") }\n"
	if err := os.WriteFile(dialer, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	violations, err := CheckNoDataPlaneDial(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(violations) == 0 {
		t.Fatal("the gate missed a control-plane file that dials out — it cannot fail, so it is not a gate")
	}
}

// TestNoDataPlaneDialIgnoresTestFiles asserts the scan's stated scope: a test may stand up a
// client to exercise a server, and is not part of the shipped control plane.
func TestNoDataPlaneDialIgnoresTestFiles(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "cmd", "controlplane-app")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	testFile := filepath.Join(dir, "gateway_test.go")
	src := "package main\n\nimport \"net\"\n\nfunc f() { net.Dial(\"tcp\", \"x\") }\n"
	if err := os.WriteFile(testFile, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	violations, err := CheckNoDataPlaneDial(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(violations) != 0 {
		t.Fatalf("test files are out of scope for the AC4 scan, got %d violations", len(violations))
	}
}
