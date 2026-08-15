package arch

import (
	"os"
	"path/filepath"
	"testing"
)

// TestNoCAKeyMaterialInProductionRoot is the SPEC-0044 AC1 fitness assertion:
// the production composition root cannot construct a CA from a file path or
// env, because no private-key parser or key-pair loader exists in it. The
// agent door's credentials are issued through the custody seam — references
// and digests only (ADR-0064, ADR-0066).
func TestNoCAKeyMaterialInProductionRoot(t *testing.T) {
	root := repoRoot(t)
	violations, err := CheckNoCAKeyMaterial(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	for _, v := range violations {
		t.Errorf("AC1 violated: %s constructs a CA from key material (%s) — the production root issues through custody only", v.File, v.Marker)
	}
}

// TestNoDevCAReachFromProductionRoot is the SPEC-0044 AC3 fitness assertion:
// the dev CA is unreachable from the production composition root — custody
// is the only CA the shipped control plane constructs.
func TestNoDevCAReachFromProductionRoot(t *testing.T) {
	root := repoRoot(t)
	violations, err := CheckNoDevCAReach(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	for _, v := range violations {
		t.Errorf("AC3 violated: %s constructs the dev CA (%s) — dev custody is unreachable from the production root", v.File, v.Marker)
	}
}

// TestNoCAKeyMaterialGateCanFail proves AC1's assertion is not vacuous: a
// production-root file that parses a private key must be caught. A fitness
// function that cannot fail is not a fitness function.
func TestNoCAKeyMaterialGateCanFail(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "cmd", "controlplane-app")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	src := "package main\n\nimport \"crypto/x509\"\n\nfunc f(der []byte) { _, _ = x509.ParseECPrivateKey(der) }\n"
	if err := os.WriteFile(filepath.Join(dir, "sneaky.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	violations, err := CheckNoCAKeyMaterial(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(violations) == 0 {
		t.Fatal("the gate missed a production-root file that parses a private key — it cannot fail, so it is not a gate")
	}
}

// TestNoDevCAReachGateCanFail proves AC3's assertion is not vacuous: a
// production-root file that constructs the dev CA must be caught.
func TestNoDevCAReachGateCanFail(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "cmd", "controlplane-app")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	src := "package main\n\nfunc f() { _, _ = agent.NewDevCA(\"ca\", nil) }\n"
	if err := os.WriteFile(filepath.Join(dir, "sneaky.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	violations, err := CheckNoDevCAReach(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(violations) == 0 {
		t.Fatal("the gate missed a production-root file that constructs the dev CA — it cannot fail, so it is not a gate")
	}
}

// TestCustodyGatesIgnoreTestFiles asserts both scans' stated scope: a test
// may stand up dev custody (dev/test compositions do exactly this), and a
// test is not part of the shipped control plane.
func TestCustodyGatesIgnoreTestFiles(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "cmd", "controlplane-app")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	src := "package main\n\nfunc f() { _, _ = agent.NewDevCA(\"ca\", nil); _, _ = tls.X509KeyPair(nil, nil) }\n"
	if err := os.WriteFile(filepath.Join(dir, "dev_test.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	km, err := CheckNoCAKeyMaterial(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	dev, err := CheckNoDevCAReach(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(km) != 0 || len(dev) != 0 {
		t.Fatalf("test files are out of scope for the custody scans, got %d key-material and %d dev-CA violations", len(km), len(dev))
	}
}
