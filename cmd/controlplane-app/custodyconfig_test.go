package main

import (
	"strings"
	"testing"
)

// TestLoadCustodyConfigRequiresSnapshotFile is the fail-fast env half of the
// Wave-3 C1 fix: with the agent door open, an unset
// GITFROK_CUSTODY_SNAPSHOT_FILE is a startup error with a clear message —
// the bundle's durable state has nowhere to live, and the rollout refuses
// before the first restart could crash-loop.
func TestLoadCustodyConfigRequiresSnapshotFile(t *testing.T) {
	env := map[string]string{custodyOpenBaoAddrEnv: "https://openbao.control-plane.svc:8200"}
	_, err := loadCustodyConfig(func(k string) string { return env[k] })
	if err == nil || !strings.Contains(err.Error(), custodySnapshotFileEnv) {
		t.Fatalf("loadCustodyConfig without a snapshot file = %v; want the %s refusal", err, custodySnapshotFileEnv)
	}
}

// TestLoadCustodyConfigCarriesTheSnapshotFile: a configured snapshot path
// reaches the issuer composition exactly as set.
func TestLoadCustodyConfigCarriesTheSnapshotFile(t *testing.T) {
	env := map[string]string{
		custodyOpenBaoAddrEnv:  "https://openbao.control-plane.svc:8200",
		custodySnapshotFileEnv: "/var/lib/controlplane/agent-ca.snapshot",
	}
	cfg, err := loadCustodyConfig(func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("loadCustodyConfig: %v", err)
	}
	if cfg.SnapshotFile != "/var/lib/controlplane/agent-ca.snapshot" {
		t.Fatalf("SnapshotFile = %q; want the configured path", cfg.SnapshotFile)
	}
}
