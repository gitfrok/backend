package main

import (
	"strings"
	"testing"
	"time"
)

// The release trust bundle's env posture tests (T-0041, SPEC-0045 AC2). The
// refusals mirror the custody posture of SPEC-0044 — configured-but-broken
// fails the rollout before it serves — while the ENABLED gate differs
// deliberately: an unset snapshot file is the honest "distribution not
// configured" branch (the additive DesiredState.release_trust_bundle field
// stays empty), never an error.

// TestLoadReleaseTrustConfigUnsetIsHonestAbsence: with no snapshot file the
// loader reports disabled, not an error — the door serves the channel with
// the release_trust_bundle field empty and logs that posture loudly.
func TestLoadReleaseTrustConfigUnsetIsHonestAbsence(t *testing.T) {
	cfg, err := loadReleaseTrustConfig(func(string) string { return "" })
	if err != nil {
		t.Fatalf("loadReleaseTrustConfig with nothing set = %v; want the honest disabled branch", err)
	}
	if cfg.enabled {
		t.Fatalf("enabled = true with no %s; want distribution-not-configured", releaseTrustSnapshotFileEnv)
	}
}

// TestLoadReleaseTrustConfigSeedIsOneArtifact: a seed key ID without its
// PUBLIC PEM file (or the converse) is a configuration error — the pair is
// one artifact, exactly like the custody posture's paired refusals.
func TestLoadReleaseTrustConfigSeedIsOneArtifact(t *testing.T) {
	for name, env := range map[string]map[string]string{
		"id without pem": {
			releaseTrustSnapshotFileEnv: "/var/lib/controlplane/release-trust.snapshot",
			releaseTrustSeedIDEnv:       "release-signing-gen1",
		},
		"pem without id": {
			releaseTrustSnapshotFileEnv: "/var/lib/controlplane/release-trust.snapshot",
			releaseTrustSeedPEMEnv:      "/etc/gitfrok/release-trust/gen1.pub",
		},
	} {
		_, err := loadReleaseTrustConfig(func(k string) string { return env[k] })
		if err == nil || !strings.Contains(err.Error(), releaseTrustSeedIDEnv) {
			t.Fatalf("%s: loadReleaseTrustConfig = %v; want the seed-pair refusal naming %s", name, err, releaseTrustSeedIDEnv)
		}
	}
}

// TestLoadReleaseTrustConfigRefusesMalformedInterval: a reconcile interval
// that is not a positive duration fails the rollout — an unbounded interval
// is how a staged key declaration goes unnoticed indefinitely.
func TestLoadReleaseTrustConfigRefusesMalformedInterval(t *testing.T) {
	for _, bad := range []string{"soon", "-5s", "0s"} {
		env := map[string]string{
			releaseTrustSnapshotFileEnv:   "/var/lib/controlplane/release-trust.snapshot",
			releaseTrustReconcileEveryEnv: bad,
		}
		_, err := loadReleaseTrustConfig(func(k string) string { return env[k] })
		if err == nil || !strings.Contains(err.Error(), releaseTrustReconcileEveryEnv) {
			t.Fatalf("interval %q: loadReleaseTrustConfig = %v; want the %s refusal", bad, err, releaseTrustReconcileEveryEnv)
		}
	}
}

// TestLoadReleaseTrustConfigCarriesThePosture: every configured value reaches
// the composition exactly as set, and the reconcile interval defaults to the
// thirty-second bound when unset.
func TestLoadReleaseTrustConfigCarriesThePosture(t *testing.T) {
	env := map[string]string{
		releaseTrustSnapshotFileEnv: "/var/lib/controlplane/release-trust.snapshot",
		releaseTrustSeedIDEnv:       "release-signing-gen1",
		releaseTrustSeedPEMEnv:      "/etc/gitfrok/release-trust/gen1.pub",
		releaseTrustStagingDirEnv:   "/etc/gitfrok/release-trust/staging",
	}
	cfg, err := loadReleaseTrustConfig(func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("loadReleaseTrustConfig: %v", err)
	}
	if !cfg.enabled {
		t.Fatal("enabled = false with a snapshot file set; want distribution configured")
	}
	if cfg.snapshotFile != "/var/lib/controlplane/release-trust.snapshot" {
		t.Fatalf("snapshotFile = %q; want the configured path", cfg.snapshotFile)
	}
	if cfg.seedID != "release-signing-gen1" || cfg.seedPEMFile != "/etc/gitfrok/release-trust/gen1.pub" {
		t.Fatalf("seed = (%q, %q); want the configured pair", cfg.seedID, cfg.seedPEMFile)
	}
	if cfg.stagingDir != "/etc/gitfrok/release-trust/staging" {
		t.Fatalf("stagingDir = %q; want the configured directory", cfg.stagingDir)
	}
	if cfg.reconcileEvery != 30*time.Second {
		t.Fatalf("reconcileEvery = %s; want the 30s default bound", cfg.reconcileEvery)
	}
}
