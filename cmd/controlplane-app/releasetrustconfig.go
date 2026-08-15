package main

import (
	"fmt"
	"time"
)

// The release trust bundle's per-environment configuration (invariant 13,
// T-0041, SPEC-0045 AC2, ADR-0065 decision 2): where the bundle's durable
// revision epoch lives, the seed public key of a first startup, and the
// staging directory the rotation procedure declares keys through. Named
// strictly apart from the custody configuration of SPEC-0044 — the two
// bundles share no env var, no file and no snapshot format.
const (
	// releaseTrustSnapshotFileEnv is the path of the bundle's durable
	// snapshot — where the staged release trust bundle's revision epoch
	// lives across a control-plane restart. The snapshot holds only key IDs
	// and PUBLIC verification keys, so it is a tenant-less platform
	// singleton on the control plane's own filesystem, exactly like the
	// custody snapshot but a different file. Unset means distribution is not
	// configured: the additive DesiredState.release_trust_bundle field
	// simply stays empty (an honest absence, loudly logged) — never an
	// accidental empty-bundle distribution from an unpersisted epoch.
	releaseTrustSnapshotFileEnv = "GITFROK_RELEASE_TRUST_SNAPSHOT_FILE"
	// releaseTrustSeedIDEnv / releaseTrustSeedPEMEnv bootstrap a FIRST
	// startup when no snapshot exists yet: the publishing CI's seed PUBLIC
	// key. They must be set together; a private key is refused by the
	// bundle's parser (ADR-0044 custody posture).
	releaseTrustSeedIDEnv  = "GITFROK_RELEASE_TRUST_SEED_ID"
	releaseTrustSeedPEMEnv = "GITFROK_RELEASE_TRUST_SEED_PEM_FILE"
	// releaseTrustStagingDirEnv is the staged-key ACTUATION seam: the
	// directory whose *.pub files declare the desired live key set.
	// Reconciled at startup and periodically; an empty directory is a
	// no-op, never a mass removal.
	releaseTrustStagingDirEnv = "GITFROK_RELEASE_TRUST_STAGING_DIR"
	// releaseTrustReconcileEveryEnv bounds how late a staged key declaration
	// can go unnoticed; thirty seconds is ample for a rotation procedure.
	releaseTrustReconcileEveryEnv = "GITFROK_RELEASE_TRUST_RECONCILE_EVERY"
)

// releaseTrustConfig is what the composition root reads; enabled is false
// when distribution is not configured.
type releaseTrustConfig struct {
	enabled        bool
	snapshotFile   string
	seedID         string
	seedPEMFile    string
	stagingDir     string
	reconcileEvery time.Duration
}

// loadReleaseTrustConfig reads the release trust posture from the
// environment. The refusals are the custody posture's: a seed ID without its
// PEM file (or vice versa) is a configuration error, and a malformed
// reconcile interval is refused. An unset snapshot file is NOT an error —
// it is the honest "distribution not configured" branch.
func loadReleaseTrustConfig(getenv func(string) string) (releaseTrustConfig, error) {
	snapshotFile := getenv(releaseTrustSnapshotFileEnv)
	if snapshotFile == "" {
		return releaseTrustConfig{enabled: false}, nil
	}
	seedID, seedPEM := getenv(releaseTrustSeedIDEnv), getenv(releaseTrustSeedPEMEnv)
	if (seedID == "") != (seedPEM == "") {
		return releaseTrustConfig{}, fmt.Errorf("%s and %s must be set together: the seed key's ID and its "+
			"PUBLIC PEM file are one artifact", releaseTrustSeedIDEnv, releaseTrustSeedPEMEnv)
	}
	every := 30 * time.Second
	if v := getenv(releaseTrustReconcileEveryEnv); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			return releaseTrustConfig{}, fmt.Errorf("%s must be a positive duration: %q", releaseTrustReconcileEveryEnv, v)
		}
		every = d
	}
	return releaseTrustConfig{
		enabled:        true,
		snapshotFile:   snapshotFile,
		seedID:         seedID,
		seedPEMFile:    seedPEM,
		stagingDir:     getenv(releaseTrustStagingDirEnv),
		reconcileEvery: every,
	}, nil
}
