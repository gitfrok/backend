package releasebundle

import (
	"errors"
	"fmt"
	"os"
	"time"
)

// ComposeConfig wires the restart-proof release trust bundle (T-0041,
// SPEC-0045 AC2): where the durable state lives and, for a FIRST startup,
// the seed public key the publishing CI hands over. Named apart from the
// custody composition of SPEC-0044 — different artifact, different config,
// different snapshot format.
//
// SECRECY, stated once for this surface: the seed and every staged key are
// PUBLIC verification keys in the cosign key form of ADR-0044. The matching
// private halves live only in the publishing CI's protected environment and
// never enter this process; a private key presented here is refused by
// Stage's parser.
type ComposeConfig struct {
	// SnapshotFile is where the bundle's durable state lives. Required: a
	// bundle with nowhere to persist its revision epoch would restart the
	// epoch at one on every boot and re-distribute stale revisions the fleet
	// already moved past.
	SnapshotFile string
	// SeedKeyID / SeedPEMFile bootstrap a FIRST startup — the bundle's
	// very first key, before any staging directory or rotation exists.
	// Optional: a first startup without a seed starts EMPTY and distributes
	// nothing until the staging directory declares keys (an honest absence —
	// the channel's release_trust_bundle field is additive by design). The
	// PEM file must carry a PUBLIC key; a private key fails the rollout.
	SeedKeyID   string
	SeedPEMFile string
	Now         func() time.Time
	Logf        func(format string, args ...any)
}

// Compose builds the restart-proof bundle over store: one Bundle whose
// durable state lives in store, bootstrapped from the seed key when one is
// configured and no snapshot exists yet. Three branches — and exactly three,
// the same shape the custody composition of SPEC-0044 uses (Wave-3 review
// C1), applied to THIS bundle's artifacts:
//
//  1. A snapshot is present  -> Restore: the bundle comes back exactly where
//     the fleet last saw it; a mid-window restart re-publishes exactly the
//     revision the planes last acked.
//  2. No snapshot, seed set  -> Bootstrap the seed public key and persist it
//     through the change hook wired BEFORE the bootstrap fires.
//  3. No snapshot, no seed   -> start empty: the channel distributes nothing
//     (LatestReleaseTrustBundle reports ok=false) until the staging seam
//     declares keys. Loudly logged — an empty fleet trust set is a posture,
//     never an accident.
//
// A corrupt or partial snapshot fails LOUDLY: falling through from a refused
// load to bootstrap would restart the revision epoch and diverge the window
// this process serves from the one the fleet holds.
func Compose(cfg ComposeConfig, store SnapshotStore) (*Bundle, error) {
	if store == nil {
		return nil, errors.New("releasebundle: nil snapshot store")
	}
	if cfg.SnapshotFile == "" {
		return nil, errors.New("releasebundle: snapshot file path is required: the bundle's durable " +
			"revision epoch must survive a control-plane restart, and a bundle with nowhere to persist it " +
			"would restart the epoch at one on every boot")
	}
	if (cfg.SeedKeyID == "") != (cfg.SeedPEMFile == "") {
		return nil, errors.New("releasebundle: seed key ID and seed PEM file must be set together")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}

	bundle, err := NewBundle(cfg.Now)
	if err != nil {
		return nil, err
	}
	// The hook is wired BEFORE any state change so the bootstrap's own stage
	// is persisted: a crash right after bootstrap must still leave the
	// snapshot behind, or the next start re-enters branch 2/3.
	bundle.SetChangeHook(func(snap Snapshot) {
		if err := store.Save(snap); err != nil {
			cfg.Logf("releasebundle: FAILED to persist the bundle snapshot: %v — a restart before the next successful save will not see the newest staging state", err)
		}
	})

	snap, ok, err := store.Load()
	if err != nil {
		return nil, fmt.Errorf("releasebundle: load bundle snapshot: %w", err)
	}
	if ok {
		if err := bundle.Restore(snap); err != nil {
			return nil, fmt.Errorf("releasebundle: restore bundle snapshot: %w", err)
		}
		return bundle, nil
	}

	if cfg.SeedKeyID != "" {
		pemBytes, err := os.ReadFile(cfg.SeedPEMFile)
		if err != nil {
			return nil, fmt.Errorf("releasebundle: read seed key %q: %w", cfg.SeedPEMFile, err)
		}
		if err := bundle.Bootstrap(cfg.SeedKeyID, pemBytes); err != nil {
			return nil, fmt.Errorf("releasebundle: bootstrap seed key %q: %w", cfg.SeedKeyID, err)
		}
		return bundle, nil
	}

	cfg.Logf("releasebundle: no snapshot and no seed key — starting EMPTY; the channel distributes no " +
		"release trust bundle until the staging directory declares keys (an honest absence, never an accident)")
	return bundle, nil
}
