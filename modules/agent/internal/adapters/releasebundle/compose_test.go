package releasebundle_test

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gitfrok/backend/modules/agent/internal/adapters/releasebundle"
)

func mustStore(t *testing.T, path string) *releasebundle.FileSnapshotStore {
	t.Helper()
	store, err := releasebundle.NewFileSnapshotStore(path)
	if err != nil {
		t.Fatalf("NewFileSnapshotStore: %v", err)
	}
	return store
}

// The composition seam (T-0041, SPEC-0045 AC2): Compose wires the bundle's
// durable state BEFORE any state change, so a crash between bootstrap and
// the next change still leaves the snapshot behind — and a corrupt snapshot
// fails LOUDLY instead of silently re-bootstrapping the revision epoch.

func TestComposeBootstrapPersistsSnapshot(t *testing.T) {
	dir := t.TempDir()
	snapPath := filepath.Join(dir, "release-trust.snapshot")
	seed := newTestKey(t, "release-signing-seed")
	if err := os.WriteFile(filepath.Join(dir, "seed.pub"), seed.pem, 0o600); err != nil {
		t.Fatal(err)
	}

	b, err := releasebundle.Compose(releasebundle.ComposeConfig{
		SnapshotFile: snapPath,
		SeedKeyID:    seed.id,
		SeedPEMFile:  filepath.Join(dir, "seed.pub"),
	}, mustStore(t, snapPath))
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	st, ok, err := b.LatestReleaseTrustBundle(t.Context())
	if err != nil || !ok || len(st.Keys) != 1 || st.Keys[0].ID != seed.id {
		t.Fatalf("bootstrapped bundle = %+v (ok=%v err=%v), want the seed key", st, ok, err)
	}
	// The hook fired BEFORE the bootstrap returned: the snapshot is already
	// on disk, so a crash right now does not lose the epoch.
	if _, err := os.Stat(snapPath); err != nil {
		t.Fatalf("bootstrap did not persist its snapshot through the change hook: %v", err)
	}
}

func TestComposeRestoresSnapshot(t *testing.T) {
	dir := t.TempDir()
	snapPath := filepath.Join(dir, "release-trust.snapshot")
	store, err := releasebundle.NewFileSnapshotStore(snapPath)
	if err != nil {
		t.Fatalf("NewFileSnapshotStore: %v", err)
	}
	k1, k2 := newTestKey(t, "release-signing-gen1"), newTestKey(t, "release-signing-gen2")
	b, err := releasebundle.NewBundle(time.Now)
	if err != nil {
		t.Fatalf("NewBundle: %v", err)
	}
	if err := b.Bootstrap(k1.id, k1.pem); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if err := b.Stage(k2.id, k2.pem); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if err := store.Save(b.Snapshot()); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// The mid-window restart: no seed configured, the snapshot alone must
	// bring the bundle back exactly where the fleet last saw it.
	restored, err := releasebundle.Compose(releasebundle.ComposeConfig{SnapshotFile: snapPath}, store)
	if err != nil {
		t.Fatalf("Compose on snapshot: %v", err)
	}
	signID, err := restored.SigningKeyID()
	if err != nil {
		t.Fatalf("SigningKeyID: %v", err)
	}
	if restored.Revision() != b.Revision() || restored.StagingRevision() != b.StagingRevision() || signID != k2.id {
		t.Fatalf("restored bundle = rev %d/%d signing %q, want %d/%d %q",
			restored.Revision(), restored.StagingRevision(), signID,
			b.Revision(), b.StagingRevision(), k2.id)
	}
}

func TestComposeStartsEmptyWithoutSeed(t *testing.T) {
	dir := t.TempDir()
	snapPath := filepath.Join(dir, "release-trust.snapshot")
	b, err := releasebundle.Compose(releasebundle.ComposeConfig{SnapshotFile: snapPath}, mustStore(t, snapPath))
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if _, ok, err := b.LatestReleaseTrustBundle(t.Context()); err != nil || ok {
		t.Fatalf("LatestReleaseTrustBundle = (_, %v, %v), want the honest empty bundle", ok, err)
	}
}

func TestComposeRefusesCorruptSnapshot(t *testing.T) {
	dir := t.TempDir()
	snapPath := filepath.Join(dir, "release-trust.snapshot")
	if err := os.WriteFile(snapPath, []byte("{corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	seed := newTestKey(t, "release-signing-seed")
	pemPath := filepath.Join(dir, "seed.pub")
	if err := os.WriteFile(pemPath, seed.pem, 0o600); err != nil {
		t.Fatal(err)
	}
	// A refused load must NOT fall through to bootstrap: that would restart
	// the revision epoch at one and diverge from the revisions the fleet acked.
	_, err := releasebundle.Compose(releasebundle.ComposeConfig{
		SnapshotFile: snapPath,
		SeedKeyID:    seed.id,
		SeedPEMFile:  pemPath,
	}, mustStore(t, snapPath))
	if err == nil {
		t.Fatal("Compose must fail loudly on a corrupt snapshot, never fall through to bootstrap")
	}
}

func TestComposeRefusesPrivateSeedKey(t *testing.T) {
	dir := t.TempDir()
	snapPath := filepath.Join(dir, "release-trust.snapshot")
	seed := newTestKey(t, "release-signing-seed")
	privDER, err := x509.MarshalECPrivateKey(seed.priv)
	if err != nil {
		t.Fatal(err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})
	pemPath := filepath.Join(dir, "seed.pub")
	if err := os.WriteFile(pemPath, privPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = releasebundle.Compose(releasebundle.ComposeConfig{
		SnapshotFile: snapPath,
		SeedKeyID:    seed.id,
		SeedPEMFile:  pemPath,
	}, mustStore(t, snapPath))
	if err == nil {
		t.Fatal("Compose must refuse a PRIVATE seed key — the custody posture of ADR-0044")
	}
}

func TestComposeConfigValidation(t *testing.T) {
	dir := t.TempDir()
	store, err := releasebundle.NewFileSnapshotStore(filepath.Join(dir, "s.snapshot"))
	if err != nil {
		t.Fatalf("NewFileSnapshotStore: %v", err)
	}
	if _, err := releasebundle.Compose(releasebundle.ComposeConfig{}, store); err == nil {
		t.Fatal("Compose without a snapshot file must be refused")
	}
	if _, err := releasebundle.Compose(releasebundle.ComposeConfig{SnapshotFile: "x.snapshot"}, nil); err == nil {
		t.Fatal("Compose with a nil store must be refused")
	}
	if _, err := releasebundle.Compose(releasebundle.ComposeConfig{SnapshotFile: "x.snapshot", SeedKeyID: "k"}, store); err == nil {
		t.Fatal("Compose with a seed ID but no seed PEM file must be refused")
	}
}
