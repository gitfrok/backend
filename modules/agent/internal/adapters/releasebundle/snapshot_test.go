package releasebundle_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gitfrok/backend/modules/agent/internal/adapters/releasebundle"
)

// The durable-state half of SPEC-0045 AC2 for the RELEASE trust bundle: the
// snapshot round-trips exactly, an absent file is the honest absence, and a
// corrupt or foreign file is refused — never treated as "nothing yet"
// (Compose must never fall through a refused load into bootstrap).

func TestSnapshotSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "release-trust.snapshot")
	store, err := releasebundle.NewFileSnapshotStore(path)
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

	snap, ok, err := store.Load()
	if err != nil || !ok {
		t.Fatalf("Load = (_, %v, %v), want a snapshot", ok, err)
	}
	if snap.Revision != b.Revision() || snap.StagingRevision != b.StagingRevision() || snap.SigningKeyID != k2.id {
		t.Fatalf("round-tripped snapshot = %+v, want revision %d/%d signing %q", snap, b.Revision(), b.StagingRevision(), k2.id)
	}
	if len(snap.Keys) != 2 || snap.Keys[0].ID != k1.id || snap.Keys[1].ID != k2.id {
		t.Fatalf("round-tripped keys = %+v, want [gen1 gen2]", snap.Keys)
	}
	// The snapshot is written 0600: public trust metadata is still not world
	// writable on the control plane's own filesystem.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat snapshot: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("snapshot mode = %v, want 0600", info.Mode().Perm())
	}
}

func TestSnapshotLoadAbsentIsHonest(t *testing.T) {
	store, err := releasebundle.NewFileSnapshotStore(filepath.Join(t.TempDir(), "never-written.snapshot"))
	if err != nil {
		t.Fatalf("NewFileSnapshotStore: %v", err)
	}
	snap, ok, err := store.Load()
	if err != nil || ok || snap.Revision != 0 {
		t.Fatalf("Load on absent file = (%+v, %v, %v), want honest absence", snap, ok, err)
	}
}

func TestSnapshotLoadCorruptRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "release-trust.snapshot")
	if err := os.WriteFile(path, []byte("{this is not a snapshot"), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := releasebundle.NewFileSnapshotStore(path)
	if err != nil {
		t.Fatalf("NewFileSnapshotStore: %v", err)
	}
	if _, ok, err := store.Load(); err == nil || ok {
		t.Fatal("Load on a corrupt snapshot must fail loudly — a silent absence would re-bootstrap the revision epoch")
	}
}

func TestSnapshotLoadForeignFormatRefused(t *testing.T) {
	// A custody snapshot (SPEC-0044) is not a release trust snapshot: one
	// bundle's durable state is never mistaken for the other's.
	path := filepath.Join(t.TempDir(), "release-trust.snapshot")
	foreign := []byte(`{"format":"gitfrok.agent-custody.snapshot.v1","snapshot":{}}`)
	if err := os.WriteFile(path, foreign, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := releasebundle.NewFileSnapshotStore(path)
	if err != nil {
		t.Fatalf("NewFileSnapshotStore: %v", err)
	}
	if _, ok, err := store.Load(); err == nil || ok {
		t.Fatal("Load must refuse a custody snapshot format — the two bundles never share durable state")
	}
}

func TestSnapshotStoreRequiresPath(t *testing.T) {
	if _, err := releasebundle.NewFileSnapshotStore(""); err == nil {
		t.Fatal("NewFileSnapshotStore without a path must be refused")
	}
}
