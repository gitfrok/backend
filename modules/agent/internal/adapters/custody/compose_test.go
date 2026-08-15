package custody

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// memSnapshotStore is an in-memory SnapshotStore for the composition tests:
// it remembers the last snapshot saved and can be primed or broken by tests.
type memSnapshotStore struct {
	mu      sync.Mutex
	snap    Snapshot
	present bool
	saves   int
	loadErr error
	saveErr error
}

func (m *memSnapshotStore) Load() (Snapshot, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.loadErr != nil {
		return Snapshot{}, false, m.loadErr
	}
	return m.snap, m.present, nil
}

func (m *memSnapshotStore) Save(snap Snapshot) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.saveErr != nil {
		return m.saveErr
	}
	m.snap, m.present, m.saves = snap, true, m.saves+1
	return nil
}

func (m *memSnapshotStore) state() (Snapshot, bool, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.snap, m.present, m.saves
}

var composeNow = time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)

// TestComposeIssuerBootstrapsWhenNoSnapshot is branch 2: nothing persisted,
// nothing in custody — ComposeIssuer bootstraps the first root and the
// bootstrap's own stage is already persisted through the change hook.
func TestComposeIssuerBootstrapsWhenNoSnapshot(t *testing.T) {
	signer := NewFakeSigner()
	store := &memSnapshotStore{}
	issuer, err := ComposeIssuer(context.Background(), signer, store, "agent-ca", func() time.Time { return composeNow }, nil)
	if err != nil {
		t.Fatalf("compose: %v", err)
	}
	if !signer.HasKey("agent-ca") {
		t.Fatal("bootstrap must generate the first root's key in custody")
	}
	roots := issuer.Bundle().Roots()
	if len(roots) != 1 || roots[0].Ref != KeyRef("agent-ca") {
		t.Fatalf("roots = %+v, want the one bootstrapped root", roots)
	}
	snap, present, saves := store.state()
	if !present || saves < 1 {
		t.Fatalf("the bootstrap's stage must persist through the hook: present=%v saves=%d", present, saves)
	}
	if len(snap.Roots) != 1 || snap.Roots[0].Ref != KeyRef("agent-ca") {
		t.Fatalf("persisted snapshot = %+v, want the bootstrapped root", snap)
	}
}

// TestComposeIssuerRestoresSnapshotAcrossRestart is branch 1, the restart
// half of Wave-3 review C1: a bundle that staged a rotation and recorded an
// issuance comes back after a simulated control-plane restart with BOTH
// roots, the SAME staging revision and the SAME ledger — and custody is
// never asked to generate a key again.
func TestComposeIssuerRestoresSnapshotAcrossRestart(t *testing.T) {
	signer := NewFakeSigner()
	store := &memSnapshotStore{}
	now := func() time.Time { return composeNow }

	first, err := ComposeIssuer(context.Background(), signer, store, "agent-ca", now, nil)
	if err != nil {
		t.Fatalf("compose first: %v", err)
	}
	if _, err := first.Bundle().Stage(context.Background(), "agent-ca-next"); err != nil {
		t.Fatalf("stage rotation: %v", err)
	}
	first.Bundle().RecordIssuance("cert-1", KeyRef("agent-ca"), composeNow.Add(24*time.Hour))
	wantRev, wantStaging := first.Bundle().Revision(), first.Bundle().StagingRevision()

	// The restart: a NEW issuer over the SAME custody service and store.
	second, err := ComposeIssuer(context.Background(), signer, store, "agent-ca", now, nil)
	if err != nil {
		t.Fatalf("compose after restart: %v", err)
	}
	generates, _, _ := signer.Counts()
	if generates != 2 {
		t.Fatalf("custody saw %d GenerateKey calls across the restart; want exactly the two staging steps (bootstrap + stage), the restore adds none", generates)
	}
	roots := second.Bundle().Roots()
	if len(roots) != 2 || roots[0].Ref != KeyRef("agent-ca") || roots[1].Ref != KeyRef("agent-ca-next") {
		t.Fatalf("restored roots = %+v, want both staged roots in order", roots)
	}
	if got := second.Bundle().Revision(); got != wantRev {
		t.Fatalf("restored revision = %d, want %d — a restart neither replays nor skips a step", got, wantRev)
	}
	if got := second.Bundle().StagingRevision(); got != wantStaging {
		t.Fatalf("restored staging revision = %d, want %d — the fleet re-sees the revision it last saw", got, wantStaging)
	}
	// The ledger came back: removing the OLD root while a live certificate
	// chains to it is refused — the precondition reads the restored ledger.
	if err := second.Bundle().RemoveRoot(KeyRef("agent-ca")); err == nil {
		t.Fatal("the restored ledger must still refuse removing a root a live certificate chains to")
	}
	// Mid-window restart re-publishes the same revision the fleet last saw.
	st, ok, err := second.Bundle().LatestCATrustBundle(context.Background())
	if err != nil || !ok || st.Revision != wantStaging || len(st.Roots) != 2 {
		t.Fatalf("restored distribution = %+v,%v,%v; want revision %d with both roots", st, ok, err, wantStaging)
	}
}

// TestComposeIssuerReattachesWhenKeyExists is branch 3: custody kept the key,
// the control plane lost its snapshot. ComposeIssuer does NOT fail on
// ErrKeyExists and does NOT stage a second key — it re-attaches by the
// existing key's public half, starts a fresh revision, logs the branch
// loudly, and persists the rebuilt root.
func TestComposeIssuerReattachesWhenKeyExists(t *testing.T) {
	signer := NewFakeSigner()
	store := &memSnapshotStore{}
	// Custody already holds the key — e.g. a snapshot file lost to a volume
	// rebuild while OpenBao kept its transit keys.
	if _, err := signer.GenerateKey(context.Background(), "agent-ca"); err != nil {
		t.Fatalf("pre-create: %v", err)
	}
	var logs []string
	logf := func(format string, args ...any) {
		logs = append(logs, strings.TrimSpace(format))
	}
	issuer, err := ComposeIssuer(context.Background(), signer, store, "agent-ca", func() time.Time { return composeNow }, logf)
	if err != nil {
		t.Fatalf("compose must re-attach, not fail: %v", err)
	}
	generates, _, _ := signer.Counts()
	if generates != 1 {
		t.Fatalf("custody saw %d GenerateKey calls; re-attach reads the public half, it never generates a second key", generates)
	}
	roots := issuer.Bundle().Roots()
	if len(roots) != 1 || roots[0].Ref != KeyRef("agent-ca") {
		t.Fatalf("roots = %+v, want the one re-attached root", roots)
	}
	if got := issuer.Bundle().Revision(); got != 1 {
		t.Fatalf("re-attached revision = %d, want 1 — the epoch starts fresh", got)
	}
	joined := strings.Join(logs, "\n")
	if !strings.Contains(joined, "re-attach") {
		t.Fatalf("the re-attach branch must log loudly; logs = %q", joined)
	}
	// The rebuilt root is persisted, so the NEXT restart takes branch 1.
	snap, present, _ := store.state()
	if !present || len(snap.Roots) != 1 {
		t.Fatalf("the re-attached root must persist: present=%v snap=%+v", present, snap)
	}
}

// TestComposeIssuerCorruptSnapshotFailsLoudly: a snapshot Load that fails —
// the shape of a partial or corrupt write — refuses startup outright. It
// never falls through to bootstrap: re-bootstrapping against custody that
// kept its keys would diverge the served window from the fleet's.
func TestComposeIssuerCorruptSnapshotFailsLoudly(t *testing.T) {
	signer := NewFakeSigner()
	store := &memSnapshotStore{loadErr: errors.New("snapshot truncated")}
	if _, err := ComposeIssuer(context.Background(), signer, store, "agent-ca", nil, nil); err == nil {
		t.Fatal("a corrupt snapshot must fail the composition")
	}
	generates, _, _ := signer.Counts()
	if generates != 0 {
		t.Fatalf("a refused load must never fall through to bootstrap; custody saw %d GenerateKey calls", generates)
	}
}

// TestChangeHookPersistsEveryChange: after composition, EVERY bundle state
// change — a staged root, a ledger entry — lands in the store. A restart
// between any two changes restores the state at the last one.
func TestChangeHookPersistsEveryChange(t *testing.T) {
	signer := NewFakeSigner()
	store := &memSnapshotStore{}
	issuer, err := ComposeIssuer(context.Background(), signer, store, "agent-ca", func() time.Time { return composeNow }, nil)
	if err != nil {
		t.Fatalf("compose: %v", err)
	}
	_, _, savesAfterBootstrap := store.state()

	if _, err := issuer.Bundle().Stage(context.Background(), "agent-ca-next"); err != nil {
		t.Fatalf("stage: %v", err)
	}
	snap, _, savesAfterStage := store.state()
	if savesAfterStage != savesAfterBootstrap+1 || len(snap.Roots) != 2 {
		t.Fatalf("a staged root must persist: saves %d->%d, roots in snapshot %d", savesAfterBootstrap, savesAfterStage, len(snap.Roots))
	}

	issuer.Bundle().RecordIssuance("cert-1", KeyRef("agent-ca-next"), composeNow.Add(24*time.Hour))
	snap, _, savesAfterLedger := store.state()
	if savesAfterLedger != savesAfterStage+1 || len(snap.Issued) != 1 {
		t.Fatalf("a ledger entry must persist: saves %d->%d, ledger in snapshot %d", savesAfterStage, savesAfterLedger, len(snap.Issued))
	}
}

// TestFileSnapshotStoreRoundTrip: what Save writes, Load hands back — exactly.
func TestFileSnapshotStoreRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "custody.snapshot")
	store, err := NewFileSnapshotStore(path)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	want := Snapshot{
		Revision:        7,
		StagingRevision: 3,
		Roots:           []SnapshotRoot{{Ref: "agent-ca", CertDER: []byte{1, 2, 3}, StagedAt: composeNow}},
		Issued:          []SnapshotIssued{{CertificateID: "cert-1", RootRef: "agent-ca", ExpiresAt: composeNow.Add(time.Hour)}},
	}
	if err := store.Save(want); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, ok, err := store.Load()
	if err != nil || !ok {
		t.Fatalf("load = %v,%v after a save", ok, err)
	}
	if got.Revision != want.Revision || got.StagingRevision != want.StagingRevision ||
		len(got.Roots) != 1 || got.Roots[0].Ref != want.Roots[0].Ref ||
		len(got.Issued) != 1 || got.Issued[0].CertificateID != "cert-1" {
		t.Fatalf("round-trip = %+v, want %+v", got, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("snapshot file mode = %v, want 0600", info.Mode().Perm())
	}
}

// TestFileSnapshotStoreMissingIsAbsent: a file that was never written is the
// honest absence — no snapshot, no error.
func TestFileSnapshotStoreMissingIsAbsent(t *testing.T) {
	store, err := NewFileSnapshotStore(filepath.Join(t.TempDir(), "never-written.snapshot"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	if _, ok, err := store.Load(); err != nil || ok {
		t.Fatalf("load of a missing file = ok:%v err:%v; want absent and no error", ok, err)
	}
}

// TestFileSnapshotStoreCorruptFails: a partial write or foreign content at
// the snapshot path is never treated as an absence — Load refuses it.
func TestFileSnapshotStoreCorruptFails(t *testing.T) {
	for name, content := range map[string]string{
		"truncated json": `{"format":"gitfrok.agent-custody.snapshot.v1","snapshot":{"Revi`,
		"foreign json":   `{"unrelated": true}`,
		"wrong format":   `{"format":"something-else.v9","snapshot":{}}`,
		"empty file":     ``,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "custody.snapshot")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatalf("seed: %v", err)
			}
			store, err := NewFileSnapshotStore(path)
			if err != nil {
				t.Fatalf("store: %v", err)
			}
			if _, ok, err := store.Load(); err == nil || ok {
				t.Fatalf("load of a corrupt snapshot = ok:%v err:%v; want a refusal", ok, err)
			}
		})
	}
}

// TestFileSnapshotStoreSaveReplacesAtomically: a second Save overwrites the
// first COMPLETELY — the file always holds one whole snapshot, because the
// write commits at the rename, not in place.
func TestFileSnapshotStoreSaveReplacesAtomically(t *testing.T) {
	path := filepath.Join(t.TempDir(), "custody.snapshot")
	store, err := NewFileSnapshotStore(path)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	if err := store.Save(Snapshot{Revision: 1}); err != nil {
		t.Fatalf("first save: %v", err)
	}
	if err := store.Save(Snapshot{Revision: 2}); err != nil {
		t.Fatalf("second save: %v", err)
	}
	got, ok, err := store.Load()
	if err != nil || !ok || got.Revision != 2 {
		t.Fatalf("after two saves load = %+v,%v,%v; want exactly the newest snapshot", got, ok, err)
	}
	// No temp litter left beside the target.
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("snapshot dir holds %d entries; want only the snapshot itself", len(entries))
	}
}

// TestComposeIssuerAgainstFileStore is the end-to-end restart shape over the
// REAL file store: bootstrap, stage, crash (drop the issuer), restart — the
// restored bundle re-publishes the fleet's revision from disk.
func TestComposeIssuerAgainstFileStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent-ca.snapshot")
	signer := NewFakeSigner()
	store, err := NewFileSnapshotStore(path)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	first, err := ComposeIssuer(context.Background(), signer, store, "agent-ca", func() time.Time { return composeNow }, nil)
	if err != nil {
		t.Fatalf("compose first: %v", err)
	}
	if _, err := first.Bundle().Stage(context.Background(), "agent-ca-next"); err != nil {
		t.Fatalf("stage: %v", err)
	}
	wantStaging := first.Bundle().StagingRevision()

	second, err := ComposeIssuer(context.Background(), signer, store, "agent-ca", func() time.Time { return composeNow }, nil)
	if err != nil {
		t.Fatalf("compose after restart: %v", err)
	}
	st, ok, err := second.Bundle().LatestCATrustBundle(context.Background())
	if err != nil || !ok || st.Revision != wantStaging || len(st.Roots) != 2 {
		t.Fatalf("restart over the file store = %+v,%v,%v; want staging revision %d with both roots", st, ok, err, wantStaging)
	}
}
