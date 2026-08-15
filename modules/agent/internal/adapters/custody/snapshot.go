package custody

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// snapshotFormat names the durable envelope this package writes. A file that
// does not carry exactly this marker is NOT a custody snapshot — Load refuses
// it instead of guessing, and ComposeIssuer never falls through from a
// refused load to Bootstrap (Wave-3 review C1).
const snapshotFormat = "gitfrok.agent-custody.snapshot.v1"

// SnapshotStore is the bundle's durable side: it persists the Snapshot the
// change hook emits and hands it back on the next startup. Snapshot/Restore
// carry the window across a control-plane restart (SPEC-0044 AC2); the store
// is WHERE they land. A snapshot that is present but unreadable is an error,
// never an absence — silently treating a corrupt snapshot as "nothing yet"
// would re-bootstrap against a custody service that kept its keys.
type SnapshotStore interface {
	// Load returns the persisted snapshot. ok is false ONLY when no snapshot
	// exists at all; a present-but-corrupt or partial snapshot is an error.
	Load() (Snapshot, bool, error)
	// Save atomically persists the snapshot so a crash mid-write can never
	// leave a partial file behind in place of the previous good state.
	Save(Snapshot) error
}

// snapshotEnvelope wraps the snapshot in a format marker so a Load can tell a
// custody snapshot from any other file — or from a truncated write.
type snapshotEnvelope struct {
	Format   string   `json:"format"`
	Snapshot Snapshot `json:"snapshot"`
}

// FileSnapshotStore persists the bundle's durable state to one file on the
// control plane's own filesystem. The snapshot is a tenant-less platform
// singleton — it belongs to no tenant, so no tenant-isolated store can carry
// it honestly; a dedicated file named by the composition is its home. The
// file holds ONLY public material and key references (Snapshot carries no
// private half — there is none in this process) and is written 0600.
//
// Save is atomic: temp file, fsync, rename. A crash at any point leaves
// either the previous complete snapshot or none at all — never a partial one
// in place of it.
type FileSnapshotStore struct {
	path string
	mu   sync.Mutex // serializes Save's temp-write-rename sequence
}

// NewFileSnapshotStore returns a store over path. path must be set: a store
// with nowhere to persist is a composition mistake, refused here.
func NewFileSnapshotStore(path string) (*FileSnapshotStore, error) {
	if path == "" {
		return nil, errors.New("custody: snapshot store: path is required")
	}
	return &FileSnapshotStore{path: path}, nil
}

// Load reads the snapshot file. A missing file is the honest absence
// (zero, false, nil); anything present but not a complete, well-formed
// custody snapshot is an error the caller must fail on — loudly.
func (s *FileSnapshotStore) Load() (Snapshot, bool, error) {
	raw, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return Snapshot{}, false, nil
	}
	if err != nil {
		return Snapshot{}, false, fmt.Errorf("custody: snapshot %q: %w", s.path, err)
	}
	var env snapshotEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return Snapshot{}, false, fmt.Errorf(
			"custody: snapshot %q is not a readable custody snapshot (a partial or corrupt write?): %w — refusing to fall through to bootstrap",
			s.path, err)
	}
	if env.Format != snapshotFormat {
		return Snapshot{}, false, fmt.Errorf(
			"custody: snapshot %q carries format %q, not %q — refusing to fall through to bootstrap",
			s.path, env.Format, snapshotFormat)
	}
	return env.Snapshot, true, nil
}

// Save atomically persists the snapshot: write a temp file next to the
// target, fsync it, rename it over the target at mode 0600. The rename is
// the commit point — before it the previous snapshot stands, after it the
// new one does, and no crash in between yields a partial file at the target
// path.
func (s *FileSnapshotStore) Save(snap Snapshot) error {
	raw, err := json.Marshal(snapshotEnvelope{Format: snapshotFormat, Snapshot: snap})
	if err != nil {
		return fmt.Errorf("custody: snapshot %q: encode: %w", s.path, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, ".custody-snapshot-*.tmp")
	if err != nil {
		return fmt.Errorf("custody: snapshot %q: temp file: %w", s.path, err)
	}
	name := tmp.Name()
	defer os.Remove(name) // a no-op once the rename succeeded
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return fmt.Errorf("custody: snapshot %q: write: %w", s.path, err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("custody: snapshot %q: chmod: %w", s.path, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("custody: snapshot %q: fsync: %w", s.path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("custody: snapshot %q: close temp: %w", s.path, err)
	}
	if err := os.Rename(name, s.path); err != nil {
		return fmt.Errorf("custody: snapshot %q: rename into place: %w", s.path, err)
	}
	// Best effort: fsync the directory so the rename itself is durable. A
	// filesystem that cannot is not refused here — the atomicity claim is
	// about the target path's contents, which the rename already commits.
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// ComposeIssuer builds the restart-proof issuer over signer: one Bundle whose
// durable state lives in store, bootstrapped under keyName, and the Issuer
// over it. Three branches — and exactly three (Wave-3 review C1):
//
//  1. A snapshot is present  -> Restore: the bundle comes back exactly where
//     the fleet last saw it; no custody call but what Restore needs (none).
//  2. No snapshot exists     -> Bootstrap: generate the first root and
//     persist it through the change hook the bootstrap itself fires.
//  3. Bootstrap finds the key ALREADY held by custody -> re-attach: read the
//     existing key's public half, rebuild the first root through it, start a
//     FRESH revision epoch and log loudly. The custody side survived a lost
//     snapshot by design; the control-plane side rebuilds what it can — the
//     root — and names what it cannot: the issuance ledger starts empty.
//
// A corrupt or partial snapshot fails LOUDLY — branch 2 is reachable only on
// a genuine absence: falling through from a refused load to bootstrap would
// stage a root against a custody service that kept its keys, and the window
// the fleet trusts would diverge from the window this process serves.
func ComposeIssuer(ctx context.Context, signer Signer, store SnapshotStore, keyName string, now func() time.Time, logf func(format string, args ...any)) (*Issuer, error) {
	if store == nil {
		return nil, errors.New("custody: nil snapshot store")
	}
	if now == nil {
		now = time.Now
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	bundle, err := NewBundle(signer, now)
	if err != nil {
		return nil, err
	}
	// The hook is wired BEFORE any state change so the bootstrap's own stage
	// is persisted: a crash between generate and any later change must still
	// leave the snapshot behind, or the next start re-enters branch 3.
	bundle.SetChangeHook(func(snap Snapshot) {
		if err := store.Save(snap); err != nil {
			logf("custody: FAILED to persist the bundle snapshot: %v — a restart before the next successful save will not see the newest staging state", err)
		}
	})

	snap, ok, err := store.Load()
	if err != nil {
		return nil, fmt.Errorf("custody: load bundle snapshot: %w", err)
	}
	if ok {
		if err := bundle.Restore(snap); err != nil {
			return nil, fmt.Errorf("custody: restore bundle snapshot: %w", err)
		}
		return NewIssuer(bundle)
	}

	if _, err := bundle.Bootstrap(ctx, keyName); err == nil {
		return NewIssuer(bundle)
	} else if !errors.Is(err, ErrKeyExists) {
		return nil, fmt.Errorf("custody: bootstrap %q: %w", keyName, err)
	}
	// Branch 3: custody kept the key; this control plane lost its snapshot.
	// Re-attach by reference — loudly, because the ledger is rebuilt empty.
	logf("custody: bootstrap %q found the key already held by custody and no snapshot to restore: "+
		"re-attaching by the key's public half; the bundle revision starts fresh and the issuance ledger is rebuilt empty", keyName)
	if _, err := bundle.ReattachRoot(ctx, keyName); err != nil {
		return nil, fmt.Errorf("custody: re-attach %q: %w", keyName, err)
	}
	return NewIssuer(bundle)
}
