package releasebundle

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// snapshotFormat names the durable envelope this package writes. A file that
// does not carry exactly this marker is NOT a release trust snapshot — Load
// refuses it instead of guessing, and Compose never falls through from a
// refused load to Bootstrap. Named strictly apart from the custody snapshot
// format of SPEC-0044: one bundle's durable state is never mistaken for the
// other's (SPEC-0045's two-bundles note).
const snapshotFormat = "gitfrok.agent-release-trust.snapshot.v1"

// SnapshotStore is the bundle's durable side: it persists the Snapshot the
// change hook emits and hands it back on the next startup. Snapshot/Restore
// carry the rotation window across a control-plane restart (SPEC-0045 AC2);
// the store is WHERE they land. A snapshot that is present but unreadable is
// an error, never an absence — silently treating a corrupt snapshot as
// "nothing yet" would re-bootstrap a revision epoch the fleet already moved
// past.
type SnapshotStore interface {
	// Load returns the persisted snapshot. ok is false ONLY when no snapshot
	// exists at all; a present-but-corrupt or partial snapshot is an error.
	Load() (Snapshot, bool, error)
	// Save atomically persists the snapshot so a crash mid-write can never
	// leave a partial file behind in place of the previous good state.
	Save(Snapshot) error
}

// snapshotEnvelope wraps the snapshot in a format marker so a Load can tell a
// release trust snapshot from any other file — or from a truncated write.
type snapshotEnvelope struct {
	Format   string   `json:"format"`
	Snapshot Snapshot `json:"snapshot"`
}

// FileSnapshotStore persists the bundle's durable state to one file on the
// control plane's own filesystem. The snapshot is a tenant-less platform
// singleton — it belongs to no tenant, so no tenant-isolated store can carry
// it honestly; a dedicated file named by the composition is its home. The
// file holds ONLY public verification keys and window metadata (Snapshot
// carries no private half — there is none in this process) and is written
// 0600.
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
		return nil, errors.New("releasebundle: snapshot store: path is required")
	}
	return &FileSnapshotStore{path: path}, nil
}

// Load reads the snapshot file. A missing file is the honest absence
// (zero, false, nil); anything present but not a complete, well-formed
// release trust snapshot is an error the caller must fail on — loudly.
func (s *FileSnapshotStore) Load() (Snapshot, bool, error) {
	raw, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return Snapshot{}, false, nil
	}
	if err != nil {
		return Snapshot{}, false, fmt.Errorf("releasebundle: snapshot %q: %w", s.path, err)
	}
	var env snapshotEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return Snapshot{}, false, fmt.Errorf(
			"releasebundle: snapshot %q is not a readable release trust snapshot (a partial or corrupt write?): %w — refusing to fall through to bootstrap",
			s.path, err)
	}
	if env.Format != snapshotFormat {
		return Snapshot{}, false, fmt.Errorf(
			"releasebundle: snapshot %q carries format %q, not %q — refusing to fall through to bootstrap",
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
		return fmt.Errorf("releasebundle: snapshot %q: encode: %w", s.path, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, ".release-trust-snapshot-*.tmp")
	if err != nil {
		return fmt.Errorf("releasebundle: snapshot %q: temp file: %w", s.path, err)
	}
	name := tmp.Name()
	defer os.Remove(name) // a no-op once the rename succeeded
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return fmt.Errorf("releasebundle: snapshot %q: write: %w", s.path, err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("releasebundle: snapshot %q: chmod: %w", s.path, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("releasebundle: snapshot %q: fsync: %w", s.path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("releasebundle: snapshot %q: close temp: %w", s.path, err)
	}
	if err := os.Rename(name, s.path); err != nil {
		return fmt.Errorf("releasebundle: snapshot %q: rename into place: %w", s.path, err)
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
