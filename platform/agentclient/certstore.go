// Package agentclient is the data-plane half of the agent channel (T-0031, SPEC-0039 AC1,
// SPEC-0038, ADR-0060): the client that runs in a customer's cluster, dials the control plane
// outbound, presents the one-time enrolment token on its first Connect, stores the issued client
// certificate, and applies on-channel rotations.
//
// SECRECY (SPEC-0038 AC2): the one-time token is a bearer credential. It is supplied at install
// time, presented exactly once on the bootstrap stream, and never logged, never echoed into an
// error, and never handed to the credential store. The store only ever sees the issued PEM
// bundle. Nothing this package writes back — a log line, an error, a persisted file — carries
// the token.
package agentclient

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// ErrNoCredential reports that the store holds no client credential yet — the data plane has not
// enrolled (or its credential was cleared) and must bootstrap with a fresh token.
var ErrNoCredential = errors.New("agentclient: no stored client credential")

// CertStore is the durable home for the control-plane-issued client credential (the PEM bundle:
// leaf, chain, private key). It stores ONLY the credential — never the enrolment token
// (SPEC-0038 AC2). Swapping a file-backed store for a KMS-backed one is a composition change.
type CertStore interface {
	// Save durably records the credential bundle, replacing any previous one.
	Save(ctx context.Context, pem []byte) error
	// Load returns the stored bundle, or ErrNoCredential when there is none.
	Load(ctx context.Context) ([]byte, error)
	// Clear removes the stored credential (re-enrolment path, ADR-0060 §4).
	Clear(ctx context.Context) error
}

// MemoryCertStore is an in-process CertStore for tests and ephemeral compositions.
type MemoryCertStore struct {
	mu  sync.Mutex
	pem []byte
}

var _ CertStore = (*MemoryCertStore)(nil)

func (m *MemoryCertStore) Save(_ context.Context, pem []byte) error {
	if len(pem) == 0 {
		return errors.New("agentclient: refusing to store an empty credential")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pem = append([]byte(nil), pem...)
	return nil
}

func (m *MemoryCertStore) Load(_ context.Context) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.pem) == 0 {
		return nil, ErrNoCredential
	}
	return append([]byte(nil), m.pem...), nil
}

func (m *MemoryCertStore) Clear(_ context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pem = nil
	return nil
}

// FileCertStore persists the credential to a single file with owner-only permissions. It is the
// default for a data plane whose cluster gives the agent a writable volume. The file holds only
// the issued credential bundle; the enrolment token is never written here.
type FileCertStore struct {
	path string
}

var _ CertStore = (*FileCertStore)(nil)

// NewFileCertStore wires a store rooted at path. The parent directory is created on first Save.
// path is operator-supplied configuration (a mount point), never request-derived; it is cleaned
// for hygiene.
func NewFileCertStore(path string) *FileCertStore { return &FileCertStore{path: filepath.Clean(path)} }

func (f *FileCertStore) Save(_ context.Context, pem []byte) error {
	if len(pem) == 0 {
		return errors.New("agentclient: refusing to store an empty credential")
	}
	if err := os.MkdirAll(filepath.Dir(f.path), 0o700); err != nil {
		return fmt.Errorf("agentclient: prepare credential dir: %w", err)
	}
	if err := os.WriteFile(f.path, pem, 0o600); err != nil {
		return fmt.Errorf("agentclient: write credential: %w", err)
	}
	return nil
}

func (f *FileCertStore) Load(_ context.Context) ([]byte, error) {
	pem, err := os.ReadFile(f.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoCredential
	}
	if err != nil {
		return nil, fmt.Errorf("agentclient: read credential: %w", err)
	}
	if len(pem) == 0 {
		return nil, ErrNoCredential
	}
	return pem, nil
}

func (f *FileCertStore) Clear(_ context.Context) error {
	err := os.Remove(f.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
