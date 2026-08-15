package custody

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
)

// FakeSigner is the CI custody service: a Signer over in-memory ECDSA P-256
// keys with the SAME surface the production provider exposes — references in,
// public halves and signatures out, and no method that returns private
// material (SPEC-0044 Test plan: the custody interface exercised against a
// fake provider in CI, never the production one).
//
// It holds private keys in process memory because it IS the fake custody
// boundary; what it shares with the production posture is the surface —
// nothing in this package, or through this type, ever hands that material
// out. It is test custody in exactly the sense pki.DevCA is: the production
// composition root must never reach it.
//
// A FakeSigner survives a simulated control-plane restart: the control plane
// comes back and re-attaches by reference; the custody service kept the keys.
// Seal and Unseal simulate the availability half of ADR-0066 decision 6.
type FakeSigner struct {
	mu     sync.Mutex
	keys   map[string]*ecdsa.PrivateKey
	sealed bool

	// call accounting: tests assert WHICH seam operations the issuance path
	// performed — references and digests in, signatures out, and nothing else.
	generates  int
	publics    int
	signs      int
	lastDigest int // length of the last digest presented for signing
}

var _ Signer = (*FakeSigner)(nil)

// NewFakeSigner returns an empty, unsealed CI custody service.
func NewFakeSigner() *FakeSigner {
	return &FakeSigner{keys: make(map[string]*ecdsa.PrivateKey)}
}

// GenerateKey creates one ECDSA P-256 key and returns only its reference.
func (f *FakeSigner) GenerateKey(_ context.Context, name string) (KeyRef, error) {
	if name == "" {
		return "", errors.New("custody: fake: empty key name")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sealed {
		return "", fmt.Errorf("custody: fake: sealed: %w", ErrUnavailable)
	}
	if _, exists := f.keys[name]; exists {
		return "", fmt.Errorf("custody: fake: %q: %w", name, ErrKeyExists)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", fmt.Errorf("custody: fake: generate: %w", err)
	}
	f.keys[name] = key
	f.generates++
	return KeyRef(name), nil
}

// PublicKey returns the public half of the referenced key — never more.
func (f *FakeSigner) PublicKey(_ context.Context, ref KeyRef) (*ecdsa.PublicKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sealed {
		return nil, fmt.Errorf("custody: fake: sealed: %w", ErrUnavailable)
	}
	key, ok := f.keys[string(ref)]
	if !ok {
		return nil, fmt.Errorf("custody: fake: %q: %w", ref, ErrNoKey)
	}
	f.publics++
	// A copy of the public point only: the private half stays inside this
	// type's unexported state, structurally unaddressable from outside.
	pub := *key.Public().(*ecdsa.PublicKey)
	return &pub, nil
}

// SignDigest signs one SHA-256 digest with the referenced key.
func (f *FakeSigner) SignDigest(_ context.Context, ref KeyRef, digest []byte) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sealed {
		return nil, fmt.Errorf("custody: fake: sealed: %w", ErrUnavailable)
	}
	key, ok := f.keys[string(ref)]
	if !ok {
		return nil, fmt.Errorf("custody: fake: %q: %w", ref, ErrNoKey)
	}
	if len(digest) != 32 {
		return nil, fmt.Errorf("custody: fake: digest is %d bytes, not a SHA-256 digest", len(digest))
	}
	f.signs++
	f.lastDigest = len(digest)
	return ecdsa.SignASN1(rand.Reader, key, digest)
}

// Seal simulates a custody outage: every seam call refuses until Unseal.
// This is the SPEC-0044 custody-unavailable shape — issuance stops, nothing
// already signed is touched.
func (f *FakeSigner) Seal() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sealed = true
}

// Unseal ends a simulated custody outage.
func (f *FakeSigner) Unseal() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sealed = false
}

// Sealed reports whether the fake is currently refusing.
func (f *FakeSigner) Sealed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sealed
}

// Counts reports how many times each seam operation ran — the assertion
// surface for references-not-material proofs: an issuance path that reads
// only references generates once per root, reads publics, and signs digests,
// and a verification path calls the seam NEVER.
func (f *FakeSigner) Counts() (generates, publics, signs int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.generates, f.publics, f.signs
}

// LastDigestLength is the byte length of the most recent digest presented to
// SignDigest: proof the seam saw a digest, never a whole credential or key.
func (f *FakeSigner) LastDigestLength() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastDigest
}

// HasKey reports whether the fake holds a key by this name — the test-side
// stand-in for asking the custody service whether a reference resolves. It
// names the key; it never exposes it.
func (f *FakeSigner) HasKey(ref KeyRef) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.keys[string(ref)]
	return ok
}
