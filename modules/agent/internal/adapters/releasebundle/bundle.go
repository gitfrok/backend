// Package releasebundle is the staged RELEASE trust bundle (T-0041, SPEC-0045
// AC2, ADR-0044/ADR-0065): the cosign release-signing keys the data planes
// verify SignedRelease references against, staged for distribution over the
// reconcile channel as DesiredState.release_trust_bundle.
//
// It is a DIFFERENT artifact from the custody package's CA trust bundle
// (SPEC-0044, ADR-0064) — different owner, different rotation reasons,
// different wire field and type (SPEC-0045's two-bundles note). The shapes
// deliberately do not line up either: the CA bundle stages custody KEY
// REFERENCES and self-signs certificates through them; the release bundle
// stages PUBLIC KEYS the publishing CI hands over — the matching private key
// never enters the control plane, and a private key presented for staging is
// refused, exactly as the data plane's verifier refuses one (ADR-0044).
package releasebundle

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/gitfrok/backend/modules/agent/api"
)

// Key is one release-signing key in the staged bundle: its ID and the PUBLIC
// key as PEM in the cosign key form of ADR-0044. The private half lives only
// in the publishing CI's protected environment.
type Key struct {
	ID           string
	PublicKeyPEM []byte
	StagedAt     time.Time
	RemovedAt    time.Time // zero while the key is live in the bundle
}

// ErrKeyStillNeeded refuses a removal that would leave the bundle unable to
// validate any signature the fleet currently holds — the last live key never
// leaves, and the SIGNING key leaves only via a Stage that moves signing to
// its successor first (ADR-0044's two-key overlap, applied as removal
// preconditions).
var ErrKeyStillNeeded = errors.New("releasebundle: key still needed by signed releases")

// ErrNoKeys reports a bundle with no live key — nothing to sign or trust.
var ErrNoKeys = errors.New("releasebundle: bundle holds no live key")

// Bundle is the staged release trust bundle with the dual-validate rotation
// window (SPEC-0045 AC2, ADR-0044 decision 2). It owns the ordered set of
// keys, the monotonic bundle REVISION, and the window operations:
//
//   - Stage brings a NEW public key in beside the current one and moves
//     signing to it; from that instant signatures by BOTH keys validate and
//     new releases sign with the new one.
//   - RemoveKey retires an old key once signing has moved past it; a
//     premature removal is refused, never performed.
//   - Snapshot/Restore carry the window state across a control-plane
//     restart: a mid-window restart changes nothing for the fleet.
//
// The revision advances with every staging step — Stage, removal — so the
// reconcile path detects staging progress and distributes the newest state
// (agent/v1 ReleaseTrustBundle.revision, SPEC-0045 AC2).
//
// Bundle is safe for concurrent use.
type Bundle struct {
	now func() time.Time

	mu           sync.Mutex
	keys         []Key  // oldest first
	signingKeyID string // the key new releases sign with
	// revision is the bundle's durable epoch; stagingRev is the DISTRIBUTED
	// epoch the reconcile channel publishes. Here every operation is a
	// staging step, so they move together — the split the CA bundle needs
	// for its issuance ledger has no analogue: release signatures are not
	// issued by this process.
	revision   int64
	stagingRev int64
	// onChange, when set, receives a snapshot after every staging step —
	// the seam the composition root persists the durable state through. It
	// fires OUTSIDE mu (see notifyChange); notifyMu serializes the firings
	// themselves, so concurrent steps hand the store snapshots in one order.
	notifyMu sync.Mutex
	onChange func(Snapshot)
}

// NewBundle returns an empty bundle reading the clock from now. Bootstrap or
// Restore gives it keys.
func NewBundle(now func() time.Time) (*Bundle, error) {
	if now == nil {
		return nil, errors.New("releasebundle: nil clock")
	}
	return &Bundle{now: now}, nil
}

// Bootstrap stages the FIRST key of a fresh bundle and points signing at it.
// A bundle bootstraps exactly once in its life; afterwards rotation is
// Stage. The PEM must be a public key in the cosign key form — a private key
// is refused (ADR-0044 custody posture). The empty-check and the stage are
// ONE atomic step under the bundle lock: two concurrent bootstraps can never
// both pass the check and both stage.
func (b *Bundle) Bootstrap(keyID string, publicKeyPEM []byte) error {
	if keyID == "" {
		return errors.New("releasebundle: key ID is required")
	}
	if _, err := parsePublicKey(publicKeyPEM); err != nil {
		return fmt.Errorf("releasebundle: bootstrap %q: %w", keyID, err)
	}
	b.mu.Lock()
	if len(b.liveKeysLocked()) > 0 {
		b.mu.Unlock()
		return fmt.Errorf("releasebundle: bundle already bootstrapped; rotate with Stage")
	}
	b.stageLocked(keyID, publicKeyPEM)
	b.mu.Unlock()
	b.notifyChange()
	return nil
}

// Stage brings one NEW release-signing public key into the bundle beside the
// current one AND moves signing to it: the dual-validate window opens —
// signatures by both keys validate, new releases sign with the new one
// (ADR-0044 decision 2). Staging advances the bundle revision. A key ID that
// is LIVE is refused without changing state; an ID whose every occurrence is
// RETIRED may be staged again — a re-declaration of a retired key (the
// reconcile seam's convergence must never wedge on a name the bundle once
// knew). An unparseable / private PEM is refused without changing state.
func (b *Bundle) Stage(keyID string, publicKeyPEM []byte) error {
	if keyID == "" {
		return errors.New("releasebundle: key ID is required")
	}
	if _, err := parsePublicKey(publicKeyPEM); err != nil {
		return fmt.Errorf("releasebundle: stage %q: %w", keyID, err)
	}
	b.mu.Lock()
	for _, k := range b.keys {
		if k.ID == keyID && k.RemovedAt.IsZero() {
			b.mu.Unlock()
			return fmt.Errorf("releasebundle: key %q is already live in the bundle", keyID)
		}
	}
	b.stageLocked(keyID, publicKeyPEM)
	b.mu.Unlock()
	b.notifyChange()
	return nil
}

// stageLocked performs one staging mutation: append the key, move signing to
// it, advance both revisions. The caller holds mu and fires the change hook
// after releasing it.
func (b *Bundle) stageLocked(keyID string, publicKeyPEM []byte) {
	pemCopy := make([]byte, len(publicKeyPEM))
	copy(pemCopy, publicKeyPEM)
	b.keys = append(b.keys, Key{ID: keyID, PublicKeyPEM: pemCopy, StagedAt: b.now()})
	b.signingKeyID = keyID
	b.revision++
	b.stagingRev++
}

// RemoveKey retires key ID from the trust bundle — and REFUSES while the key
// is still needed: the last live key never leaves, and the current SIGNING
// key leaves only via a Stage that moves signing to its successor (the
// removal precondition SPEC-0045 inherits from ADR-0044's two-key overlap).
// A refused removal changes nothing: signatures by the key keep validating.
func (b *Bundle) RemoveKey(keyID string) error {
	b.mu.Lock()
	live := b.liveKeysLocked()
	idx := -1
	for i, k := range live {
		if k.ID == keyID {
			idx = i
			break
		}
	}
	if idx < 0 {
		b.mu.Unlock()
		return fmt.Errorf("releasebundle: key %q is not live in the bundle: %w", keyID, ErrNoKeys)
	}
	if len(live) == 1 {
		b.mu.Unlock()
		return fmt.Errorf("releasebundle: refusing to remove the ONLY live key %q: %w", keyID, ErrKeyStillNeeded)
	}
	if b.signingKeyID == keyID {
		b.mu.Unlock()
		return fmt.Errorf("releasebundle: refusing to remove the SIGNING key %q before a successor is staged: %w", keyID, ErrKeyStillNeeded)
	}
	for i := range b.keys {
		if b.keys[i].ID == keyID {
			b.keys[i].RemovedAt = b.now()
		}
	}
	b.revision++
	b.stagingRev++
	b.mu.Unlock()
	b.notifyChange()
	return nil
}

// SigningKeyID is the key NEW releases sign with: during the overlap the
// staged key, whose signatures validate alongside the old one's.
func (b *Bundle) SigningKeyID() (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.liveKeysLocked()) == 0 {
		return "", ErrNoKeys
	}
	return b.signingKeyID, nil
}

// Keys returns a snapshot of every key the bundle knows, live or removed,
// oldest first — the operator-visible rotation state.
func (b *Bundle) Keys() []Key {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]Key, len(b.keys))
	copy(out, b.keys)
	return out
}

// Revision is the bundle's durable epoch; Snapshot/Restore carries it.
func (b *Bundle) Revision() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.revision
}

// StagingRevision is the distributed epoch the reconcile channel publishes
// as the release trust bundle's revision (agent/v1 ReleaseTrustBundle.
// revision).
func (b *Bundle) StagingRevision() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.stagingRev
}

// SetChangeHook installs the callback that receives a snapshot after every
// staging step (stage, removal) — the seam the composition root persists the
// bundle's durable state through. The hook fires outside the bundle lock.
func (b *Bundle) SetChangeHook(hook func(Snapshot)) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.onChange = hook
}

// LatestReleaseTrustBundle projects the bundle's CURRENT staged state onto
// the api shape the reconcile channel distributes (agent/v1 DesiredState's
// release_trust_bundle, SPEC-0045 AC2): revision, every LIVE key
// oldest-first as PEM, and the key new releases sign with. ok is false when
// the bundle holds no live key — nothing to distribute. This RELEASE trust
// bundle is a DIFFERENT artifact from SPEC-0044's CA trust bundle; the
// naming and the type keep them apart.
func (b *Bundle) LatestReleaseTrustBundle(_ context.Context) (api.ReleaseTrustBundleState, bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	live := b.liveKeysLocked()
	if len(live) == 0 {
		return api.ReleaseTrustBundleState{}, false, nil
	}
	st := api.ReleaseTrustBundleState{
		Revision:     b.stagingRev,
		Keys:         make([]api.ReleaseTrustKey, 0, len(live)),
		SigningKeyID: b.signingKeyID,
	}
	for _, k := range live {
		pemCopy := make([]byte, len(k.PublicKeyPEM))
		copy(pemCopy, k.PublicKeyPEM)
		st.Keys = append(st.Keys, api.ReleaseTrustKey{ID: k.ID, PublicKeyPEM: pemCopy})
	}
	return st, true, nil
}

func (b *Bundle) liveKeysLocked() []Key {
	var out []Key
	for _, k := range b.keys {
		if k.RemovedAt.IsZero() {
			out = append(out, k)
		}
	}
	return out
}

// notifyChange fires the change hook with the current snapshot OUTSIDE the
// bundle lock — the contract SetChangeHook states. A staging step commits
// under mu and hands the hook a copied snapshot here, so a hook that blocks
// (the composition's persistence does) can never wedge a staging operation,
// and notifyMu serializes the firings so concurrent steps reach the store in
// one order.
func (b *Bundle) notifyChange() {
	b.notifyMu.Lock()
	defer b.notifyMu.Unlock()
	b.mu.Lock()
	hook := b.onChange
	var snap Snapshot
	if hook != nil {
		snap = b.snapshotLocked()
	}
	b.mu.Unlock()
	if hook != nil {
		hook(snap)
	}
}

// snapshotLocked copies the bundle's durable state. The caller holds mu.
func (b *Bundle) snapshotLocked() Snapshot {
	snap := Snapshot{
		Revision:        b.revision,
		StagingRevision: b.stagingRev,
		SigningKeyID:    b.signingKeyID,
		Keys:            make([]SnapshotKey, 0, len(b.keys)),
	}
	for _, k := range b.keys {
		pemCopy := make([]byte, len(k.PublicKeyPEM))
		copy(pemCopy, k.PublicKeyPEM)
		snap.Keys = append(snap.Keys, SnapshotKey{ID: k.ID, PublicKeyPEM: pemCopy, StagedAt: k.StagedAt, RemovedAt: k.RemovedAt})
	}
	return snap
}

// Snapshot is the bundle's durable state: keys (IDs, public PEM, window
// timestamps), the signing key and both revisions. It carries NO private
// material — there is none in this process to carry. Restore rebuilds a
// bundle from one; a mid-window restart re-publishes exactly the revision
// the fleet last saw.
type Snapshot struct {
	Revision        int64
	StagingRevision int64
	SigningKeyID    string
	Keys            []SnapshotKey
}

// SnapshotKey is one key as durable state.
type SnapshotKey struct {
	ID           string
	PublicKeyPEM []byte
	StagedAt     time.Time
	RemovedAt    time.Time
}

// Snapshot captures the current bundle state.
func (b *Bundle) Snapshot() Snapshot {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.snapshotLocked()
}

// Restore rebuilds the bundle's state from a snapshot, re-validating every
// key's PEM.
func (b *Bundle) Restore(snap Snapshot) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	keys := make([]Key, 0, len(snap.Keys))
	for _, sk := range snap.Keys {
		if _, err := parsePublicKey(sk.PublicKeyPEM); err != nil {
			return fmt.Errorf("releasebundle: restore key %q: %w", sk.ID, err)
		}
		pemCopy := make([]byte, len(sk.PublicKeyPEM))
		copy(pemCopy, sk.PublicKeyPEM)
		keys = append(keys, Key{ID: sk.ID, PublicKeyPEM: pemCopy, StagedAt: sk.StagedAt, RemovedAt: sk.RemovedAt})
	}
	b.keys, b.signingKeyID, b.revision, b.stagingRev = keys, snap.SigningKeyID, snap.Revision, snap.StagingRevision
	return nil
}

// parsePublicKey accepts one PEM block carrying the PKIX (SUBJECT PUBLIC KEY
// INFO) encoding cosign publishes a verification key in, and returns the
// ECDSA public half. A private key is detected and refused explicitly — a
// private key in the trust bundle is a custody failure, not a verification
// key — the same posture the data plane's verifier takes (ADR-0044).
func parsePublicKey(pemBytes []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	if pub, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		ec, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("public key is %T, want ECDSA", pub)
		}
		return ec, nil
	}
	if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return nil, errors.New("bundle carries a private key; only public keys belong here")
	}
	if _, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return nil, errors.New("bundle carries a private key; only public keys belong here")
	}
	return nil, errors.New("public key is not a parseable PKIX ECDSA key")
}
