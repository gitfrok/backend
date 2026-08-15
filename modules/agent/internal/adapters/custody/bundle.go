package custody

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"
)

// caValidity bounds a staged CA root's own certificate. It is deliberately
// far beyond any leaf lifetime (api.Config.CertLifetime is short-lived): a
// leaf's chain must never break because its ROOT expired mid-life. Rotation
// cadence and overlap length are per-environment configuration owned by the
// operator and the composition root (SPEC-0044 non-functional), not compiled
// into this adapter.
const caValidity = 10 * 365 * 24 * time.Hour

// Root is one CA root in the staged trust bundle: a custody key reference
// and the self-signed CA certificate built on its public half. The root
// holds the REFERENCE — the private key never enters this process
// (ADR-0064 decision 2).
type Root struct {
	Ref       KeyRef
	Cert      *x509.Certificate
	StagedAt  time.Time
	RemovedAt time.Time // zero while the root is live in the bundle
}

// issuedRecord is the ledger entry one issued certificate leaves behind:
// WHICH root signed it and WHEN it expires. This is the removal-precondition
// data AC2 names — the old root leaves only after every certificate it
// issued predates its removal. In production the registry is the durable
// source of these facts; the composition-swap wave wires it in (the ledger
// here is in-process, like the bundle itself, until reconcile distribution
// lands — see the package comment).
type issuedRecord struct {
	CertificateID string
	RootRef       KeyRef
	ExpiresAt     time.Time
}

// Bundle is the staged CA trust bundle with the dual-validate rotation
// window (SPEC-0044 AC2, ADR-0064 decision 4). It owns the ordered set of
// roots — each a key REFERENCE plus its CA certificate — the issuance
// ledger, and the three window operations:
//
//   - Stage brings a NEW custody key in beside the current root; from that
//     instant both roots validate and new issuance chains to the new one.
//   - RemoveRoot retires the old root, but ONLY after every certificate it
//     signed has expired — premature removal is refused, never performed.
//   - Snapshot/Restore carry the window state across a control-plane
//     restart: a mid-window restart changes nothing for the fleet — no
//     re-enrolment, ADR-0060 unchanged.
//
// Bundle is safe for concurrent use.
type Bundle struct {
	signer Signer
	now    func() time.Time

	mu     sync.Mutex
	roots  []Root         // oldest first; the LAST live root is the issuance root
	issued []issuedRecord // every certificate this control plane issued through the bundle
	// inflight counts RESERVED-but-uncommitted issuances per root: between
	// ReserveIssuance and CompleteIssuance/AbortIssuance the root cannot be
	// removed, so an in-flight signature can never be orphaned under a root
	// the ledger already let go (the RemoveRoot race the reservation closes).
	inflight map[KeyRef]int
}

// ErrRootStillNeeded refuses an old root's removal while at least one live
// certificate still chains to it (SPEC-0044 AC2 removal precondition).
var ErrRootStillNeeded = errors.New("custody: root still needed by live certificates")

// ErrNoRoots reports a bundle with no live root — nothing to sign or trust.
var ErrNoRoots = errors.New("custody: bundle holds no live root")

// NewBundle returns an empty bundle signing through signer and reading the
// clock from now. Bootstrap or Restore gives it roots.
func NewBundle(signer Signer, now func() time.Time) (*Bundle, error) {
	if signer == nil {
		return nil, errors.New("custody: nil signer")
	}
	if now == nil {
		return nil, errors.New("custody: nil clock")
	}
	return &Bundle{signer: signer, now: now}, nil
}

// Bootstrap stages the FIRST root of a fresh bundle under key name. A bundle
// bootstraps exactly once in its life; afterwards rotation is Stage.
func (b *Bundle) Bootstrap(ctx context.Context, name string) (KeyRef, error) {
	b.mu.Lock()
	live := b.liveRootsLocked()
	b.mu.Unlock()
	if len(live) > 0 {
		return "", fmt.Errorf("custody: bundle already bootstrapped; rotate with Stage")
	}
	return b.Stage(ctx, name)
}

// Stage brings one NEW custody key into the bundle beside the current root:
// the custody service generates it, the control plane self-signs the root
// certificate THROUGH it, and the dual-validate window opens — both roots
// validate, new issuance chains to the new one (ADR-0064 decision 4).
func (b *Bundle) Stage(ctx context.Context, name string) (KeyRef, error) {
	root, err := b.buildRoot(ctx, name)
	if err != nil {
		return "", err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.roots = append(b.roots, root)
	return root.Ref, nil
}

// buildRoot generates one custody key and self-signs its CA certificate:
// the TBS is hashed in-process and only the DIGEST crosses the seam; the
// signature comes back; the private key never does.
func (b *Bundle) buildRoot(ctx context.Context, name string) (Root, error) {
	ref, err := b.signer.GenerateKey(ctx, name)
	if err != nil {
		return Root{}, fmt.Errorf("custody: stage %q: %w", name, err)
	}
	pub, err := b.signer.PublicKey(ctx, ref)
	if err != nil {
		return Root{}, fmt.Errorf("custody: stage %q: read public half: %w", name, err)
	}
	now := b.now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now.Add(-time.Hour), // clock-skew leeway, as the dev CA does
		NotAfter:              now.Add(caValidity),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	signer := &custodyKey{signer: b.signer, ref: ref, pub: pub}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, signer)
	if err != nil {
		return Root{}, fmt.Errorf("custody: stage %q: self-sign ca: %w", name, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return Root{}, fmt.Errorf("custody: stage %q: parse ca: %w", name, err)
	}
	return Root{Ref: ref, Cert: cert, StagedAt: now}, nil
}

// IssuanceRoot is the root NEW certificates chain to: the newest live root.
// During the overlap this is the staged key — old certificates keep
// validating against the old root, new ones chain to the new one (AC2).
func (b *Bundle) IssuanceRoot() (KeyRef, *x509.Certificate, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	live := b.liveRootsLocked()
	if len(live) == 0 {
		return "", nil, ErrNoRoots
	}
	newest := live[len(live)-1]
	return newest.Ref, newest.Cert, nil
}

// ReserveIssuance selects the issuance root AND pins it: until the matching
// CompleteIssuance or AbortIssuance, RemoveRoot refuses this root. This is
// the critical section the Issuer's root-selection + sign + record sequence
// runs under — without it, a removal that observes an EMPTY ledger could
// retire a root while a signature for it is still crossing the seam, and the
// completed certificate would chain to a root the bundle no longer trusts.
func (b *Bundle) ReserveIssuance() (KeyRef, *x509.Certificate, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	live := b.liveRootsLocked()
	if len(live) == 0 {
		return "", nil, ErrNoRoots
	}
	newest := live[len(live)-1]
	if b.inflight == nil {
		b.inflight = make(map[KeyRef]int)
	}
	b.inflight[newest.Ref]++
	return newest.Ref, newest.Cert, nil
}

// AbortIssuance releases one reservation without recording an issuance —
// the shape every failed Issue leaves behind, so a failed signature does not
// hold a root hostage.
func (b *Bundle) AbortIssuance(ref KeyRef) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.inflight[ref] > 0 {
		b.inflight[ref]--
	}
}

// CompleteIssuance records one issued certificate into the ledger under the
// reserved root and releases the reservation in the SAME critical section —
// the ledger check a concurrent RemoveRoot runs never observes the gap
// between "reserved" and "recorded".
func (b *Bundle) CompleteIssuance(certificateID string, ref KeyRef, expiresAt time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.issued = append(b.issued, issuedRecord{CertificateID: certificateID, RootRef: ref, ExpiresAt: expiresAt})
	if b.inflight[ref] > 0 {
		b.inflight[ref]--
	}
}

// Pool returns a trust pool holding every LIVE root — the verifier side of
// the dual-validate window. During the overlap it contains old and new
// alike; after a removal it contains only what survived it.
func (b *Bundle) Pool() (*x509.CertPool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	live := b.liveRootsLocked()
	if len(live) == 0 {
		return nil, ErrNoRoots
	}
	pool := x509.NewCertPool()
	for _, r := range live {
		pool.AddCert(r.Cert)
	}
	return pool, nil
}

// Roots returns a snapshot of every root the bundle knows, live or removed,
// oldest first — the operator-visible rotation state.
func (b *Bundle) Roots() []Root {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]Root, len(b.roots))
	copy(out, b.roots)
	return out
}

// RecordIssuance enters one issued certificate into the ledger under the
// root that signed it, without touching the reservation count — it is the
// restore/test-side primitive; the live Issuer path records through
// CompleteIssuance so the ledger entry and the reservation release stay one
// critical section. The removal precondition reads from here.
func (b *Bundle) RecordIssuance(certificateID string, root KeyRef, expiresAt time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.issued = append(b.issued, issuedRecord{CertificateID: certificateID, RootRef: root, ExpiresAt: expiresAt})
}

// RemoveRoot retires root ref from the trust bundle — and REFUSES while any
// certificate it signed is still live at the bundle's clock (AC2: the old
// trust root is removed only after every issued certificate predates its
// removal). A refused removal changes nothing: the root keeps validating.
func (b *Bundle) RemoveRoot(ref KeyRef) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	live := b.liveRootsLocked()
	idx := -1
	for i, r := range live {
		if r.Ref == ref {
			idx = i
			break
		}
	}
	if idx < 0 {
		return fmt.Errorf("custody: root %q is not live in the bundle: %w", ref, ErrNoKey)
	}
	if len(live) == 1 {
		return fmt.Errorf("custody: refusing to remove the ONLY live root %q: %w", ref, ErrRootStillNeeded)
	}
	if b.inflight[ref] > 0 {
		// A signature for this root is crossing the seam right now: its
		// ledger entry does not exist yet, but the certificate will. The
		// reservation makes the in-flight issuance visible to the removal
		// precondition.
		return fmt.Errorf("custody: an issuance under root %q is in flight: %w", ref, ErrRootStillNeeded)
	}
	liveCount := 0
	for _, rec := range b.issued {
		if rec.RootRef == ref && rec.ExpiresAt.After(now) {
			liveCount++
		}
	}
	if liveCount > 0 {
		return fmt.Errorf("custody: %d live certificate(s) still chain to root %q: %w", liveCount, ref, ErrRootStillNeeded)
	}
	for i := range b.roots {
		if b.roots[i].Ref == ref {
			b.roots[i].RemovedAt = now
		}
	}
	return nil
}

func (b *Bundle) liveRootsLocked() []Root {
	var out []Root
	for _, r := range b.roots {
		if r.RemovedAt.IsZero() {
			out = append(out, r)
		}
	}
	return out
}

// Snapshot is the bundle's durable state: roots (references, certificates,
// window timestamps) and the issuance ledger. It carries NO private
// material — there is none in this process to carry. Restore rebuilds a
// bundle from one against the SAME custody service: the custody side
// survives a control-plane restart by design; this is the control-plane side
// of that story.
//
// DEFERRED: this is the shape the reconcile channel would distribute to the
// fleet's trust side once agent/v1 gains a bundle field (package comment).
type Snapshot struct {
	Roots []SnapshotRoot
	// Issued is the ledger. CertificateIDs and expiry only — a certificate's
	// PEM never enters bundle state (SPEC-0038 AC2 secrecy, restated).
	Issued []SnapshotIssued
}

// SnapshotRoot is one root as durable state: the reference, the CA
// certificate DER, and the window timestamps.
type SnapshotRoot struct {
	Ref       KeyRef
	CertDER   []byte
	StagedAt  time.Time
	RemovedAt time.Time
}

// SnapshotIssued is one ledger entry as durable state.
type SnapshotIssued struct {
	CertificateID string
	RootRef       KeyRef
	ExpiresAt     time.Time
}

// Snapshot captures the current bundle state.
func (b *Bundle) Snapshot() Snapshot {
	b.mu.Lock()
	defer b.mu.Unlock()
	snap := Snapshot{
		Roots:  make([]SnapshotRoot, 0, len(b.roots)),
		Issued: make([]SnapshotIssued, 0, len(b.issued)),
	}
	for _, r := range b.roots {
		certDER := make([]byte, len(r.Cert.Raw))
		copy(certDER, r.Cert.Raw)
		snap.Roots = append(snap.Roots, SnapshotRoot{Ref: r.Ref, CertDER: certDER, StagedAt: r.StagedAt, RemovedAt: r.RemovedAt})
	}
	for _, rec := range b.issued {
		snap.Issued = append(snap.Issued, SnapshotIssued{CertificateID: rec.CertificateID, RootRef: rec.RootRef, ExpiresAt: rec.ExpiresAt})
	}
	return snap
}

// Restore rebuilds the bundle's state from a snapshot, re-parsing the root
// certificates. The signer is NOT in the snapshot: keys live in the custody
// service, and a restored bundle re-attaches to them by reference alone.
func (b *Bundle) Restore(snap Snapshot) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	roots := make([]Root, 0, len(snap.Roots))
	for _, sr := range snap.Roots {
		cert, err := x509.ParseCertificate(sr.CertDER)
		if err != nil {
			return fmt.Errorf("custody: restore root %q: %w", sr.Ref, err)
		}
		roots = append(roots, Root{Ref: sr.Ref, Cert: cert, StagedAt: sr.StagedAt, RemovedAt: sr.RemovedAt})
	}
	issued := make([]issuedRecord, 0, len(snap.Issued))
	for _, si := range snap.Issued {
		issued = append(issued, issuedRecord{CertificateID: si.CertificateID, RootRef: si.RootRef, ExpiresAt: si.ExpiresAt})
	}
	b.roots, b.issued = roots, issued
	return nil
}
