package custody_test

import (
	"context"
	"crypto/ecdsa"
	"encoding/pem"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/gitfrok/backend/modules/agent/api"
	"github.com/gitfrok/backend/modules/agent/internal/adapters/custody"
)

// The AC2 window tests exercise the in-memory staging abstraction
// custody.Bundle. Fleet distribution over the reconcile channel rides
// agent/v1 DesiredState.ca_trust_bundle (governance@779d022) and is proven
// at the reconcile level by the grpc adapter's
// TestAC2_CARotationDistributedOverReconcile; Snapshot/Restore is where the
// durable wiring attaches. Nothing below stands in for the distribution
// tests, and the CA bundle they rotate is named apart from SPEC-0045's
// release trust bundle (T-0040's two-bundles rule).

// stageOverlap opens the dual-validate window: one root bootstrapped, one
// certificate issued under it, one NEW root staged beside it.
func stageOverlap(t *testing.T) (*custody.FakeSigner, *custody.Bundle, *custody.Issuer, *clock, api.IssuedCertificate, custody.KeyRef) {
	t.Helper()
	fake, bundle, issuer, clk := newTestCA(t, "agent-ca-gen1")
	oldCert, _ := issueOne(t, issuer, clk, 24*time.Hour)
	newRef, err := bundle.Stage(context.Background(), "agent-ca-gen2")
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	return fake, bundle, issuer, clk, oldCert, newRef
}

// leafDEROf decodes the leaf certificate DER out of one issued bundle.
func leafDEROf(t *testing.T, cert api.IssuedCertificate) []byte {
	t.Helper()
	block, _ := pem.Decode(cert.PEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("issued bundle does not begin with a CERTIFICATE block")
	}
	return block.Bytes
}

// TestRotationStageOpensDualValidateWindow is AC2's first half: during the
// overlap, a certificate chained to the OLD root still validates while the
// NEW root sits in the trust pool beside it — no fleet re-enrolment.
func TestRotationStageOpensDualValidateWindow(t *testing.T) {
	_, bundle, issuer, clk, oldCert, newRef := stageOverlap(t)

	roots := bundle.Roots()
	if len(roots) != 2 {
		t.Fatalf("bundle holds %d roots during the overlap, want 2", len(roots))
	}
	ref, _, err := bundle.IssuanceRoot()
	if err != nil || ref != newRef {
		t.Fatalf("IssuanceRoot = (%q, %v), want the NEW root %q", ref, err, newRef)
	}

	// Old certificate, new window: still trusted.
	if _, validity, err := issuer.VerifyChain([][]byte{leafDEROf(t, oldCert)}, clk.Now()); err != nil || validity != api.ValidNow {
		t.Errorf("old-root certificate during overlap = (%v, %v), want (ValidNow, nil)", validity, err)
	}
	// The pool holds both live roots — the verifier half of dual validation.
	// A probe issuance chains to the staged key and must validate at once.
	probe, err := issuer.Issue(context.Background(), testIdentity, clk.Now(), time.Hour, 0)
	if err != nil {
		t.Fatalf("probe Issue during overlap: %v", err)
	}
	if _, validity, err := issuer.VerifyChain([][]byte{leafDEROf(t, probe)}, clk.Now()); err != nil || validity != api.ValidNow {
		t.Errorf("probe issuance against the overlap pool = (%v, %v), want (ValidNow, nil)", validity, err)
	}
}

// TestNewIssuanceChainsToNewKeyDuringOverlap is AC2's second half: once the
// window is open, every NEW certificate chains to the NEW key — while the
// old root keeps validating what it signed.
func TestNewIssuanceChainsToNewKeyDuringOverlap(t *testing.T) {
	_, bundle, issuer, clk, _, newRef := stageOverlap(t)

	_, newLeaf := issueOne(t, issuer, clk, 24*time.Hour)

	sawNew := false
	for _, r := range bundle.Roots() {
		switch {
		case r.Ref == newRef:
			sawNew = true
			if err := newLeaf.CheckSignatureFrom(r.Cert); err != nil {
				t.Errorf("new issuance does not chain to the NEW root: %v", err)
			}
		default:
			if newLeaf.CheckSignatureFrom(r.Cert) == nil {
				t.Error("new issuance chains to the OLD root — issuance must switch to the staged key")
			}
		}
	}
	if !sawNew {
		t.Fatal("staged root vanished from the bundle")
	}
}

// TestPrematureRemovalRefused is AC2's removal precondition, negative half:
// while one certificate still chains to the old root and lives, the old root
// REFUSES to leave — and the refusal changes nothing for that certificate.
func TestPrematureRemovalRefused(t *testing.T) {
	_, bundle, issuer, clk, oldCert, _ := stageOverlap(t)

	oldRef := bundle.Roots()[0].Ref
	err := bundle.RemoveRoot(oldRef)
	if !errors.Is(err, custody.ErrRootStillNeeded) {
		t.Fatalf("RemoveRoot while a live certificate chains to it = %v, want ErrRootStillNeeded", err)
	}

	// The refusal is a no-op for trust: the old certificate still validates.
	if _, validity, vErr := issuer.VerifyChain([][]byte{leafDEROf(t, oldCert)}, clk.Now()); vErr != nil || validity != api.ValidNow {
		t.Errorf("old certificate after a refused removal = (%v, %v), want (ValidNow, nil)", validity, vErr)
	}
	roots := bundle.Roots()
	live := 0
	for _, r := range roots {
		if r.RemovedAt.IsZero() {
			live++
		}
	}
	if live != 2 {
		t.Errorf("%d live roots after a refused removal, want 2", live)
	}
}

// TestRemovalOnlyAfterEveryCertificatePredatesIt is AC2's removal
// precondition, positive half: once every certificate the old root signed
// has expired, removal succeeds — and a still-LIVE certificate issued under
// the NEW root never holds the old root's removal hostage. After removal
// the old chain stops validating and the CA carries on under the new root:
// rotation completed, no re-enrolment.
func TestRemovalOnlyAfterEveryCertificatePredatesIt(t *testing.T) {
	_, bundle, issuer, clk, oldCert, _ := stageOverlap(t)
	// A long-lived certificate under the NEW root: still live when the old
	// root is removed — proof the precondition is per-root.
	if _, err := issuer.Issue(context.Background(), testIdentity, clk.Now(), 48*time.Hour, 0); err != nil {
		t.Fatalf("Issue under the new root: %v", err)
	}

	oldRef := bundle.Roots()[0].Ref

	// Age the clock past the old certificate's 24h lifetime.
	clk.Advance(25 * time.Hour)
	if err := bundle.RemoveRoot(oldRef); err != nil {
		t.Fatalf("RemoveRoot after every old-root certificate expired: %v", err)
	}

	// The old chain is now untrusted — an error, never a classification.
	if _, _, err := issuer.VerifyChain([][]byte{leafDEROf(t, oldCert)}, clk.Now()); err == nil {
		t.Error("old-root certificate still validates after its root's removal")
	}
	// A fresh issuance proves the CA carries on after removal.
	fresh, _ := issueOne(t, issuer, clk, time.Hour)
	if _, validity, err := issuer.VerifyChain([][]byte{leafDEROf(t, fresh)}, clk.Now()); err != nil || validity != api.ValidNow {
		t.Errorf("fresh issuance after removal = (%v, %v), want (ValidNow, nil)", validity, err)
	}

	live := 0
	for _, r := range bundle.Roots() {
		if r.RemovedAt.IsZero() {
			live++
		}
	}
	if live != 1 {
		t.Errorf("%d live roots after removal, want 1", live)
	}
}

// TestRemoveOnlyLiveRootRefused: a one-root bundle refuses removal of its
// only root even with no live certificates — a CA with nowhere to sign is
// not a rotation, it is an outage nobody asked for.
func TestRemoveOnlyLiveRootRefused(t *testing.T) {
	_, bundle, _, clk := newTestCA(t, "agent-ca-solo")
	clk.Advance(time.Hour)
	onlyRef := bundle.Roots()[0].Ref
	if err := bundle.RemoveRoot(onlyRef); !errors.Is(err, custody.ErrRootStillNeeded) {
		t.Errorf("RemoveRoot(the only root) = %v, want ErrRootStillNeeded", err)
	}
}

// TestMidWindowRestartPreservesTheWindow: a control-plane restart MID
// rotation changes nothing for the fleet. The restored bundle keeps both
// roots live, keeps dual-validating, keeps issuing under the new key, and
// keeps the removal precondition — the ledger survived the restart with the
// window (AC2: no fleet re-enrolment; ADR-0060 unchanged).
func TestMidWindowRestartPreservesTheWindow(t *testing.T) {
	fake, bundle, issuer, clk, oldCert, newRef := stageOverlap(t)
	_, _ = issueOne(t, issuer, clk, 24*time.Hour)
	snap := bundle.Snapshot()

	// The restart: a NEW bundle and issuer re-attach to the SAME custody
	// service — the fake, like the production provider, kept the keys.
	restored, err := custody.NewBundle(fake, clk.Now)
	if err != nil {
		t.Fatalf("NewBundle after restart: %v", err)
	}
	if err := restored.Restore(snap); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	restoredIssuer, err := custody.NewIssuer(restored)
	if err != nil {
		t.Fatalf("NewIssuer after restart: %v", err)
	}

	// Dual validation carries across the restart.
	if _, validity, err := restoredIssuer.VerifyChain([][]byte{leafDEROf(t, oldCert)}, clk.Now()); err != nil || validity != api.ValidNow {
		t.Errorf("pre-restart old-root certificate after restart = (%v, %v), want (ValidNow, nil)", validity, err)
	}

	// Issuance still chains to the staged key.
	ref, _, err := restored.IssuanceRoot()
	if err != nil || ref != newRef {
		t.Fatalf("post-restart IssuanceRoot = (%q, %v), want %q", ref, err, newRef)
	}
	_, newLeaf := issueOne(t, restoredIssuer, clk, time.Hour)
	for _, r := range restored.Roots() {
		if r.Ref == newRef && newLeaf.CheckSignatureFrom(r.Cert) != nil {
			t.Error("post-restart issuance does not chain to the staged key")
		}
	}

	// The removal precondition survived too: the pre-restart certificate is
	// still live, so the old root still refuses to leave.
	oldRef := restored.Roots()[0].Ref
	if err := restored.RemoveRoot(oldRef); !errors.Is(err, custody.ErrRootStillNeeded) {
		t.Errorf("post-restart RemoveRoot = %v, want ErrRootStillNeeded — the ledger must survive the restart", err)
	}
}

// TestRestoreRejectsUnparsableState guards the restore path: a corrupted
// root certificate in durable state is a loud refusal, never a bundle that
// silently lost a root.
func TestRestoreRejectsUnparsableState(t *testing.T) {
	_, bundle, _, _ := newTestCA(t, "agent-ca-corrupt")
	snap := bundle.Snapshot()
	snap.Roots[0].CertDER = []byte("not a certificate")

	fresh, err := custody.NewBundle(custody.NewFakeSigner(), newClock().Now)
	if err != nil {
		t.Fatalf("NewBundle: %v", err)
	}
	if err := fresh.Restore(snap); err == nil {
		t.Fatal("Restore accepted an unparsable root certificate")
	}
}

// gatedSigner is a custody seam whose SignDigest can be held at a gate: the
// race test parks one signature mid-flight while the window operations run
// beside it. Until armed it passes through, so bootstrap self-signs freely.
type gatedSigner struct {
	mu    sync.Mutex
	inner custody.Signer
	began chan struct{} // closed over once per call while armed
	gate  chan struct{} // the signature waits on this while armed
	fail  bool          // refuse after the gate opens
}

func (g *gatedSigner) GenerateKey(ctx context.Context, name string) (custody.KeyRef, error) {
	return g.inner.GenerateKey(ctx, name)
}

func (g *gatedSigner) PublicKey(ctx context.Context, ref custody.KeyRef) (*ecdsa.PublicKey, error) {
	return g.inner.PublicKey(ctx, ref)
}

func (g *gatedSigner) SignDigest(ctx context.Context, ref custody.KeyRef, digest []byte) ([]byte, error) {
	g.mu.Lock()
	began, gate, fail := g.began, g.gate, g.fail
	// One-shot: exactly ONE signature — the one the test parks — waits at
	// the gate; every later seam call (a Stage's self-sign) passes through.
	g.began, g.gate = nil, nil
	g.mu.Unlock()
	if began != nil {
		began <- struct{}{}
	}
	if gate != nil {
		<-gate
	}
	if fail {
		return nil, errors.New("gated signer: seam outage")
	}
	return g.inner.SignDigest(ctx, ref, digest)
}

func (g *gatedSigner) arm() (gate, began chan struct{}) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.began = make(chan struct{}, 1)
	g.gate = make(chan struct{})
	return g.gate, g.began
}

// TestIssuanceInFlightHoldsItsRoot is the RemoveRoot race the reservation
// closes: a signature for the OLD root is crossing the seam when the window
// says the root may go. The removal must be REFUSED while the issuance is in
// flight — its ledger entry does not exist yet, but the certificate will —
// and the completed certificate must land under a root the bundle still
// trusted at signature time.
func TestIssuanceInFlightHoldsItsRoot(t *testing.T) {
	fake := custody.NewFakeSigner()
	gs := &gatedSigner{inner: fake}
	clk := newClock()
	bundle, err := custody.NewBundle(gs, clk.Now)
	if err != nil {
		t.Fatalf("NewBundle: %v", err)
	}
	oldRef, err := bundle.Bootstrap(context.Background(), "agent-ca-race-a")
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	issuer, err := custody.NewIssuer(bundle)
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}

	// One issuance parks mid-flight at the seam, under the ONLY root.
	gate, began := gs.arm()
	done := make(chan error, 1)
	go func() {
		_, err := issuer.Issue(context.Background(), testIdentity, clk.Now(), time.Hour, time.Minute)
		done <- err
	}()
	<-began // the signature is crossing the seam; the reservation is held

	// The window opens and tries to retire the signing root in one motion.
	if _, err := bundle.Stage(context.Background(), "agent-ca-race-b"); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if err := bundle.RemoveRoot(oldRef); !errors.Is(err, custody.ErrRootStillNeeded) {
		t.Fatalf("RemoveRoot during in-flight issuance = %v, want ErrRootStillNeeded", err)
	}

	// The signature completes: the issuance lands, and the root stays held —
	// now by its ledger entry instead of its reservation.
	close(gate)
	if err := <-done; err != nil {
		t.Fatalf("in-flight Issue failed: %v", err)
	}
	if err := bundle.RemoveRoot(oldRef); !errors.Is(err, custody.ErrRootStillNeeded) {
		t.Fatalf("RemoveRoot after in-flight issuance = %v, want ErrRootStillNeeded (the ledger now)", err)
	}

	// Once the certificate predates the removal, the root leaves cleanly.
	clk.Advance(2 * time.Hour)
	if err := bundle.RemoveRoot(oldRef); err != nil {
		t.Fatalf("RemoveRoot after expiry = %v, want success", err)
	}
}

// TestFailedIssuanceReleasesItsReservation is the reservation's other half: a
// signature that FAILS at the seam must not hold its root hostage — the
// abort releases the reservation, and the removal is admitted immediately.
func TestFailedIssuanceReleasesItsReservation(t *testing.T) {
	fake := custody.NewFakeSigner()
	gs := &gatedSigner{inner: fake}
	clk := newClock()
	bundle, err := custody.NewBundle(gs, clk.Now)
	if err != nil {
		t.Fatalf("NewBundle: %v", err)
	}
	if _, err := bundle.Bootstrap(context.Background(), "agent-ca-abort-a"); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	newRef, err := bundle.Stage(context.Background(), "agent-ca-abort-b")
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	issuer, err := custody.NewIssuer(bundle)
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}

	gate, began := gs.arm()
	gs.mu.Lock()
	gs.fail = true
	gs.mu.Unlock()
	done := make(chan error, 1)
	go func() {
		_, err := issuer.Issue(context.Background(), testIdentity, clk.Now(), time.Hour, time.Minute)
		done <- err
	}()
	<-began
	// In flight: the NEWEST root (the issuance root) refuses removal.
	if err := bundle.RemoveRoot(newRef); !errors.Is(err, custody.ErrRootStillNeeded) {
		t.Fatalf("RemoveRoot during in-flight issuance = %v, want ErrRootStillNeeded", err)
	}

	// The seam fails: the issuance aborts and its reservation is released.
	close(gate)
	if err := <-done; err == nil {
		t.Fatal("Issue succeeded against a failing seam")
	}
	if err := bundle.RemoveRoot(newRef); err != nil {
		t.Fatalf("RemoveRoot after failed issuance = %v, want success — the reservation must be released", err)
	}
}
