package custody_test

import (
	"context"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"github.com/gitfrok/backend/modules/agent/api"
	"github.com/gitfrok/backend/modules/agent/internal/adapters/custody"
)

// The AC2 window tests exercise the in-memory staging abstraction
// custody.Bundle: on 2026-08-15 the agent/v1 DesiredState message carries no
// field capable of staging a CA trust bundle (verified against
// governance/contracts/proto/agent/v1/agent.proto), so distribution over the
// reconcile channel is DEFERRED behind an additive agent/v1 governance PR
// (SPEC-0044 Contracts touched). Snapshot/Restore is where that wiring
// attaches; nothing below stands in for fleet distribution.

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
