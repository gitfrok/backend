package custody_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"github.com/gitfrok/backend/modules/agent/internal/adapters/custody"
)

// The reconcile-distribution tests prove SPEC-0044 AC2 over the WIRE SHAPE:
// what a data plane actually sees on DesiredState.ca_trust_bundle during
// stage, overlap and removal. The source is Bundle.LatestCATrustBundle —
// the api.CATrustBundleState projection the gateway maps onto the contract
// message (grpc.caTrustBundleWire). The in-memory window mechanics
// themselves are rotation_test.go's surface; these tests EXTEND them onto
// the distribution projection rather than duplicating them — both suites
// share stageOverlap and the same bundle mechanics.

// rootsOf parses the PEM roots one projection carries — the data plane's
// view of the bundle.
func rootsOf(t *testing.T, pems [][]byte) []*x509.Certificate {
	t.Helper()
	var out []*x509.Certificate
	for i, raw := range pems {
		block, _ := pem.Decode(raw)
		if block == nil || block.Type != "CERTIFICATE" {
			t.Fatalf("trusted root %d does not carry a CERTIFICATE PEM block", i)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("trusted root %d: %v", i, err)
		}
		out = append(out, cert)
	}
	return out
}

// TestDistributionProjectsStagedRootsDuringOverlap is AC2 over the reconcile
// shape: during the dual-validate window a data plane's desired state holds
// BOTH roots, the issuance root names the staged key, and the revision has
// advanced past the bootstrap epoch.
func TestDistributionProjectsStagedRootsDuringOverlap(t *testing.T) {
	_, bundle, issuer, clk, oldCert, newRef := stageOverlap(t)

	st, ok, err := bundle.LatestCATrustBundle(context.Background())
	if err != nil || !ok {
		t.Fatalf("LatestCATrustBundle = (_, %v, %v), want a projection", ok, err)
	}
	if len(st.Roots) != 2 {
		t.Fatalf("data plane sees %d trusted roots during the overlap, want 2", len(st.Roots))
	}
	if st.IssuanceRootID != string(newRef) {
		t.Errorf("issuance root = %q, want the staged root %q", st.IssuanceRootID, newRef)
	}
	if st.Revision < 2 {
		t.Errorf("revision = %d after bootstrap + stage, want >= 2", st.Revision)
	}

	// The old certificate's CA is one of the two projected roots — the
	// data plane holding this bundle keeps validating it.
	leaf := leafCertOf(t, oldCert.PEM)
	var pems [][]byte
	for _, r := range st.Roots {
		pems = append(pems, r.CertificatePEM)
	}
	var oldValidates, newPresent bool
	for i, root := range rootsOf(t, pems) {
		if leaf.CheckSignatureFrom(root) == nil {
			oldValidates = true
		}
		if st.Roots[i].ID == string(newRef) {
			newPresent = true
		}
	}
	if !oldValidates {
		t.Errorf("old-root certificate does not validate against the projected overlap bundle")
	}
	if !newPresent {
		t.Errorf("staged root %q missing from the projected bundle", newRef)
	}

	// A NEW issuance under the overlap chains to the staged root and
	// validates against the projection — the window the data plane sees.
	probe, err := issuer.Issue(context.Background(), testIdentity, clk.Now(), time.Hour, 0)
	if err != nil {
		t.Fatalf("Issue during overlap: %v", err)
	}
	probeLeaf := leafCertOf(t, probe.PEM)
	if probeLeaf.Issuer.CommonName != string(newRef) {
		t.Errorf("new issuance chains to %q, want the staged root %q", probeLeaf.Issuer.CommonName, newRef)
	}
	// Every projected root carries its own expiry — the wire field a data
	// plane judges a root by before it parses.
	for _, r := range st.Roots {
		if r.NotAfter.IsZero() {
			t.Errorf("projected root %q carries no expiry", r.ID)
		}
	}
}

// TestDistributionRemovalPreconditionKeepsOldRootVisible proves the removal
// precondition over the wire: while a live certificate depends on the old
// root, RemoveRoot refuses AND the projection still carries the old root;
// once every certificate predates the removal, the projection loses it and
// the revision advances again.
func TestDistributionRemovalPreconditionKeepsOldRootVisible(t *testing.T) {
	_, bundle, _, clk, _, newRef := stageOverlap(t)
	before, _, _ := bundle.LatestCATrustBundle(context.Background())

	// The old root's certificate (issued in stageOverlap) is live for 24h:
	// removal must refuse, and the wire must keep carrying the old root.
	oldRef := bundle.Roots()[0].Ref
	if err := bundle.RemoveRoot(oldRef); !errors.Is(err, custody.ErrRootStillNeeded) {
		t.Fatalf("RemoveRoot with a live certificate = %v, want ErrRootStillNeeded", err)
	}
	refused, _, _ := bundle.LatestCATrustBundle(context.Background())
	if len(refused.Roots) != 2 {
		t.Fatalf("refused removal left %d roots on the wire, want 2", len(refused.Roots))
	}
	if refused.Revision != before.Revision {
		t.Errorf("refused removal moved the revision %d -> %d", before.Revision, refused.Revision)
	}

	// Past the old certificate's expiry the precondition passes: the
	// projection drops the old root and the revision advances.
	clk.Advance(25 * time.Hour)
	if err := bundle.RemoveRoot(oldRef); err != nil {
		t.Fatalf("RemoveRoot after expiry: %v", err)
	}
	after, ok, err := bundle.LatestCATrustBundle(context.Background())
	if err != nil || !ok {
		t.Fatalf("LatestCATrustBundle after removal = (_, %v, %v)", ok, err)
	}
	if len(after.Roots) != 1 {
		t.Fatalf("post-removal wire carries %d roots, want 1", len(after.Roots))
	}
	if after.Roots[0].ID != string(newRef) {
		t.Errorf("post-removal wire carries %q, want %q", after.Roots[0].ID, newRef)
	}
	if after.Revision <= before.Revision {
		t.Errorf("removal did not advance the revision: %d <= %d", after.Revision, before.Revision)
	}
}

// TestDistributionMidWindowRestartRepublishesSameRevision covers the restart
// half of the reconcile story (extends rotation_test's mid-window restart):
// a control plane restored from its snapshot re-projects EXACTLY the
// revision and root set the fleet last saw — no replay, no skip.
func TestDistributionMidWindowRestartRepublishesSameRevision(t *testing.T) {
	fake, bundle, _, clk, _, newRef := stageOverlap(t)
	before, _, _ := bundle.LatestCATrustBundle(context.Background())

	// Restart: a fresh bundle against the SAME custody service, restored
	// from the durable snapshot — the control-plane half of the story.
	restarted, err := custody.NewBundle(fake, clk.Now)
	if err != nil {
		t.Fatalf("NewBundle on restart: %v", err)
	}
	if err := restarted.Restore(bundle.Snapshot()); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	after, ok, err := restarted.LatestCATrustBundle(context.Background())
	if err != nil || !ok {
		t.Fatalf("post-restart LatestCATrustBundle = (_, %v, %v)", ok, err)
	}
	if after.Revision != before.Revision {
		t.Errorf("restart changed the revision: %d -> %d", before.Revision, after.Revision)
	}
	if after.IssuanceRootID != string(newRef) {
		t.Errorf("restart changed the issuance root: %q -> %q", newRef, after.IssuanceRootID)
	}
	if len(after.Roots) != len(before.Roots) {
		t.Fatalf("restart changed the root count: %d -> %d", len(before.Roots), len(after.Roots))
	}
	for i := range after.Roots {
		if !bytes.Equal(after.Roots[i].CertificatePEM, before.Roots[i].CertificatePEM) {
			t.Errorf("restart changed root %d's PEM", i)
		}
	}
}

// TestDistributionEmptyBundleProjectsNothing: a bundle with no live root has
// nothing to distribute — the reconcile path must skip, never publish an
// empty trust set that would break every data plane's admission.
func TestDistributionEmptyBundleProjectsNothing(t *testing.T) {
	fake := custody.NewFakeSigner()
	clk := newClock()
	bundle, err := custody.NewBundle(fake, clk.Now)
	if err != nil {
		t.Fatalf("NewBundle: %v", err)
	}
	if _, ok, err := bundle.LatestCATrustBundle(context.Background()); err != nil || ok {
		t.Fatalf("empty bundle projected (%v, %v), want (false, nil)", ok, err)
	}
}

// leafCertOf decodes the leaf certificate from one issued PEM bundle.
func leafCertOf(t *testing.T, pemBundle []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(pemBundle)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("issued bundle does not begin with a CERTIFICATE block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return cert
}
