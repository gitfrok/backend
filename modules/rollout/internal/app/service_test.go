package app

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/gitfrok/backend/modules/rollout/api"
	"github.com/gitfrok/backend/modules/rollout/internal/adapters/memory"
	"github.com/gitfrok/backend/modules/rollout/internal/domain"
	"github.com/gitfrok/backend/platform/bus"
)

// --- test scaffolding ----------------------------------------------------------------------

type clock struct{ now time.Time }

func (c *clock) Now() time.Time          { return c.now }
func (c *clock) advance(d time.Duration) { c.now = c.now.Add(d) }

// newMemStore returns the in-process store the app tests run on.
func newMemStore() RolloutStore { return memory.New() }

func testKey(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	return priv, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
}

func signRelease(t *testing.T, priv *ecdsa.PrivateKey, rel api.SignedRelease) api.SignedRelease {
	t.Helper()
	hash := sha256.Sum256(rel.CanonicalIdentity())
	sig, err := ecdsa.SignASN1(rand.Reader, priv, hash[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	rel.Signature = sig
	return rel
}

func rel(version, digest string) api.SignedRelease {
	return api.SignedRelease{OCIRef: "registry.gitsaas.example/gitsaas/git-rpc", Digest: digest}
}

func mkRelease(t *testing.T, priv *ecdsa.PrivateKey, version, digest string) api.Release {
	t.Helper()
	return api.Release{Component: "git-rpc", Version: version, Signed: signRelease(t, priv, rel(version, digest))}
}

func newService(t *testing.T, pemBytes []byte) (*Service, *clock) {
	t.Helper()
	tb, err := domain.NewTrustBundleFromPEM(pemBytes)
	if err != nil {
		t.Fatalf("trust bundle: %v", err)
	}
	clk := &clock{now: time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)}
	svc := New(tb, newMemStore(), bus.NewInProcess(), api.Config{StaleAfter: 5 * time.Minute, Now: clk.Now}, nil)
	return svc, clk
}

// fakeApplier is the in-process stand-in for the data-plane apply seam.
type fakeApplier struct {
	applyFn func(rel api.Release) error
	applied []api.Release
}

func (f *fakeApplier) Apply(_ context.Context, r api.Release) error {
	f.applied = append(f.applied, r)
	if f.applyFn != nil {
		return f.applyFn(r)
	}
	return nil
}

const (
	tenant = "tenant-1"
	plane  = "dp-1"
)

// --- AC3: the signature gate runs BEFORE anything is recorded ------------------------------

func TestPublishRefusesUnsignedLeavesStateUntouched(t *testing.T) {
	priv, pemBytes := testKey(t)
	svc, _ := newService(t, pemBytes)
	ctx := context.Background()

	// A good rollout exists first: the refusal must leave it exactly as it is.
	good := mkRelease(t, priv, "1.0.0", "sha256:aaa")
	if _, err := svc.PublishDesired(ctx, tenant, plane, 1, good); err != nil {
		t.Fatalf("publish good release: %v", err)
	}

	unsigned := api.Release{Component: "git-rpc", Version: "1.1.0", Signed: rel("1.1.0", "sha256:bbb")}
	_, err := svc.PublishDesired(ctx, tenant, plane, 2, unsigned)
	if err != api.ErrReleaseUnsigned {
		t.Fatalf("unsigned release must be refused as unsigned, got %v", err)
	}

	// The existing rollout is untouched: still generation 1.
	r, _, rerr := svc.Rollout(ctx, tenant, plane)
	if rerr != nil {
		t.Fatalf("rollout: %v", rerr)
	}
	if r.Generation != 1 || r.DesiredVersion != "1.0.0" {
		t.Fatalf("a refused release must leave the running rollout untouched, got gen=%d ver=%s", r.Generation, r.DesiredVersion)
	}
}

func TestPublishRefusesMisSigned(t *testing.T) {
	attacker, _ := testKey(t)
	_, trustedPEM := testKey(t)
	svc, _ := newService(t, trustedPEM)

	bad := mkRelease(t, attacker, "1.1.0", "sha256:bbb") // signed by an untrusted key
	_, err := svc.PublishDesired(context.Background(), tenant, plane, 1, bad)
	if err != api.ErrReleaseMisSigned {
		t.Fatalf("mis-signed release must be refused, got %v", err)
	}
}

// --- AC4: idempotent reconcile — same generation twice is not a second rollout ------------

func TestPublishSameGenerationIsIdempotent(t *testing.T) {
	priv, pemBytes := testKey(t)
	svc, _ := newService(t, pemBytes)
	ctx := context.Background()

	r1 := mkRelease(t, priv, "1.1.0", "sha256:aaa")
	first, err := svc.PublishDesired(ctx, tenant, plane, 7, r1)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	second, err := svc.PublishDesired(ctx, tenant, plane, 7, r1)
	if err != nil {
		t.Fatalf("republish same generation: %v", err)
	}
	if first.ID != second.ID {
		t.Fatalf("republishing the same generation must return the SAME rollout, got %s and %s", first.ID, second.ID)
	}
}

func TestReconcileTerminalIsNoOp(t *testing.T) {
	priv, pemBytes := testKey(t)
	svc, _ := newService(t, pemBytes)
	ctx := context.Background()

	r := mkRelease(t, priv, "1.1.0", "sha256:aaa")
	if _, err := svc.PublishDesired(ctx, tenant, plane, 1, r); err != nil {
		t.Fatalf("publish: %v", err)
	}
	applier := &fakeApplier{}
	if _, err := svc.Reconcile(ctx, tenant, plane, applier); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	// Converge it.
	if _, err := svc.ReportActual(ctx, tenant, plane, api.ActualReport{AppliedGeneration: 1, ActualVersion: "1.1.0", Healthy: true}); err != nil {
		t.Fatalf("report: %v", err)
	}
	before := len(applier.applied)
	// A second reconcile of an applied rollout applies nothing again.
	if _, err := svc.Reconcile(ctx, tenant, plane, applier); err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
	if len(applier.applied) != before {
		t.Fatalf("reconciling an applied rollout must be a no-op, applied %d more times", len(applier.applied)-before)
	}
}

// --- AC5: a failed upgrade rolls back and reports a reason --------------------------------

func TestReconcileFailureRollsBackToPrior(t *testing.T) {
	priv, pemBytes := testKey(t)
	svc, _ := newService(t, pemBytes)
	ctx := context.Background()

	// Establish a known-good v1.0.0 as the running release.
	v1 := mkRelease(t, priv, "1.0.0", "sha256:aaa")
	if _, err := svc.PublishDesired(ctx, tenant, plane, 1, v1); err != nil {
		t.Fatalf("publish v1: %v", err)
	}
	if _, err := svc.Reconcile(ctx, tenant, plane, &fakeApplier{}); err != nil {
		t.Fatalf("reconcile v1: %v", err)
	}
	if _, err := svc.ReportActual(ctx, tenant, plane, api.ActualReport{AppliedGeneration: 1, ActualVersion: "1.0.0", Healthy: true}); err != nil {
		t.Fatalf("report v1: %v", err)
	}

	// Publish a broken v1.1.0 and make the applier fail it.
	v2 := mkRelease(t, priv, "1.1.0", "sha256:bbb")
	if _, err := svc.PublishDesired(ctx, tenant, plane, 2, v2); err != nil {
		t.Fatalf("publish v2: %v", err)
	}
	failApplier := &fakeApplier{applyFn: func(r api.Release) error {
		if r.Version == "1.1.0" {
			return context.DeadlineExceeded // the upgrade fails
		}
		return nil
	}}
	out, err := svc.Reconcile(ctx, tenant, plane, failApplier)
	if err != nil {
		t.Fatalf("reconcile v2: %v", err)
	}
	if out.Phase != api.PhaseRolledBack {
		t.Fatalf("a failed upgrade must roll back, got phase %s", out.Phase)
	}
	if out.ActualVersion != "1.0.0" {
		t.Fatalf("rollback must restore the prior version, got %s", out.ActualVersion)
	}
	if out.Message == "" {
		t.Fatal("a rolled-back upgrade must report a reason (AC5)")
	}
}

// --- AC6: only a reported convergence applies; reports drive the phase -------------------

func TestReportActualAppliesOnlyOnReportedConvergence(t *testing.T) {
	priv, pemBytes := testKey(t)
	svc, _ := newService(t, pemBytes)
	ctx := context.Background()

	r := mkRelease(t, priv, "1.1.0", "sha256:aaa")
	if _, err := svc.PublishDesired(ctx, tenant, plane, 1, r); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if _, err := svc.Reconcile(ctx, tenant, plane, &fakeApplier{}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	// Before any report, the rollout is in-progress — never applied.
	got, status, err := svc.Rollout(ctx, tenant, plane)
	if err != nil {
		t.Fatalf("rollout: %v", err)
	}
	if got.Phase != api.PhaseInProgress || status.Phase == api.PhaseApplied {
		t.Fatalf("before a report the rollout must be in-progress, got %s", got.Phase)
	}
	// A report of convergence is the ONLY thing that may apply it.
	if _, err := svc.ReportActual(ctx, tenant, plane, api.ActualReport{AppliedGeneration: 1, ActualVersion: "1.1.0", Healthy: true}); err != nil {
		t.Fatalf("report: %v", err)
	}
	got, _, _ = svc.Rollout(ctx, tenant, plane)
	if got.Phase != api.PhaseApplied {
		t.Fatalf("a reported convergence must apply the rollout, got %s", got.Phase)
	}
}

// --- AC7: the version window holds and its expiry is honored -----------------------------

func TestWindowHoldsPinnedVersion(t *testing.T) {
	priv, pemBytes := testKey(t)
	svc, _ := newService(t, pemBytes)
	ctx := context.Background()

	// Pin to 1.0.0 with a future supported window.
	if err := svc.SetWindow(ctx, tenant, plane, api.VersionWindow{
		PinnedVersion: "1.0.0", SupportedUntil: time.Now().Add(24 * time.Hour),
	}); err != nil {
		t.Fatalf("set window: %v", err)
	}
	// Publish 1.1.0: it is recorded (desired) but the reconcile holds it.
	v := mkRelease(t, priv, "1.1.0", "sha256:aaa")
	if _, err := svc.PublishDesired(ctx, tenant, plane, 1, v); err != nil {
		t.Fatalf("publish: %v", err)
	}
	applier := &fakeApplier{}
	out, err := svc.Reconcile(ctx, tenant, plane, applier)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if len(applier.applied) != 0 {
		t.Fatalf("a pinned version must not be applied, applied=%d", len(applier.applied))
	}
	if out.Phase != api.PhaseInProgress {
		t.Fatalf("a held rollout stays in-progress, got %s", out.Phase)
	}
}

func TestExpiredWindowDoesNotSilentlyForce(t *testing.T) {
	priv, pemBytes := testKey(t)
	svc, clk := newService(t, pemBytes)
	ctx := context.Background()

	// A window whose support already lapsed.
	if err := svc.SetWindow(ctx, tenant, plane, api.VersionWindow{SupportedUntil: clk.now.Add(-1 * time.Hour)}); err != nil {
		t.Fatalf("set window: %v", err)
	}
	v := mkRelease(t, priv, "1.1.0", "sha256:aaa")
	if _, err := svc.PublishDesired(ctx, tenant, plane, 1, v); err != nil {
		t.Fatalf("publish: %v", err)
	}
	applier := &fakeApplier{}
	_, err := svc.Reconcile(ctx, tenant, plane, applier)
	if err != api.ErrWindowExpired {
		t.Fatalf("an upgrade past the supported window must not be silently forced, got %v", err)
	}
	if len(applier.applied) != 0 {
		t.Fatal("nothing may be applied past an expired window without an explicit force")
	}
}
