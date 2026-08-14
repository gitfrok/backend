package rollout

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"github.com/gitfrok/backend/modules/rollout/api"
	"github.com/gitfrok/backend/platform/bus"
)

// This is the integration lane the task's test list asks for: a full rollout driven through the
// real composition root (trust bundle + memory store + bus) against a FAKE CLUSTER — an
// Applier that can be made to fail — and a silent data plane whose staleness is asserted. It
// exercises the whole engine end to end without opening any inbound path: the only seam is the
// local Applier (SPEC-0039 AC4).

func testSigningKey(t *testing.T) (*ecdsa.PrivateKey, []byte) {
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

func signedRelease(t *testing.T, priv *ecdsa.PrivateKey, version, digest string) api.Release {
	t.Helper()
	s := api.SignedRelease{OCIRef: "registry.gitsaas.example/gitsaas/git-rpc", Digest: digest}
	hash := sha256.Sum256(s.CanonicalIdentity())
	sig, err := ecdsa.SignASN1(rand.Reader, priv, hash[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	s.Signature = sig
	return api.Release{Component: "git-rpc", Version: version, Signed: s}
}

// fakeCluster is the data-plane apply seam in the integration lane. It records what it was
// asked to run and can be told to fail a specific version, which is how a broken upgrade is
// injected without any real cluster.
type fakeCluster struct {
	failVersion string
	running     string
	applies     []string
}

func (c *fakeCluster) Apply(_ context.Context, r api.Release) error {
	c.applies = append(c.applies, r.Version)
	if c.failVersion == r.Version {
		return errors.New("fake cluster: " + r.Version + " failed its health gate")
	}
	c.running = r.Version
	return nil
}

func TestIntegrationRolloutFailureRollbackAgainstFakeCluster(t *testing.T) {
	priv, pubPEM := testSigningKey(t)
	tb, err := NewTrustBundleFromPEM(pubPEM)
	if err != nil {
		t.Fatalf("trust bundle: %v", err)
	}
	clk := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	engine := New(tb, bus.NewInProcess(), api.Config{StaleAfter: 5 * time.Minute, Now: func() time.Time { return clk }}, nil)
	ctx := context.Background()
	const tenant, plane = "tenant-1", "dp-1"

	cluster := &fakeCluster{}

	// 1. Ship v1.0.0 and let the cluster converge on it — the known-good baseline.
	v1 := signedRelease(t, priv, "1.0.0", "sha256:aaa")
	if _, err := engine.PublishDesired(ctx, tenant, plane, 1, v1); err != nil {
		t.Fatalf("publish v1: %v", err)
	}
	if _, err := engine.Reconcile(ctx, tenant, plane, cluster); err != nil {
		t.Fatalf("reconcile v1: %v", err)
	}
	if _, err := engine.ReportActual(ctx, tenant, plane, api.ActualReport{AppliedGeneration: 1, ActualVersion: "1.0.0", Healthy: true}); err != nil {
		t.Fatalf("report v1: %v", err)
	}
	if cluster.running != "1.0.0" {
		t.Fatalf("cluster should be running v1.0.0, got %s", cluster.running)
	}

	// 2. Ship a broken v1.1.0: the cluster's apply fails.
	cluster.failVersion = "1.1.0"
	v2 := signedRelease(t, priv, "1.1.0", "sha256:bbb")
	if _, err := engine.PublishDesired(ctx, tenant, plane, 2, v2); err != nil {
		t.Fatalf("publish v2: %v", err)
	}
	out, err := engine.Reconcile(ctx, tenant, plane, cluster)
	if err != nil {
		t.Fatalf("reconcile v2: %v", err)
	}

	// 3. The failed upgrade must roll back to the prior release, with a reason, and the
	//    cluster must actually be running the prior version again — no half-applied state.
	if out.Phase != api.PhaseRolledBack {
		t.Fatalf("a failed upgrade must read ROLLED_BACK, got %s", out.Phase)
	}
	if out.Message == "" {
		t.Fatal("a rolled-back upgrade must report why (AC5)")
	}
	if cluster.running != "1.0.0" {
		t.Fatalf("the cluster must be back on v1.0.0 after rollback, got %s", cluster.running)
	}
	got, status, err := engine.Rollout(ctx, tenant, plane)
	if err != nil {
		t.Fatalf("rollout view: %v", err)
	}
	if got.Phase != api.PhaseRolledBack || status.Stale {
		t.Fatalf("rollout view must read rolled-back and not stale, got phase=%s stale=%v", got.Phase, status.Stale)
	}
	if got.ActualVersion != "1.0.0" {
		t.Fatalf("the reported actual version must be the prior release, got %s", got.ActualVersion)
	}
}

func TestIntegrationSilentDataPlaneIsStaleNeverUpgraded(t *testing.T) {
	priv, pubPEM := testSigningKey(t)
	tb, err := NewTrustBundleFromPEM(pubPEM)
	if err != nil {
		t.Fatalf("trust bundle: %v", err)
	}
	now := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	current := now
	engine := New(tb, bus.NewInProcess(), api.Config{StaleAfter: 5 * time.Minute, Now: func() time.Time { return current }}, nil)
	ctx := context.Background()
	const tenant, plane = "tenant-1", "dp-silent"

	// Publish a rollout, reconcile it into the cluster, but the data plane then goes SILENT —
	// no report ever arrives.
	v := signedRelease(t, priv, "2.0.0", "sha256:ccc")
	if _, err := engine.PublishDesired(ctx, tenant, plane, 1, v); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if _, err := engine.Reconcile(ctx, tenant, plane, &fakeCluster{}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	// While the silence is fresh the rollout reads in-progress.
	_, status, err := engine.Rollout(ctx, tenant, plane)
	if err != nil {
		t.Fatalf("rollout view: %v", err)
	}
	if status.Phase == api.PhaseApplied {
		t.Fatal("a rollout with no data-plane report must never read upgraded")
	}

	// Age past the staleness window: the silent data plane reads STALE, never "upgraded".
	current = now.Add(10 * time.Minute)
	got, status, err := engine.Rollout(ctx, tenant, plane)
	if err != nil {
		t.Fatalf("rollout view: %v", err)
	}
	if !status.Stale {
		t.Fatal("a data plane silent since the rollout began must read stale")
	}
	if got.Phase == api.PhaseApplied || status.Phase == api.PhaseApplied {
		t.Fatal("a stale, silent data plane must NEVER read as upgraded")
	}
}
