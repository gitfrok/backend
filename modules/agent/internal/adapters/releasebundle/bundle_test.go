package releasebundle_test

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

	"github.com/gitfrok/backend/modules/agent/internal/adapters/releasebundle"
)

// The staged RELEASE trust bundle of SPEC-0045 AC2 — the cosign
// release-signing keys of ADR-0044/ADR-0065. These tests are the
// rotation-window mechanics on their own surface; the reconcile-distribution
// proof over the wire is release_bundle_reconcile_test.go in the grpc
// adapter. Nothing here touches the CA trust bundle of SPEC-0044 — the two
// artifacts never prove one another.

type testClock struct{ t time.Time }

func (c *testClock) Now() time.Time          { return c.t }
func (c *testClock) Advance(d time.Duration) { c.t = c.t.Add(d) }

// testKey is one release-signing keypair: the private half stays in the
// test (the publishing CI's posture), the public PEM is what stages.
type testKey struct {
	id   string
	priv *ecdsa.PrivateKey
	pem  []byte
}

func newTestKey(t *testing.T, id string) testKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate %s: %v", id, err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal %s: %v", id, err)
	}
	return testKey{id: id, priv: priv, pem: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})}
}

// signRelease signs one release's canonical identity the way sign-release.sh
// does: ECDSA over sha256(oci_ref@digest), DER, base64 — here as raw DER.
func signRelease(t *testing.T, k testKey, ociRef, digest string) []byte {
	t.Helper()
	h := sha256.Sum256([]byte(ociRef + "@" + digest))
	sig, err := ecdsa.SignASN1(rand.Reader, k.priv, h[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return sig
}

// verifiesAgainst reports whether sig checks out against ANY key the
// projection carries — the data plane's dual-validate view.
func verifiesAgainst(t *testing.T, keys [][]byte, sig []byte, ociRef, digest string) bool {
	t.Helper()
	h := sha256.Sum256([]byte(ociRef + "@" + digest))
	for _, raw := range keys {
		block, _ := pem.Decode(raw)
		if block == nil {
			t.Fatalf("distributed key carries no PEM block")
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			t.Fatalf("distributed key does not parse: %v", err)
		}
		ec, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			t.Fatalf("distributed key is %T, want ECDSA", pub)
		}
		if ecdsa.VerifyASN1(ec, h[:], sig) {
			return true
		}
	}
	return false
}

func bundleKeys(t *testing.T, b *releasebundle.Bundle) [][]byte {
	t.Helper()
	st, ok, err := b.LatestReleaseTrustBundle(context.Background())
	if err != nil || !ok {
		t.Fatalf("LatestReleaseTrustBundle = (_, %v, %v), want a projection", ok, err)
	}
	var out [][]byte
	for _, k := range st.Keys {
		out = append(out, k.PublicKeyPEM)
	}
	return out
}

// TestStagedDualValidateWindowIsNoDowntime is AC2's rotation mechanics:
// during the overlap BOTH keys' signatures validate — a release signed
// before the stage keeps verifying after it, and a release signed with the
// new key verifies immediately. There is no instant at which either plane's
// trust set rejects a legitimate signature.
func TestStagedDualValidateWindowIsNoDowntime(t *testing.T) {
	clk := &testClock{t: time.Now()}
	b, err := releasebundle.NewBundle(clk.Now)
	if err != nil {
		t.Fatalf("NewBundle: %v", err)
	}
	gen1 := newTestKey(t, "release-signing-gen1")
	if err := b.Bootstrap(gen1.id, gen1.pem); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	const ociRef = "registry.example/gitfrok/operator"
	const digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	oldSig := signRelease(t, gen1, ociRef, digest)

	gen2 := newTestKey(t, "release-signing-gen2")
	if err := b.Stage(gen2.id, gen2.pem); err != nil {
		t.Fatalf("Stage: %v", err)
	}

	st, ok, err := b.LatestReleaseTrustBundle(context.Background())
	if err != nil || !ok {
		t.Fatalf("LatestReleaseTrustBundle = (_, %v, %v)", ok, err)
	}
	if len(st.Keys) != 2 {
		t.Fatalf("overlap projection carries %d keys, want 2", len(st.Keys))
	}
	if st.Keys[0].ID != gen1.id || st.Keys[1].ID != gen2.id {
		t.Fatalf("overlap keys = [%s %s], want [gen1 gen2] oldest-first", st.Keys[0].ID, st.Keys[1].ID)
	}
	if st.SigningKeyID != gen2.id {
		t.Errorf("signing key during overlap = %q, want %q", st.SigningKeyID, gen2.id)
	}
	if st.Revision < 2 {
		t.Errorf("revision = %d after bootstrap + stage, want >= 2", st.Revision)
	}

	keys := bundleKeys(t, b)
	if !verifiesAgainst(t, keys, oldSig, ociRef, digest) {
		t.Errorf("pre-stage signature stopped validating during the overlap — downtime")
	}
	newSig := signRelease(t, gen2, ociRef, digest)
	if !verifiesAgainst(t, keys, newSig, ociRef, digest) {
		t.Errorf("signature by the staged key does not validate during the overlap")
	}
}

// TestRemovalPreconditionsKeepOldKeyTrusted proves the removal half: the
// only live key and the current SIGNING key both refuse removal, and a
// refused removal leaves the projection and the revision untouched; after a
// successor is staged, the old key leaves and the projection converges.
func TestRemovalPreconditionsKeepOldKeyTrusted(t *testing.T) {
	clk := &testClock{t: time.Now()}
	b, err := releasebundle.NewBundle(clk.Now)
	if err != nil {
		t.Fatalf("NewBundle: %v", err)
	}
	gen1 := newTestKey(t, "release-signing-gen1")
	if err := b.Bootstrap(gen1.id, gen1.pem); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	// The ONLY live key never leaves.
	if err := b.RemoveKey(gen1.id); !errors.Is(err, releasebundle.ErrKeyStillNeeded) {
		t.Fatalf("removing the only key = %v, want ErrKeyStillNeeded", err)
	}

	gen2 := newTestKey(t, "release-signing-gen2")
	if err := b.Stage(gen2.id, gen2.pem); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	// The SIGNING key leaves only via its successor's stage — direct
	// removal is refused while signing still points at it.
	if err := b.RemoveKey(gen2.id); !errors.Is(err, releasebundle.ErrKeyStillNeeded) {
		t.Fatalf("removing the signing key = %v, want ErrKeyStillNeeded", err)
	}
	before, _, _ := b.LatestReleaseTrustBundle(context.Background())

	// The predecessor, now superseded, leaves cleanly.
	if err := b.RemoveKey(gen1.id); err != nil {
		t.Fatalf("RemoveKey after the overlap: %v", err)
	}
	after, ok, err := b.LatestReleaseTrustBundle(context.Background())
	if err != nil || !ok {
		t.Fatalf("LatestReleaseTrustBundle after removal = (_, %v, %v)", ok, err)
	}
	if len(after.Keys) != 1 || after.Keys[0].ID != gen2.id {
		t.Fatalf("converged projection = %+v, want only %s", after.Keys, gen2.id)
	}
	if after.Revision <= before.Revision {
		t.Errorf("removal did not advance the revision: %d <= %d", after.Revision, before.Revision)
	}
	if after.SigningKeyID != gen2.id {
		t.Errorf("removal moved the signing key to %q, want %q", after.SigningKeyID, gen2.id)
	}
}

// TestPrivateMaterialRefused guards the custody posture on the way in: a
// private key presented for staging is refused, and the refusal changes
// nothing — the bundle keeps its prior state and revision.
func TestPrivateMaterialRefused(t *testing.T) {
	clk := &testClock{t: time.Now()}
	b, err := releasebundle.NewBundle(clk.Now)
	if err != nil {
		t.Fatalf("NewBundle: %v", err)
	}
	gen1 := newTestKey(t, "release-signing-gen1")
	if err := b.Bootstrap(gen1.id, gen1.pem); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	revBefore := b.StagingRevision()

	privDER, err := x509.MarshalECPrivateKey(gen1.priv)
	if err != nil {
		t.Fatalf("marshal private: %v", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})
	if err := b.Stage("intruder", privPEM); err == nil {
		t.Fatalf("staging a private key succeeded — the bundle must carry public material only")
	}
	if got := b.StagingRevision(); got != revBefore {
		t.Errorf("refused stage moved the revision %d -> %d", revBefore, got)
	}
	if len(b.Keys()) != 1 {
		t.Errorf("refused stage changed the key count to %d", len(b.Keys()))
	}

	// PKCS8 private keys are refused the same way.
	pkcs8, err := x509.MarshalPKCS8PrivateKey(gen1.priv)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	if err := b.Stage("intruder2", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})); err == nil {
		t.Fatalf("staging a PKCS8 private key succeeded")
	}
}

// TestMidWindowRestartRepublishesSameRevision covers the restart half: a
// bundle restored from its durable snapshot re-projects EXACTLY the revision
// and key set the fleet last saw — no replay, no skip.
func TestMidWindowRestartRepublishesSameRevision(t *testing.T) {
	clk := &testClock{t: time.Now()}
	b, err := releasebundle.NewBundle(clk.Now)
	if err != nil {
		t.Fatalf("NewBundle: %v", err)
	}
	gen1 := newTestKey(t, "release-signing-gen1")
	gen2 := newTestKey(t, "release-signing-gen2")
	if err := b.Bootstrap(gen1.id, gen1.pem); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if err := b.Stage(gen2.id, gen2.pem); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	before, _, _ := b.LatestReleaseTrustBundle(context.Background())

	restarted, err := releasebundle.NewBundle(clk.Now)
	if err != nil {
		t.Fatalf("NewBundle on restart: %v", err)
	}
	if err := restarted.Restore(b.Snapshot()); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	after, ok, err := restarted.LatestReleaseTrustBundle(context.Background())
	if err != nil || !ok {
		t.Fatalf("post-restart projection = (_, %v, %v)", ok, err)
	}
	if after.Revision != before.Revision {
		t.Errorf("restart changed the revision: %d -> %d", before.Revision, after.Revision)
	}
	if after.SigningKeyID != before.SigningKeyID {
		t.Errorf("restart changed the signing key: %q -> %q", before.SigningKeyID, after.SigningKeyID)
	}
	if len(after.Keys) != len(before.Keys) {
		t.Fatalf("restart changed the key count: %d -> %d", len(before.Keys), len(after.Keys))
	}
	for i := range after.Keys {
		if after.Keys[i].ID != before.Keys[i].ID {
			t.Errorf("restart changed key %d's ID: %q -> %q", i, before.Keys[i].ID, after.Keys[i].ID)
		}
	}
}

// TestEmptyBundleProjectsNothing: a bundle with no live key has nothing to
// distribute — the reconcile path must skip, never publish an empty trust
// set that would break every plane's release verification.
func TestEmptyBundleProjectsNothing(t *testing.T) {
	clk := &testClock{t: time.Now()}
	b, err := releasebundle.NewBundle(clk.Now)
	if err != nil {
		t.Fatalf("NewBundle: %v", err)
	}
	if _, ok, err := b.LatestReleaseTrustBundle(context.Background()); err != nil || ok {
		t.Fatalf("empty bundle projected (%v, %v), want (false, nil)", ok, err)
	}
}

// TestDuplicateKeyIDRefused: one key ID names exactly one key for its whole
// history in the bundle — staging a second key under a known ID is refused.
func TestDuplicateKeyIDRefused(t *testing.T) {
	clk := &testClock{t: time.Now()}
	b, err := releasebundle.NewBundle(clk.Now)
	if err != nil {
		t.Fatalf("NewBundle: %v", err)
	}
	gen1 := newTestKey(t, "release-signing-gen1")
	if err := b.Bootstrap(gen1.id, gen1.pem); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	gen2 := newTestKey(t, "release-signing-gen1") // same ID, different key
	if err := b.Stage(gen2.id, gen2.pem); err == nil {
		t.Fatalf("staging a duplicate key ID succeeded")
	}
}
