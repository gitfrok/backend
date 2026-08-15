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
	"sync"
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

// TestDuplicateKeyIDRefused: one key ID names at most one LIVE key —
// staging a second key under a live ID is refused.
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
		t.Fatalf("staging a duplicate LIVE key ID succeeded")
	}
}

// TestRetiredKeyIDRestagesAfterRemoval: a key ID whose every occurrence is
// RETIRED may be staged again. A re-declared key must re-enter the bundle —
// the reconcile seam's convergence must never wedge on a name the bundle
// once knew.
func TestRetiredKeyIDRestagesAfterRemoval(t *testing.T) {
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
	if err := b.RemoveKey(gen1.id); err != nil {
		t.Fatalf("RemoveKey: %v", err)
	}

	// The SAME ID returns with NEW key material: it stages again.
	gen1b := newTestKey(t, "release-signing-gen1")
	if err := b.Stage(gen1b.id, gen1b.pem); err != nil {
		t.Fatalf("re-staging a fully retired key ID = %v, want it to stage again", err)
	}
	st, ok, err := b.LatestReleaseTrustBundle(context.Background())
	if err != nil || !ok {
		t.Fatalf("LatestReleaseTrustBundle = (_, %v, %v)", ok, err)
	}
	var live []string
	for _, k := range st.Keys {
		live = append(live, k.ID)
	}
	if len(live) != 2 {
		t.Fatalf("live keys after re-stage = %v, want gen2 and the re-staged gen1", live)
	}
	if st.SigningKeyID != gen1b.id {
		t.Fatalf("signing key after re-stage = %q, want the re-staged %q", st.SigningKeyID, gen1b.id)
	}
	// The re-staged key's NEW material is what verifies — the retired
	// occurrence is history, not trust.
	sig := signRelease(t, gen1b, "registry.example/gitfrok/operator", "sha256:33")
	if !verifiesAgainst(t, bundleKeys(t, b), sig, "registry.example/gitfrok/operator", "sha256:33") {
		t.Fatalf("signature by the re-staged key does not validate")
	}
}

// TestBootstrapIsAtomicUnderConcurrency: the empty-check and the stage are
// ONE atomic step — of N concurrent bootstraps, exactly one wins and the
// bundle holds exactly one live key (the old check-then-Stage shape let two
// racers both pass the check and both stage).
func TestBootstrapIsAtomicUnderConcurrency(t *testing.T) {
	clk := &testClock{t: time.Now()}
	b, err := releasebundle.NewBundle(clk.Now)
	if err != nil {
		t.Fatalf("NewBundle: %v", err)
	}
	const racers = 16
	keys := make([]testKey, racers)
	for i := range keys {
		keys[i] = newTestKey(t, "bootstrap-racer")
	}
	var wg sync.WaitGroup
	wins := make(chan error, racers)
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(k testKey) {
			defer wg.Done()
			wins <- b.Bootstrap(k.id, k.pem)
		}(keys[i])
	}
	wg.Wait()
	close(wins)
	succeeded := 0
	for err := range wins {
		if err == nil {
			succeeded++
		}
	}
	if succeeded != 1 {
		t.Fatalf("%d concurrent bootstraps succeeded, want exactly 1", succeeded)
	}
	st, ok, err := b.LatestReleaseTrustBundle(context.Background())
	if err != nil || !ok || len(st.Keys) != 1 {
		t.Fatalf("bundle after the race = %+v (ok=%v, err=%v), want exactly one live key", st, ok, err)
	}
}

// TestChangeHookFiresOutsideTheLock: the hook may read back into the bundle
// — it must not deadlock, which a hook fired under the bundle lock would.
// The watchdog turns the deadlock into a failure instead of a hang.
func TestChangeHookFiresOutsideTheLock(t *testing.T) {
	clk := &testClock{t: time.Now()}
	b, err := releasebundle.NewBundle(clk.Now)
	if err != nil {
		t.Fatalf("NewBundle: %v", err)
	}
	var once sync.Once
	called := make(chan struct{})
	b.SetChangeHook(func(releasebundle.Snapshot) {
		_ = b.Revision() // reads back into the bundle; deadlocks if the hook rides mu
		_ = b.Keys()
		once.Do(func() { close(called) })
	})
	gen1 := newTestKey(t, "release-signing-gen1")
	if err := b.Bootstrap(gen1.id, gen1.pem); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	select {
	case <-called:
	case <-time.After(2 * time.Second):
		t.Fatal("the change hook deadlocked — it fired under the bundle lock")
	}
}

// TestRemovalStampsOnlyTheLiveOccurrence: Stage deliberately permits an ID
// whose every occurrence is retired to be staged again, so the bundle can
// hold several entries for one key ID. Retiring the live occurrence must not
// rewrite the instant an EARLIER one stopped being trusted — Keys() is the
// operator-visible rotation state and it rides into the durable Snapshot, so
// a rewritten timestamp is a falsified record of when a key left trust.
func TestRemovalStampsOnlyTheLiveOccurrence(t *testing.T) {
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
		t.Fatalf("Stage gen2: %v", err)
	}
	if err := b.RemoveKey(gen1.id); err != nil {
		t.Fatalf("RemoveKey gen1: %v", err)
	}
	retiredAt := time.Time{}
	for _, k := range b.Keys() {
		if k.ID == gen1.id {
			retiredAt = k.RemovedAt
		}
	}
	if retiredAt.IsZero() {
		t.Fatal("gen1 carries no retirement instant after removal")
	}

	// The same ID returns with new material, takes signing, and is retired
	// again a day later.
	clk.Advance(24 * time.Hour)
	gen1b := newTestKey(t, "release-signing-gen1")
	if err := b.Stage(gen1b.id, gen1b.pem); err != nil {
		t.Fatalf("re-stage gen1: %v", err)
	}
	gen3 := newTestKey(t, "release-signing-gen3")
	if err := b.Stage(gen3.id, gen3.pem); err != nil {
		t.Fatalf("Stage gen3: %v", err)
	}
	clk.Advance(24 * time.Hour)
	if err := b.RemoveKey(gen1b.id); err != nil {
		t.Fatalf("RemoveKey re-staged gen1: %v", err)
	}

	var stamps []time.Time
	for _, k := range b.Keys() {
		if k.ID == gen1.id {
			stamps = append(stamps, k.RemovedAt)
		}
	}
	if len(stamps) != 2 {
		t.Fatalf("bundle holds %d occurrences of %q, want 2 (retired + re-staged)", len(stamps), gen1.id)
	}
	if !stamps[0].Equal(retiredAt) {
		t.Fatalf("the FIRST occurrence's retirement moved from %s to %s — a later removal rewrote rotation history",
			retiredAt, stamps[0])
	}
	if stamps[1].Equal(stamps[0]) {
		t.Fatalf("both occurrences carry the same retirement instant %s — they retired a day apart", stamps[0])
	}
}

// TestRestoreRefusesASigningKeyThatIsNotLive: a snapshot whose signing key
// names no live key would restore into a bundle that publishes a
// SigningKeyID absent from its own key set — the fleet would be told to
// expect signatures by a key it does not trust. The restore refuses instead.
func TestRestoreRefusesASigningKeyThatIsNotLive(t *testing.T) {
	clk := &testClock{t: time.Now()}
	b, err := releasebundle.NewBundle(clk.Now)
	if err != nil {
		t.Fatalf("NewBundle: %v", err)
	}
	gen1 := newTestKey(t, "release-signing-gen1")
	if err := b.Bootstrap(gen1.id, gen1.pem); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	snap := b.Snapshot()
	snap.SigningKeyID = "release-signing-never-staged"

	restored, err := releasebundle.NewBundle(clk.Now)
	if err != nil {
		t.Fatalf("NewBundle: %v", err)
	}
	if err := restored.Restore(snap); err == nil {
		t.Fatal("Restore accepted a signing key that is not live in the restored bundle")
	}
	// The refusal changes nothing: the bundle stays empty rather than
	// half-restored.
	if _, ok, err := restored.LatestReleaseTrustBundle(t.Context()); ok || err != nil {
		t.Fatalf("after a refused restore the bundle projects (ok=%v, err=%v), want nothing", ok, err)
	}
}
