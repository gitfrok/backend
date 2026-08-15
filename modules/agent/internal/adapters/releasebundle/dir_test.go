package releasebundle_test

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gitfrok/backend/modules/agent/api"
	"github.com/gitfrok/backend/modules/agent/internal/adapters/releasebundle"
)

// The staged-key ACTUATION seam (T-0041, SPEC-0045 AC2): the desired live
// key set is declared as *.pub files and ReconcileDir converges the bundle
// toward it — the operator-visible rotation procedure reduced to one
// deterministic call.

func writePub(t *testing.T, dir string, k testKey) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, k.id+".pub"), k.pem, 0o600); err != nil {
		t.Fatal(err)
	}
}

func newReconcileBundle(t *testing.T) *releasebundle.Bundle {
	t.Helper()
	b, err := releasebundle.NewBundle(time.Now)
	if err != nil {
		t.Fatalf("NewBundle: %v", err)
	}
	return b
}

func TestReconcileDirStagesDeclaredKeys(t *testing.T) {
	dir := t.TempDir()
	k1, k2 := newTestKey(t, "release-signing-gen1"), newTestKey(t, "release-signing-gen2")
	writePub(t, dir, k1)
	writePub(t, dir, k2)

	b := newReconcileBundle(t)
	if err := b.ReconcileDir(dir); err != nil {
		t.Fatalf("ReconcileDir: %v", err)
	}
	st, ok, err := b.LatestReleaseTrustBundle(t.Context())
	if err != nil || !ok {
		t.Fatalf("LatestReleaseTrustBundle = (_, %v, %v), want the staged bundle", ok, err)
	}
	if len(st.Keys) != 2 || st.Keys[0].ID != k1.id || st.Keys[1].ID != k2.id {
		t.Fatalf("staged keys = %+v, want both declared keys oldest-first", st.Keys)
	}
	// Signing moves deterministically to the LAST declared key in sort order.
	if st.SigningKeyID != k2.id {
		t.Fatalf("signing key = %q, want %q", st.SigningKeyID, k2.id)
	}
}

func TestReconcileDirRemovesUndeclaredKey(t *testing.T) {
	dir := t.TempDir()
	k1, k2 := newTestKey(t, "release-signing-gen1"), newTestKey(t, "release-signing-gen2")
	writePub(t, dir, k1)
	writePub(t, dir, k2)
	b := newReconcileBundle(t)
	if err := b.ReconcileDir(dir); err != nil {
		t.Fatalf("ReconcileDir: %v", err)
	}

	// The overlap plays out: gen1's file leaves the declaration, gen2 stays.
	if err := os.Remove(filepath.Join(dir, k1.id+".pub")); err != nil {
		t.Fatal(err)
	}
	revBefore := b.StagingRevision()
	if err := b.ReconcileDir(dir); err != nil {
		t.Fatalf("ReconcileDir after removal: %v", err)
	}
	st, ok, _ := b.LatestReleaseTrustBundle(t.Context())
	if !ok || len(st.Keys) != 1 || st.Keys[0].ID != k2.id || st.SigningKeyID != k2.id {
		t.Fatalf("converged bundle = %+v (ok=%v), want only gen2", st, ok)
	}
	if b.StagingRevision() <= revBefore {
		t.Fatalf("removal did not advance the staging revision (%d -> %d)", revBefore, b.StagingRevision())
	}
}

func TestReconcileDirEmptyDeclarationRemovesNothing(t *testing.T) {
	dir := t.TempDir()
	k1 := newTestKey(t, "release-signing-gen1")
	b := newReconcileBundle(t)
	if err := b.Bootstrap(k1.id, k1.pem); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	rev := b.StagingRevision()
	if err := b.ReconcileDir(dir); err != nil {
		t.Fatalf("ReconcileDir on empty declaration: %v", err)
	}
	st, ok, _ := b.LatestReleaseTrustBundle(t.Context())
	if !ok || len(st.Keys) != 1 || b.StagingRevision() != rev {
		t.Fatalf("empty declaration changed the bundle (ok=%v keys=%d rev %d->%d) — it must be a no-op", ok, len(st.Keys), rev, b.StagingRevision())
	}
}

func TestReconcileDirSigningKeyLeavesOnlyViaSuccessor(t *testing.T) {
	dir := t.TempDir()
	k1, k2 := newTestKey(t, "release-signing-gen1"), newTestKey(t, "release-signing-gen2")
	b := newReconcileBundle(t)
	if err := b.Bootstrap(k1.id, k1.pem); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if err := b.Stage(k2.id, k2.pem); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	// The declaration names ONLY the old key: removing the SIGNING key gen2
	// is refused by the precondition, so the reconcile leaves it live and the
	// fleet keeps validating gen2 signatures.
	writePub(t, dir, k1)
	if err := b.ReconcileDir(dir); err != nil {
		t.Fatalf("ReconcileDir with a refused removal must not error: %v", err)
	}
	st, ok, _ := b.LatestReleaseTrustBundle(t.Context())
	if !ok || len(st.Keys) != 2 {
		t.Fatalf("bundle after refused removal = %+v (ok=%v), want BOTH keys still trusted", st, ok)
	}
	if st.SigningKeyID != k2.id {
		t.Fatalf("signing key moved to %q without a successor — the precondition must hold", st.SigningKeyID)
	}
}

func TestReconcileDirPrivateMaterialRefusedBeforeAnyChange(t *testing.T) {
	dir := t.TempDir()
	k1 := newTestKey(t, "release-signing-gen1")
	writePub(t, dir, k1)
	b := newReconcileBundle(t)
	if err := b.ReconcileDir(dir); err != nil {
		t.Fatalf("ReconcileDir: %v", err)
	}
	rev := b.StagingRevision()

	// A private key dropped into the declaration refuses the WHOLE reconcile:
	// nothing stages, nothing removes (ADR-0044 custody posture).
	privDER, err := x509.MarshalECPrivateKey(k1.priv)
	if err != nil {
		t.Fatal(err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})
	if err := os.WriteFile(filepath.Join(dir, "release-signing-gen2.pub"), privPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := b.ReconcileDir(dir); err == nil {
		t.Fatal("ReconcileDir accepted a private key — the seam must refuse it")
	}
	if b.StagingRevision() != rev {
		t.Fatalf("refused reconcile moved the revision %d -> %d — it must change nothing", rev, b.StagingRevision())
	}
}

func TestReconcileDirMissingDirIsAnError(t *testing.T) {
	b := newReconcileBundle(t)
	if err := b.ReconcileDir(filepath.Join(t.TempDir(), "absent")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ReconcileDir on a missing directory = %v, want ErrNotExist", err)
	}
}

// TestReconcileDirReDeclaredRetiredKeyConverges is the un-wedge proof: a key
// ID that was declared, retired, and declared AGAIN must re-enter the bundle
// — the old shape counted retired occurrences as "known" and skipped them
// forever, so ReconcileDir could never converge toward a re-declaration.
func TestReconcileDirReDeclaredRetiredKeyConverges(t *testing.T) {
	dir := t.TempDir()
	k1, k2 := newTestKey(t, "release-signing-gen1"), newTestKey(t, "release-signing-gen2")
	writePub(t, dir, k1)
	writePub(t, dir, k2)
	b := newReconcileBundle(t)
	if err := b.ReconcileDir(dir); err != nil {
		t.Fatalf("ReconcileDir: %v", err)
	}

	// gen1 leaves the declaration and is retired (gen2 keeps signing).
	if err := os.Remove(filepath.Join(dir, k1.id+".pub")); err != nil {
		t.Fatal(err)
	}
	if err := b.ReconcileDir(dir); err != nil {
		t.Fatalf("ReconcileDir after removal: %v", err)
	}

	// gen1 is declared AGAIN — with FRESH key material — and reconciled.
	k1b := newTestKey(t, "release-signing-gen1")
	writePub(t, dir, k1b)
	if err := b.ReconcileDir(dir); err != nil {
		t.Fatalf("ReconcileDir with a re-declared retired key: %v", err)
	}
	st, ok, err := b.LatestReleaseTrustBundle(t.Context())
	if err != nil || !ok {
		t.Fatalf("LatestReleaseTrustBundle = (_, %v, %v)", ok, err)
	}
	var live []string
	for _, k := range st.Keys {
		live = append(live, k.ID)
	}
	if len(live) != 2 {
		t.Fatalf("live keys after re-declaration = %v, want the re-staged gen1 beside gen2", live)
	}
	// The FRESH material is what the bundle trusts now: a signature by the
	// re-declared key validates.
	sig := signReleaseDir(t, k1b)
	if !verifiesAgainstDir(t, st.Keys, sig) {
		t.Fatal("signature by the re-declared key does not validate against the converged bundle")
	}
}

// signReleaseDir / verifiesAgainstDir are the dir-suite's signature helpers:
// sign one canonical release identity with a test key, and verify against
// every key a bundle projection carries.
const dirReleaseIdentity = "registry.example/gitfrok/operator@sha256:redeclared"

func signReleaseDir(t *testing.T, k testKey) []byte {
	t.Helper()
	h := sha256.Sum256([]byte(dirReleaseIdentity))
	sig, err := ecdsa.SignASN1(rand.Reader, k.priv, h[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return sig
}

func verifiesAgainstDir(t *testing.T, keys []api.ReleaseTrustKey, sig []byte) bool {
	t.Helper()
	h := sha256.Sum256([]byte(dirReleaseIdentity))
	for _, k := range keys {
		block, _ := pem.Decode(k.PublicKeyPEM)
		if block == nil {
			t.Fatalf("distributed key %q carries no PEM block", k.ID)
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			t.Fatalf("distributed key %q does not parse: %v", k.ID, err)
		}
		ec, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			t.Fatalf("distributed key %q is %T, want ECDSA", k.ID, pub)
		}
		if ecdsa.VerifyASN1(ec, h[:], sig) {
			return true
		}
	}
	return false
}
