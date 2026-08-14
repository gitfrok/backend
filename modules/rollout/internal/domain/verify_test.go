package domain

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/gitfrok/backend/modules/rollout/api"
)

// testKey mints one ECDSA P-256 signing key and returns it alongside the PEM-encoded public
// key an operator would pin in the trust bundle. The private half stays in this test — it is
// exactly what ADR-0044 keeps out of the bundle and out of the process under test.
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
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	return priv, pemBytes
}

// sign signs one release's canonical identity with priv and returns the release carrying that
// signature — the shape the publishing CI produces.
func sign(t *testing.T, priv *ecdsa.PrivateKey, rel api.SignedRelease) api.SignedRelease {
	t.Helper()
	hash := sha256.Sum256(rel.CanonicalIdentity())
	sig, err := ecdsa.SignASN1(rand.Reader, priv, hash[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	rel.Signature = sig
	return rel
}

func baseRelease() api.SignedRelease {
	return api.SignedRelease{
		OCIRef: "registry.gitsaas.example/gitsaas/git-rpc",
		Digest: "sha256:0af3c1f7d9e24b8a6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b",
	}
}

func bundle(t *testing.T, pemBytes []byte) *TrustBundle {
	t.Helper()
	tb, err := NewTrustBundleFromPEM(pemBytes)
	if err != nil {
		t.Fatalf("trust bundle: %v", err)
	}
	return tb
}

func TestVerifyAcceptsCorrectlySignedRelease(t *testing.T) {
	priv, pemBytes := testKey(t)
	tb := bundle(t, pemBytes)
	rel := sign(t, priv, baseRelease())
	if err := tb.Verify(rel); err != nil {
		t.Fatalf("a correctly signed release must verify, got %v", err)
	}
}

func TestVerifyRefusesUnsignedRelease(t *testing.T) {
	_, pemBytes := testKey(t)
	tb := bundle(t, pemBytes)
	rel := baseRelease() // no signature
	if err := tb.Verify(rel); err != api.ErrReleaseUnsigned {
		t.Fatalf("an unsigned release must be refused as unsigned, got %v", err)
	}
}

func TestVerifyRefusesMisSignedRelease(t *testing.T) {
	attacker, _ := testKey(t)
	_, trustedPEM := testKey(t) // the bundle pins a DIFFERENT key
	tb := bundle(t, trustedPEM)

	// Signed by a key the data plane does not trust.
	rel := sign(t, attacker, baseRelease())
	if err := tb.Verify(rel); err != api.ErrReleaseMisSigned {
		t.Fatalf("a release signed by an untrusted key must be refused as mis-signed, got %v", err)
	}
}

func TestVerifyRefusesTamperedIdentity(t *testing.T) {
	priv, pemBytes := testKey(t)
	tb := bundle(t, pemBytes)

	rel := sign(t, priv, baseRelease())
	// Tamper the digest after signing: the signature no longer covers the identity.
	rel.Digest = "sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	if err := tb.Verify(rel); err != api.ErrReleaseMisSigned {
		t.Fatalf("a tampered digest must break the signature, got %v", err)
	}

	rel2 := sign(t, priv, baseRelease())
	rel2.OCIRef = "registry.attacker.example/gitsaas/git-rpc"
	if err := tb.Verify(rel2); err != api.ErrReleaseMisSigned {
		t.Fatalf("a swapped OCI ref must break the signature, got %v", err)
	}
}

func TestVerifyRefusesMalformedRelease(t *testing.T) {
	priv, pemBytes := testKey(t)
	tb := bundle(t, pemBytes)

	noDigest := sign(t, priv, api.SignedRelease{OCIRef: "registry.gitsaas.example/gitsaas/git-rpc"})
	if err := tb.Verify(noDigest); err != api.ErrReleaseMalformed {
		t.Fatalf("a release with no digest must be malformed, got %v", err)
	}
	noRef := sign(t, priv, api.SignedRelease{Digest: "sha256:abcd"})
	if err := tb.Verify(noRef); err != api.ErrReleaseMalformed {
		t.Fatalf("a release with no OCI ref must be malformed, got %v", err)
	}
}

func TestVerifyAcceptsRotationOverlapKey(t *testing.T) {
	// ADR-0044 rotation holds two keys during the overlap. A release signed by EITHER pinned
	// key must verify.
	oldKey, oldPEM := testKey(t)
	newKey, newPEM := testKey(t)
	tb := bundle(t, append(append([]byte{}, oldPEM...), newPEM...))
	if got := tb.KeyCount(); got != 2 {
		t.Fatalf("rotation overlap bundle should trust 2 keys, got %d", got)
	}
	if err := tb.Verify(sign(t, oldKey, baseRelease())); err != nil {
		t.Fatalf("release signed by the old key must verify during overlap, got %v", err)
	}
	if err := tb.Verify(sign(t, newKey, baseRelease())); err != nil {
		t.Fatalf("release signed by the new key must verify during overlap, got %v", err)
	}
}

func TestTrustBundleRefusesGarbage(t *testing.T) {
	if _, err := NewTrustBundleFromPEM([]byte("not a pem")); err == nil {
		t.Fatal("a bundle with no usable key must be refused")
	}
}

func TestTrustBundleRefusesPrivateKey(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if _, err := NewTrustBundleFromPEM(pemBytes); err == nil {
		t.Fatal("a private key must never be accepted into the trust bundle")
	}
}
