package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ReleaseTrustBundle is the operator's PINNED set of release-signing verification keys
// (ADR-0044, SPEC-0045 AC1): public material only, read once at startup from a directory
// the chart mounts read-only. This is the RELEASE trust artifact — cosign-style
// release-signing keys — and is a different thing from the agent-identity CA trust bundle
// (SPEC-0045's two-bundles note); it shares neither file, format nor name with it.
type ReleaseTrustBundle struct {
	keys []*ecdsa.PublicKey
	dir  string
}

// LoadReleaseTrustBundle reads every *.pub in dir as a PKIX ECDSA public key. The
// refusals are the custody posture: a missing or empty directory is refused (the operator
// cannot start without keys to verify with), and PRIVATE material is refused outright —
// a verification bundle that holds a private key is a custody breach, not a bundle.
func LoadReleaseTrustBundle(dir string) (*ReleaseTrustBundle, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", dir, err)
	}
	b := &ReleaseTrustBundle{dir: dir}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".pub") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		key, err := parseReleaseVerificationKey(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		b.keys = append(b.keys, key)
	}
	if len(b.keys) == 0 {
		return nil, fmt.Errorf("%s holds no *.pub verification key — the operator refuses to run without a pinned release trust bundle", dir)
	}
	return b, nil
}

// parseReleaseVerificationKey accepts a PKIX "PUBLIC KEY" PEM holding an ECDSA key, and
// nothing else: a private key in any wrapper is detected and refused.
func parseReleaseVerificationKey(pemBytes []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("not a PEM document")
	}
	if strings.Contains(block.Type, "PRIVATE") {
		return nil, fmt.Errorf("private key material is refused in a verification bundle (ADR-0044 custody)")
	}
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("PEM type %q — want PUBLIC KEY", block.Type)
	}
	if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return nil, fmt.Errorf("private key material disguised as a public key is refused")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKIX public key: %w", err)
	}
	ecKey, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not ECDSA — release signatures are ECDSA over SHA-256")
	}
	return ecKey, nil
}

// Size is how many verification keys the bundle trusts (the dual-validate overlap of a
// rotation briefly trusts two).
func (b *ReleaseTrustBundle) Size() int { return len(b.keys) }

// Verify checks one release identity's DER-encoded ECDSA signature against the bundle:
// at least one trusted key must accept it (the staged overlap of ADR-0044 means either
// generation's key verifies during rotation).
func (b *ReleaseTrustBundle) Verify(identity string, sigDER []byte) error {
	hash := sha256.Sum256([]byte(identity))
	for _, key := range b.keys {
		if ecdsa.VerifyASN1(key, hash[:], sigDER) {
			return nil
		}
	}
	return fmt.Errorf("no key in the release trust bundle verifies %s — the release is unsigned or mis-signed and is NOT applicable (SPEC-0039 AC3)", identity)
}
