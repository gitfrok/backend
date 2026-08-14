// Package domain is the Rollout context's inner layer: release-signing verification and
// rollout decisions as plain logic, with no infrastructure (invariant 16). Store mechanics
// live in the adapters; the signing primitives here use only the standard library, because
// verification is offline and must work in a customer cluster that cannot reach a
// transparency log (ADR-0044, ADR-0035).
package domain

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/gitfrok/backend/modules/rollout/api"
)

// TrustBundle is the set of first-party ECDSA public keys a data plane pins to verify release
// signatures (ADR-0044). It is a non-secret, versioned operator artifact; the private key that
// pairs with any key here lives only in the publishing CI's protected environment and never
// appears in this process.
type TrustBundle struct {
	keys []*ecdsa.PublicKey
}

// NewTrustBundleFromPEM parses one or more PEM-encoded public keys into a bundle. A bundle
// with no usable ECDSA key is an error: a data plane that cannot verify a signature must not
// accept releases at all, which is the same posture the enrolment CA bundle takes.
func NewTrustBundleFromPEM(pemBytes []byte) (*TrustBundle, error) {
	tb := &TrustBundle{}
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		pub, err := parsePublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("trust bundle: %w", err)
		}
		tb.keys = append(tb.keys, pub)
	}
	if len(tb.keys) == 0 {
		return nil, fmt.Errorf("trust bundle: no usable ECDSA public key found")
	}
	return tb, nil
}

// parsePublicKey accepts the PKIX (SUBJECT PUBLIC KEY INFO) encoding cosign publishes a
// verification key in. A private key is detected and refused explicitly — a private key in
// the trust bundle is a custody failure, not a verification key — and anything else is refused
// as unparseable.
func parsePublicKey(der []byte) (*ecdsa.PublicKey, error) {
	if pub, err := x509.ParsePKIXPublicKey(der); err == nil {
		ec, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("public key is %T, want ECDSA", pub)
		}
		return ec, nil
	}
	if _, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return nil, fmt.Errorf("bundle carries a private key; only public keys belong here")
	}
	if _, err := x509.ParseECPrivateKey(der); err == nil {
		return nil, fmt.Errorf("bundle carries a private key; only public keys belong here")
	}
	return nil, fmt.Errorf("public key is not a parseable PKIX ECDSA key")
}

// KeyCount reports how many verification keys the bundle currently trusts. Rotation holds two
// keys during its overlap window (ADR-0044); this lets an operator assert that state.
func (tb *TrustBundle) KeyCount() int { return len(tb.keys) }

// Verify is the AC3 gate: it returns nil only when rel carries a signature that checks out
// against at least one pinned key over rel's canonical identity. It never touches the running
// version — a refusal is a decision, not an effect.
//
// The ordering is the security statement:
//   - a release with no identity to pin is malformed — nothing verifiable, nothing applicable;
//   - a release with no signature is unsigned — refused outright (local dev images are
//     unsigned and cannot represent an agent-applied release, ADR-0044);
//   - a signature that does not verify against ANY pinned key, or that verifies the wrong
//     identity, is mis-signed — refused.
func (tb *TrustBundle) Verify(rel api.SignedRelease) error {
	if rel.OCIRef == "" || rel.Digest == "" {
		return api.ErrReleaseMalformed
	}
	if len(rel.Signature) == 0 {
		return api.ErrReleaseUnsigned
	}
	hash := sha256.Sum256(rel.CanonicalIdentity())
	for _, key := range tb.keys {
		if ecdsa.VerifyASN1(key, hash[:], rel.Signature) {
			return nil
		}
	}
	return api.ErrReleaseMisSigned
}
