// Package pki is the Agent context's certificate adapter: a control-plane CA that issues,
// inspects and verifies the short-lived client certificates an enrolled data plane
// authenticates with (ADR-0060 §2).
//
// This is the DEV/TEST custody of the CA key: an in-process ECDSA key. Production key
// custody is explicitly NOT decided here (ADR-0057 follow-up); swapping this adapter for a
// custody-backed issuer is a composition-root change, not a contract change.
package pki

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/gitfrok/backend/modules/agent/api"
	"github.com/gitfrok/backend/platform/ids"
)

// DevCA is an in-process certificate authority. It is safe for concurrent issuance.
type DevCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
	now  func() time.Time

	mu     sync.Mutex
	serial *big.Int
}

var _ api.CertificateIssuer = (*DevCA)(nil)

// NewDevCA generates one fresh CA key and self-signed certificate. The key never leaves
// this process; that is precisely why this constructor is dev/test custody only.
func NewDevCA(commonName string, now func() time.Time) (*DevCA, error) {
	if now == nil {
		return nil, errors.New("pki: nil clock")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("pki: generate ca key: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now().Add(-time.Hour),
		NotAfter:              now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("pki: self-sign ca: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("pki: parse ca: %w", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &DevCA{cert: cert, key: key, pool: pool, now: now, serial: big.NewInt(1)}, nil
}

// CAPool returns the trust pool containing the CA certificate — the verifier side that
// cmd/ wires into the gRPC server's mTLS configuration.
func (ca *DevCA) CAPool() *x509.CertPool { return ca.pool }

// Issue mints one short-lived client certificate naming the identity (SPEC-0038 AC3: the
// certificate names the tenant and the data plane). The returned PEM bundle is the whole
// credential — leaf, CA chain, private key — and travels only onto the channel that
// presented it; the caller must never log or persist it (AC2).
func (ca *DevCA) Issue(_ context.Context, id api.Identity, now time.Time, lifetime, leeway time.Duration) (api.IssuedCertificate, error) {
	if id.TenantID == "" || id.DataPlaneID == "" {
		return api.IssuedCertificate{}, errors.New("pki: identity must name tenant and data plane")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return api.IssuedCertificate{}, fmt.Errorf("pki: generate leaf key: %w", err)
	}
	ca.mu.Lock()
	ca.serial = new(big.Int).Add(ca.serial, big.NewInt(1))
	serial := new(big.Int).Set(ca.serial)
	ca.mu.Unlock()

	// NotBefore is backdated by the clock-skew leeway: a mildly skewed customer cluster
	// clock must not reject a freshly issued certificate. NotAfter is the rotation
	// deadline and is never extended (SPEC-0038 AC4).
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: subjectFor(id)},
		NotBefore:    now.Add(-leeway),
		NotAfter:     now.Add(lifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return api.IssuedCertificate{}, fmt.Errorf("pki: issue leaf: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return api.IssuedCertificate{}, fmt.Errorf("pki: marshal leaf key: %w", err)
	}
	var bundle []byte
	bundle = append(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	bundle = append(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})...)
	bundle = append(bundle, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})...)
	return api.IssuedCertificate{
		CertificateID: ids.NewULID(),
		PEM:           bundle,
		ExpiresAt:     now.Add(lifetime),
	}, nil
}

// IssueServer mints the gRPC SERVER certificate for a dev/test composition, signed by the
// same CA so clients can verify it through the normal trust pool. It is not part of the
// agent identity surface: no data plane ever authenticates with it.
func (ca *DevCA) IssueServer(commonName string, dnsNames []string, now time.Time, lifetime time.Duration) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("pki: generate server key: %w", err)
	}
	ca.mu.Lock()
	ca.serial = new(big.Int).Add(ca.serial, big.NewInt(1))
	serial := new(big.Int).Set(ca.serial)
	ca.mu.Unlock()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		DNSNames:     dnsNames,
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(lifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("pki: issue server cert: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("pki: marshal server key: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return tls.X509KeyPair(certPEM, keyPEM)
}

// Inspect recovers the identity and expiry from a leaf certificate, refusing anything this
// CA did not sign. It takes DER, the form gRPC surfaces after mTLS verification.
func (ca *DevCA) Inspect(leafDER []byte) (api.Identity, time.Time, error) {
	cert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return api.Identity{}, time.Time{}, fmt.Errorf("pki: unparsable leaf: %w", err)
	}
	if err := cert.CheckSignatureFrom(ca.cert); err != nil {
		return api.Identity{}, time.Time{}, errors.New("pki: leaf not issued by this ca")
	}
	id, err := identityFromSubject(cert.Subject.CommonName)
	if err != nil {
		return api.Identity{}, time.Time{}, err
	}
	return id, cert.NotAfter, nil
}

// VerifyChain checks a peer chain against this CA at the given instant.
//
// TRUST FIRST, THEN THE WINDOW. A chain is only ever classified as expired or not-yet-valid
// once this CA is known to have signed it; anything else is an error. The order matters: a
// forged, self-signed certificate carrying a victim's subject is outside its window as
// easily as inside it, and classifying before verifying would hand such a leaf back with no
// error at all. Admission then refuses both non-valid states and audits them, rather than
// treating a rotation that did not happen — or a skewed cluster clock — like an attack
// (SPEC-0038 AC5, AC7).
func (ca *DevCA) VerifyChain(rawCerts [][]byte, now time.Time) ([]byte, api.Validity, error) {
	if len(rawCerts) == 0 {
		return nil, api.ValidNow, errors.New("pki: no peer certificates")
	}
	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return nil, api.ValidNow, fmt.Errorf("pki: unparsable peer leaf: %w", err)
	}
	intermediates := x509.NewCertPool()
	for _, raw := range rawCerts[1:] {
		if c, err := x509.ParseCertificate(raw); err == nil {
			intermediates.AddCert(c)
		}
	}
	verifyAt := func(instant time.Time) error {
		_, vErr := leaf.Verify(x509.VerifyOptions{
			Roots:         ca.pool,
			Intermediates: intermediates,
			CurrentTime:   instant,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		})
		return vErr
	}
	if err := verifyAt(now); err == nil {
		return leaf.Raw, api.ValidNow, nil
	}
	// The chain did not verify AT NOW. Re-verify at an instant inside the leaf's own window
	// to separate the two reasons that can cause: an untrusted chain, or a trusted one whose
	// window does not contain now. Only the second is a classification.
	inWindow := leaf.NotBefore.Add(leaf.NotAfter.Sub(leaf.NotBefore) / 2)
	if err := verifyAt(inWindow); err != nil {
		return nil, api.ValidNow, fmt.Errorf("pki: chain does not verify: %w", err)
	}
	if now.Before(leaf.NotBefore) {
		return leaf.Raw, api.ValidityNotYetValid, nil
	}
	return leaf.Raw, api.ValidityExpired, nil
}

// subjectFor encodes the identity into the certificate subject; identityFromSubject is its
// inverse. The encoding is private to this adapter.
func subjectFor(id api.Identity) string { return id.TenantID + "/" + id.DataPlaneID }

func identityFromSubject(cn string) (api.Identity, error) {
	tenant, dataPlane, ok := strings.Cut(cn, "/")
	if !ok || tenant == "" || dataPlane == "" {
		return api.Identity{}, errors.New("pki: subject does not name an identity")
	}
	return api.Identity{TenantID: tenant, DataPlaneID: dataPlane}, nil
}
