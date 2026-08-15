package custody

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/gitfrok/backend/modules/agent/api"
	"github.com/gitfrok/backend/platform/ids"
)

// custodyKey adapts one custody key REFERENCE onto crypto.Signer so x509
// certificate construction can sign through it. It is the single place where
// the seam meets the standard library: Public returns the custody-provided
// public half, and Sign ships a DIGEST across the seam and returns the
// signature. Private material has nowhere to appear here — there is none to
// hold.
type custodyKey struct {
	signer Signer
	ref    KeyRef
	pub    *ecdsa.PublicKey
}

var _ crypto.Signer = (*custodyKey)(nil)

// Public returns the custody key's public half — the only material this
// adapter ever possesses.
func (k *custodyKey) Public() crypto.PublicKey { return k.pub }

// Sign signs one digest through the custody seam. x509 passes an already-
// computed SHA-256 digest for ECDSA P-256; anything else is refused rather
// than re-hashed, so the seam's contract (digest in, signature out) cannot
// drift. The context is background because crypto.Signer has none: a
// cancelled issuance surfaces as the seam call's own failure.
func (k *custodyKey) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts.HashFunc() != crypto.SHA256 {
		return nil, fmt.Errorf("custody: only SHA-256 digests cross the seam, got %v", opts.HashFunc())
	}
	return k.signer.SignDigest(context.Background(), k.ref, digest)
}

// Issuer implements api.CertificateIssuer as a drop-in peer of pki.DevCA
// (ADR-0066: the seam already exists, so a custody-backed issuer is a
// composition-root swap, not an issuance-logic change). The difference is
// custody: DevCA holds a dev key in-process; Issuer holds key REFERENCES in
// a Bundle and signs every certificate through the custody seam
// (ADR-0064 decisions 1–2, SPEC-0044 AC1).
//
// Issuer is safe for concurrent issuance.
type Issuer struct {
	bundle *Bundle

	mu     sync.Mutex
	serial *big.Int
}

var _ api.CertificateIssuer = (*Issuer)(nil)

// NewIssuer issues through bundle. The bundle must already hold roots
// (Bootstrap or Restore) before the first Issue.
func NewIssuer(bundle *Bundle) (*Issuer, error) {
	if bundle == nil {
		return nil, errors.New("custody: nil bundle")
	}
	return &Issuer{bundle: bundle, serial: big.NewInt(1)}, nil
}

// Bundle exposes the issuer's staged trust bundle — the rotation surface the
// operator (and, later, the reconcile wiring) drives: Stage, RemoveRoot,
// Snapshot, Restore.
func (i *Issuer) Bundle() *Bundle { return i.bundle }

// CAPool returns the trust pool containing every LIVE root — the verifier
// side cmd/ wires into the gRPC server's mTLS configuration, same shape as
// DevCA.CAPool.
func (i *Issuer) CAPool() (*x509.CertPool, error) { return i.bundle.Pool() }

// Issue mints one short-lived client certificate naming the identity, signed
// through the bundle's NEWEST live root (AC2: during the overlap, new
// certificates chain to the new key). The returned PEM bundle is leaf + CA
// chain + the DATA PLANE's private key — the leaf key is the customer's
// credential delivered onto the channel, exactly as DevCA does; what custody
// changed is the ROOT's key, which never appears here at all (SPEC-0038 AC2
// secrecy applies to the bundle as written there).
func (i *Issuer) Issue(ctx context.Context, id api.Identity, now time.Time, lifetime, leeway time.Duration) (api.IssuedCertificate, error) {
	if id.TenantID == "" || id.DataPlaneID == "" {
		return api.IssuedCertificate{}, errors.New("custody: identity must name tenant and data plane")
	}
	ref, caCert, err := i.bundle.IssuanceRoot()
	if err != nil {
		return api.IssuedCertificate{}, err
	}
	pub, err := i.bundle.signer.PublicKey(ctx, ref)
	if err != nil {
		return api.IssuedCertificate{}, fmt.Errorf("custody: issue: %w", err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return api.IssuedCertificate{}, fmt.Errorf("custody: generate leaf key: %w", err)
	}
	i.mu.Lock()
	i.serial = new(big.Int).Add(i.serial, big.NewInt(1))
	serial := new(big.Int).Set(i.serial)
	i.mu.Unlock()

	// NotBefore backdated by the clock-skew leeway, NotAfter never extended —
	// the same window semantics DevCA documents (SPEC-0038 AC4).
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: subjectFor(id)},
		NotBefore:    now.Add(-leeway),
		NotAfter:     now.Add(lifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	signer := &custodyKey{signer: i.bundle.signer, ref: ref, pub: pub}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &leafKey.PublicKey, signer)
	if err != nil {
		return api.IssuedCertificate{}, fmt.Errorf("custody: issue leaf: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		return api.IssuedCertificate{}, fmt.Errorf("custody: marshal leaf key: %w", err)
	}
	var bundlePEM []byte
	bundlePEM = append(bundlePEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	bundlePEM = append(bundlePEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})...)
	bundlePEM = append(bundlePEM, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})...)

	certID := ids.NewULID()
	expiresAt := now.Add(lifetime)
	i.bundle.RecordIssuance(certID, ref, expiresAt)
	return api.IssuedCertificate{CertificateID: certID, PEM: bundlePEM, ExpiresAt: expiresAt}, nil
}

// Inspect recovers the identity and expiry from a leaf certificate, refusing
// anything no LIVE root of this control plane signed. During the overlap a
// leaf under the old root inspects exactly as one under the new.
func (i *Issuer) Inspect(leafDER []byte) (api.Identity, time.Time, error) {
	cert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return api.Identity{}, time.Time{}, fmt.Errorf("custody: unparsable leaf: %w", err)
	}
	for _, root := range i.bundle.Roots() {
		if root.RemovedAt.IsZero() && cert.CheckSignatureFrom(root.Cert) == nil {
			id, err := identityFromSubject(cert.Subject.CommonName)
			if err != nil {
				return api.Identity{}, time.Time{}, err
			}
			return id, cert.NotAfter, nil
		}
	}
	return api.Identity{}, time.Time{}, errors.New("custody: leaf not issued by this control plane")
}

// VerifyChain checks a peer chain against the LIVE roots at the given
// instant, with DevCA's exact discipline: TRUST FIRST, THEN THE WINDOW — a
// chain is classified expired/not-yet-valid only once some live root is
// known to have signed it; anything else is an error (SPEC-0038 AC5, AC7).
//
// Verification is a purely LOCAL act: it reads the pool the bundle already
// holds and never crosses the custody seam. That is the custody-outage
// guarantee SPEC-0044 names — a sealed or unreachable signer refuses
// ISSUANCE; certificates already issued keep validating until expiry.
func (i *Issuer) VerifyChain(rawCerts [][]byte, now time.Time) ([]byte, api.Validity, error) {
	if len(rawCerts) == 0 {
		return nil, api.ValidNow, errors.New("custody: no peer certificates")
	}
	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return nil, api.ValidNow, fmt.Errorf("custody: unparsable peer leaf: %w", err)
	}
	pool, err := i.bundle.Pool()
	if err != nil {
		return nil, api.ValidNow, err
	}
	intermediates := x509.NewCertPool()
	for _, raw := range rawCerts[1:] {
		if c, err := x509.ParseCertificate(raw); err == nil {
			intermediates.AddCert(c)
		}
	}
	verifyAt := func(instant time.Time) error {
		_, vErr := leaf.Verify(x509.VerifyOptions{
			Roots:         pool,
			Intermediates: intermediates,
			CurrentTime:   instant,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		})
		return vErr
	}
	if err := verifyAt(now); err == nil {
		return leaf.Raw, api.ValidNow, nil
	}
	// As DevCA: re-verify inside the leaf's own window to separate an
	// untrusted chain from a trusted one whose window does not contain now.
	inWindow := leaf.NotBefore.Add(leaf.NotAfter.Sub(leaf.NotBefore) / 2)
	if err := verifyAt(inWindow); err != nil {
		return nil, api.ValidNow, fmt.Errorf("custody: chain does not verify: %w", err)
	}
	if now.Before(leaf.NotBefore) {
		return leaf.Raw, api.ValidityNotYetValid, nil
	}
	return leaf.Raw, api.ValidityExpired, nil
}

// subjectFor / identityFromSubject mirror pki's subject encoding exactly, so
// the composition-root swap is transparent: a certificate issued under
// custody carries the same identity encoding the dev CA wrote. The encoding
// stays private to each adapter.
func subjectFor(id api.Identity) string { return id.TenantID + "/" + id.DataPlaneID }

func identityFromSubject(cn string) (api.Identity, error) {
	tenant, dataPlane, ok := strings.Cut(cn, "/")
	if !ok || tenant == "" || dataPlane == "" {
		return api.Identity{}, errors.New("custody: subject does not name an identity")
	}
	return api.Identity{TenantID: tenant, DataPlaneID: dataPlane}, nil
}
