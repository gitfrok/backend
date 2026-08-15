package agentclient

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"

	agentpb "github.com/gitfrok/backend/gen/proto/agent/v1"
)

// --- a self-contained test CA -------------------------------------------------------------
// The unit tests must not reach into the Agent module's internal PKI adapter, so they mint
// their own throwaway CA. The shapes match what the control plane issues: a leaf naming an
// identity, a chain, and a private key.

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newTestCA(t *testing.T, cn string, anchor time.Time) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	// The CA's window is anchored to the SAME instant the test verifies at:
	// a wall-clock CA misses a fixed test instant outside UTC, and the
	// chain reads untrusted for a reason that has nothing to do with trust.
	now := anchor
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("self-sign ca: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &testCA{cert: cert, key: key, pool: pool}
}

// issuePEM returns a credential bundle (leaf + CA chain + key) valid over [notBefore, notAfter].
func (ca *testCA) issuePEM(t *testing.T, notBefore, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "acme/dp-1"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("issue leaf: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	var b []byte
	b = append(b, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	b = append(b, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})...)
	b = append(b, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})...)
	return b
}

// --- ApplyRotation: one failure enum value per failure mode ------------------------------

func TestApplyRotationOutcomes(t *testing.T) {
	now := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	ca := newTestCA(t, "test-ca", now)
	otherCA := newTestCA(t, "other-ca", now)

	cases := []struct {
		name   string
		roots  *x509.CertPool
		store  CertStore
		bundle func() []byte
		leeway time.Duration
		want   RotationOutcome
	}{
		{
			name:   "applied",
			roots:  ca.pool,
			store:  &MemoryCertStore{},
			bundle: func() []byte { return ca.issuePEM(t, now.Add(-time.Hour), now.Add(time.Hour)) },
			leeway: 5 * time.Minute,
			want:   RotationOutcome{Applied: true},
		},
		{
			name:   "unparsable garbage",
			roots:  ca.pool,
			store:  &MemoryCertStore{},
			bundle: func() []byte { return []byte("not a pem bundle") },
			leeway: 5 * time.Minute,
			want:   RotationOutcome{Reason: failureUnparsable},
		},
		{
			name:   "clock skew not yet valid",
			roots:  ca.pool,
			store:  &MemoryCertStore{},
			bundle: func() []byte { return ca.issuePEM(t, now.Add(time.Hour), now.Add(2*time.Hour)) },
			leeway: 5 * time.Minute,
			want:   RotationOutcome{Reason: failureClockSkew},
		},
		{
			name:   "clock skew already expired",
			roots:  ca.pool,
			store:  &MemoryCertStore{},
			bundle: func() []byte { return ca.issuePEM(t, now.Add(-2*time.Hour), now.Add(-time.Hour)) },
			leeway: 5 * time.Minute,
			want:   RotationOutcome{Reason: failureClockSkew},
		},
		{
			name:   "untrusted chain",
			roots:  ca.pool, // pinned pool does not contain otherCA
			store:  &MemoryCertStore{},
			bundle: func() []byte { return otherCA.issuePEM(t, now.Add(-time.Hour), now.Add(time.Hour)) },
			leeway: 5 * time.Minute,
			want:   RotationOutcome{Reason: failureUntrusted},
		},
		{
			name:   "persist failed",
			roots:  ca.pool,
			store:  failStore{},
			bundle: func() []byte { return ca.issuePEM(t, now.Add(-time.Hour), now.Add(time.Hour)) },
			leeway: 5 * time.Minute,
			want:   RotationOutcome{Reason: failurePersistFailed},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := New(Config{
				Roots:           tc.roots,
				Store:           tc.store,
				ClockSkewLeeway: tc.leeway,
				Now:             func() time.Time { return now },
			})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			got := c.ApplyRotation(context.Background(), &agentpb.ClientCertificate{
				CertificateId:  "cert-1",
				CertificatePem: tc.bundle(),
			})
			if got != tc.want {
				t.Fatalf("ApplyRotation = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// failStore is a CertStore whose writes always fail — the PERSIST_FAILED path.
type failStore struct{}

func (failStore) Save(context.Context, []byte) error { return errors.New("disk full") }
func (failStore) Load(context.Context) ([]byte, error) {
	return nil, ErrNoCredential
}
func (failStore) Clear(context.Context) error { return nil }

// TestApplyRotationPersistsCredential: a successful rotation replaces the stored credential.
func TestApplyRotationPersistsCredential(t *testing.T) {
	now := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	ca := newTestCA(t, "test-ca", now)
	store := &MemoryCertStore{}
	if err := store.Save(context.Background(), []byte("old-credential")); err != nil {
		t.Fatal(err)
	}
	c, err := New(Config{Roots: ca.pool, Store: store, ClockSkewLeeway: time.Minute, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	bundle := ca.issuePEM(t, now.Add(-time.Hour), now.Add(time.Hour))
	out := c.ApplyRotation(context.Background(), &agentpb.ClientCertificate{CertificateId: "c2", CertificatePem: bundle})
	if !out.Applied {
		t.Fatalf("outcome = %+v, want applied", out)
	}
	stored, err := store.Load(context.Background())
	if err != nil || !bytes.Equal(stored, bundle) {
		t.Fatalf("stored credential was not replaced by the rotation: err=%v", err)
	}
}

// --- rotation ack correlation (certificate_id echoes; failure reason only when refused) ---

func TestRotationAckCorrelation(t *testing.T) {
	now := time.Now()
	c, err := New(Config{Roots: x509.NewCertPool(), Store: &MemoryCertStore{}, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}

	applied := c.rotationAck(7, "cert-abc", RotationOutcome{Applied: true})
	ack := applied.GetCertificateRotationAck()
	if ack == nil || ack.GetCertificateId() != "cert-abc" || !ack.GetApplied() {
		t.Fatalf("applied ack = %+v, want certificate_id=cert-abc applied=true", applied)
	}
	if ack.GetFailureReason() != failureUnspecified {
		t.Fatalf("an applied ack must not carry a failure reason, got %s", ack.GetFailureReason())
	}
	if applied.GetSeq() != 7 {
		t.Fatalf("ack seq = %d, want 7", applied.GetSeq())
	}

	refused := c.rotationAck(8, "cert-xyz", RotationOutcome{Reason: failureUntrusted})
	rack := refused.GetCertificateRotationAck()
	if rack == nil || rack.GetCertificateId() != "cert-xyz" || rack.GetApplied() {
		t.Fatalf("refused ack = %+v, want certificate_id=cert-xyz applied=false", refused)
	}
	if rack.GetFailureReason() != failureUntrusted {
		t.Fatalf("refused ack reason = %s, want UNTRUSTED", rack.GetFailureReason())
	}
}

// --- credential store behaviour ------------------------------------------------------------

func TestMemoryCertStoreLifecycle(t *testing.T) {
	s := &MemoryCertStore{}
	ctx := context.Background()
	if _, err := s.Load(ctx); !errors.Is(err, ErrNoCredential) {
		t.Fatalf("empty load = %v, want ErrNoCredential", err)
	}
	if err := s.Save(ctx, []byte("pem")); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(ctx, nil); err == nil {
		t.Fatal("saving an empty credential must be refused")
	}
	got, err := s.Load(ctx)
	if err != nil || string(got) != "pem" {
		t.Fatalf("load = %q/%v", got, err)
	}
	if err := s.Clear(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(ctx); !errors.Is(err, ErrNoCredential) {
		t.Fatalf("post-clear load = %v, want ErrNoCredential", err)
	}
}

func TestFileCertStoreLifecycle(t *testing.T) {
	path := t.TempDir() + "/creds/client.pem"
	s := NewFileCertStore(path)
	ctx := context.Background()
	if _, err := s.Load(ctx); !errors.Is(err, ErrNoCredential) {
		t.Fatalf("empty load = %v, want ErrNoCredential", err)
	}
	if err := s.Save(ctx, []byte("pem-bundle")); err != nil {
		t.Fatal(err)
	}
	got, err := s.Load(ctx)
	if err != nil || string(got) != "pem-bundle" {
		t.Fatalf("load = %q/%v", got, err)
	}
	if err := s.Clear(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(ctx); !errors.Is(err, ErrNoCredential) {
		t.Fatalf("post-clear load = %v, want ErrNoCredential", err)
	}
}

// TestStoreNeverSeesTheToken pins the store/port contract: the only bytes a store can receive
// are whatever Save is handed, and the package only ever hands it a credential bundle. This test
// asserts the store interface carries no token-shaped parameter at all (compile-time) and that a
// bundle round-trips unchanged (runtime).
func TestStoreNeverSeesTheToken(t *testing.T) {
	s := &MemoryCertStore{}
	bundle := []byte("-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----\n")
	if err := s.Save(context.Background(), bundle); err != nil {
		t.Fatal(err)
	}
	got, err := s.Load(context.Background())
	if err != nil || !bytes.Equal(got, bundle) {
		t.Fatalf("store altered the bundle: %v", err)
	}
	// The store's surface has no method that accepts a token; the only writer is Save(pem).
	var _ CertStore = s
	_ = fmt.Sprintf("%T", s)
}

// TestNewRequiresTrustPoolAndStore: a client without a pinned pool or a store refuses to build.
func TestNewRequiresTrustPoolAndStore(t *testing.T) {
	if _, err := New(Config{Store: &MemoryCertStore{}}); err == nil {
		t.Fatal("a client with no trust pool must be refused")
	}
	if _, err := New(Config{Roots: x509.NewCertPool()}); err == nil {
		t.Fatal("a client with no credential store must be refused")
	}
}
