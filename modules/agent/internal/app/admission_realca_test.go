package app

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/gitfrok/backend/modules/agent/api"
	"github.com/gitfrok/backend/modules/agent/internal/adapters/memory"
	"github.com/gitfrok/backend/modules/agent/internal/adapters/pki"
)

// The admission path's other tests run on a fake issuer, which is what let the phase-3
// review's H1 through: the real CA's verification was never exercised above the adapter.
// This file admits against the REAL DevCA, so a change that makes the CA lenient fails
// here rather than in a customer's cluster.
func realCAHarness(t *testing.T, now time.Time) (*Service, *pki.DevCA) {
	t.Helper()
	clock := func() time.Time { return now }
	ca, err := pki.NewDevCA("admission-test-ca", clock)
	if err != nil {
		t.Fatalf("NewDevCA: %v", err)
	}
	cfg := api.Config{
		CertLifetime: time.Hour, RotationLead: 20 * time.Minute, RotationRetryInterval: time.Minute,
		StaleAfter: 5 * time.Minute, TokenMaxLifetime: 24 * time.Hour,
		HeartbeatInterval: 30 * time.Second, ClockSkewLeeway: 5 * time.Minute, Now: clock,
	}
	svc := New(&stubPDP{allow: true}, &captureBus{}, ca, memory.New(), memory.New(), cfg, func(string, ...any) {})
	return svc, ca
}

// enrolOne brings up one legitimately enrolled data plane and returns its identity.
func enrolOne(t *testing.T, svc *Service, tenant string) api.Identity {
	t.Helper()
	_, secret, err := svc.IssueEnrolmentToken(operatorCtx(tenant, "owner-1"), tenant, "owner-1", time.Hour)
	if err != nil {
		t.Fatalf("IssueEnrolmentToken: %v", err)
	}
	enr, err := svc.Enrol(context.Background(), api.EnrolRequest{Token: secret, Cloud: "gke", Region: "eu-west1"})
	if err != nil {
		t.Fatalf("Enrol: %v", err)
	}
	return enr.Identity
}

// selfSigned forges a leaf carrying someone else's identity, with a window the caller picks.
func selfSigned(t *testing.T, id api.Identity, notBefore, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: id.TenantID + "/" + id.DataPlaneID},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// leafDER pulls the first certificate out of an issued PEM bundle.
func leafDER(t *testing.T, pemBytes []byte) []byte {
	t.Helper()
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("no PEM block in the issued bundle")
	}
	return block.Bytes
}

// SPEC-0038 AC3/AC5: a forged certificate is refused whatever window it carries — including
// the windows that used to make VerifyChain answer with no error (review H1).
func TestAdmissionRefusesForgedCertificatesInEveryWindow(t *testing.T) {
	now := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	svc, _ := realCAHarness(t, now)
	victim := enrolOne(t, svc, "tenant-a")

	for _, tc := range []struct {
		name                string
		notBefore, notAfter time.Time
	}{
		{"inside its window", now.Add(-time.Hour), now.Add(time.Hour)},
		{"not yet valid", now.Add(time.Hour), now.Add(2 * time.Hour)},
		{"expired", now.Add(-2 * time.Hour), now.Add(-time.Hour)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			der := selfSigned(t, victim, tc.notBefore, tc.notAfter)
			id, err := svc.AdmitPeerCertificates(context.Background(), [][]byte{der})
			if err == nil {
				t.Fatalf("a forged certificate was admitted as %s/%s", id.TenantID, id.DataPlaneID)
			}
		})
	}
}

// A certificate this CA issued is admitted inside its window, refused outside it — and the
// not-yet-valid refusal is audited apart from expiry, because it is the clock-skew story.
func TestAdmissionHonoursTheRealValidityWindow(t *testing.T) {
	now := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	svc, ca := realCAHarness(t, now)
	id := enrolOne(t, svc, "tenant-a")

	live, err := ca.Issue(context.Background(), id, now, time.Hour, 0)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	admitted, err := svc.AdmitPeerCertificates(context.Background(), [][]byte{leafDER(t, live.PEM)})
	if err != nil {
		t.Fatalf("a live certificate must be admitted: %v", err)
	}
	if admitted != id {
		t.Fatalf("admitted identity = %+v, want %+v", admitted, id)
	}

	future, err := ca.Issue(context.Background(), id, now.Add(2*time.Hour), time.Hour, 0)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := svc.AdmitPeerCertificates(context.Background(), [][]byte{leafDER(t, future.PEM)}); err == nil {
		t.Fatal("a certificate presented before its NotBefore must be refused")
	}
}
