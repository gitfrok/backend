package pki

import (
	"bytes"
	"context"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/gitfrok/backend/modules/agent/api"
)

func newTestCA(t *testing.T, now time.Time) *DevCA {
	t.Helper()
	ca, err := NewDevCA("dev-enrolment-ca", func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewDevCA: %v", err)
	}
	return ca
}

// firstLeafDER extracts the leaf certificate from an issued PEM bundle.
func firstLeafDER(t *testing.T, pemBytes []byte) []byte {
	t.Helper()
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("issued PEM does not start with a certificate block")
	}
	return block.Bytes
}

func TestIssueInspectRoundTrip(t *testing.T) {
	now := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	ca := newTestCA(t, now)
	id := api.Identity{TenantID: "acme", DataPlaneID: "dp-1"}

	cert, err := ca.Issue(context.Background(), id, now, time.Hour, 5*time.Minute)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if cert.CertificateID == "" || len(cert.PEM) == 0 {
		t.Fatalf("issued certificate is empty: %+v", cert)
	}
	if !cert.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("ExpiresAt = %v, want %v", cert.ExpiresAt, now.Add(time.Hour))
	}

	gotID, gotExpiry, err := ca.Inspect(firstLeafDER(t, cert.PEM))
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if gotID != id {
		t.Fatalf("Inspect identity = %+v, want %+v", gotID, id)
	}
	if !gotExpiry.Equal(cert.ExpiresAt) {
		t.Fatalf("Inspect expiry = %v, want %v", gotExpiry, cert.ExpiresAt)
	}

	// The bundle carries the private key and the CA chain — the credential the agent persists.
	rest := cert.PEM
	var kinds []string
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		kinds = append(kinds, block.Type)
	}
	if len(kinds) < 3 || !strings.HasSuffix(kinds[1], "CERTIFICATE") {
		t.Fatalf("PEM bundle blocks = %v, want leaf, chain, key", kinds)
	}
}

func TestVerifyChainTrustAndExpiry(t *testing.T) {
	now := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	ca := newTestCA(t, now)
	id := api.Identity{TenantID: "acme", DataPlaneID: "dp-1"}
	cert, err := ca.Issue(context.Background(), id, now, time.Hour, 0)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	leaf := firstLeafDER(t, cert.PEM)

	// Trusted and unexpired.
	gotLeaf, expired, err := ca.VerifyChain([][]byte{leaf}, now.Add(30*time.Minute))
	if err != nil || expired || !bytes.Equal(gotLeaf, leaf) {
		t.Fatalf("VerifyChain = %x, expired=%v, err=%v; want trusted leaf", gotLeaf, expired, err)
	}

	// Trusted chain, expired certificate: distinguishable, not an opaque failure (the
	// admission path audits and refuses it — SPEC-0038 AC5).
	_, expired, err = ca.VerifyChain([][]byte{leaf}, now.Add(2*time.Hour))
	if err != nil || !expired {
		t.Fatalf("VerifyChain of expired cert = expired=%v, err=%v; want expired=true, no error", expired, err)
	}

	// Clock skew leeway backdates NotBefore, so a mildly skewed clock accepts a fresh cert.
	skewed, err := ca.Issue(context.Background(), id, now, time.Hour, 5*time.Minute)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, _, err := ca.VerifyChain([][]byte{firstLeafDER(t, skewed.PEM)}, now.Add(-2*time.Minute)); err != nil {
		t.Fatalf("fresh cert rejected by a 2-minute-behind clock: %v", err)
	}
}

func TestVerifyChainRejectsForeignCAs(t *testing.T) {
	now := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	ours := newTestCA(t, now)
	rogue := newTestCA(t, now)
	id := api.Identity{TenantID: "acme", DataPlaneID: "dp-1"}

	rogueCert, err := rogue.Issue(context.Background(), id, now, time.Hour, 0)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, _, err := ours.VerifyChain([][]byte{firstLeafDER(t, rogueCert.PEM)}, now); err == nil {
		t.Fatal("a certificate from another CA must not verify")
	}
	if _, _, err := ours.VerifyChain(nil, now); err == nil {
		t.Fatal("an empty chain must not verify")
	}
	if _, _, err := ours.VerifyChain([][]byte{[]byte("garbage")}, now); err == nil {
		t.Fatal("an unparsable leaf must not verify")
	}
}

func TestInspectRejectsForeignCertificates(t *testing.T) {
	now := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	ca := newTestCA(t, now)
	if _, _, err := ca.Inspect([]byte("garbage")); err == nil {
		t.Fatal("an unparsable leaf must not inspect")
	}

	// A certificate minted by another CA — naming an identity it was never granted — is
	// not one of ours, whatever its subject claims.
	foreign := selfSigned(t, now)
	if _, _, err := ca.Inspect(foreign); err == nil {
		t.Fatal("a certificate not issued by this CA must not inspect")
	}
}

// selfSigned mints a certificate outside the CA's trust for adversarial tests.
func selfSigned(t *testing.T, now time.Time) []byte {
	t.Helper()
	rogue := newTestCA(t, now)
	cert, err := rogue.Issue(context.Background(), api.Identity{TenantID: "acme", DataPlaneID: "dp-evil"}, now, time.Hour, 0)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	return firstLeafDER(t, cert.PEM)
}

var _ api.CertificateIssuer = (*DevCA)(nil)
