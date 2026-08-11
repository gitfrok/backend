package domain

import (
	"strings"
	"testing"
	"time"
)

func TestPATRevocationDeniesNextAuthentication(t *testing.T) {
	s := NewService([]byte("test-key"))
	meta, token, err := s.IssuePAT("tenant-a", "actor-a", "ci", []string{"repo.read"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	p, ok := s.AuthenticatePAT(token)
	if !ok || p.TenantID != "tenant-a" || p.ActorID != "actor-a" {
		t.Fatalf("principal=%+v ok=%v", p, ok)
	}
	if err := s.RevokePAT("tenant-a", "actor-a", meta.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.AuthenticatePAT(token); ok {
		t.Fatal("revoked token authenticated")
	}
}

func TestPATDoesNotCrossTenant(t *testing.T) {
	s := NewService([]byte("test-key"))
	meta, _, err := s.IssuePAT("tenant-a", "actor-a", "ci", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RevokePAT("tenant-b", "actor-a", meta.ID); err == nil {
		t.Fatal("cross-tenant revoke succeeded")
	}
}

func TestSSHKeyAuthenticatesToSamePrincipalShape(t *testing.T) {
	s := NewService([]byte("test-key"))
	if err := s.RegisterSSHKey("ssh-ed25519 AAA", "default", "tenant-a", "actor-a", []string{"developer"}); err != nil {
		t.Fatal(err)
	}
	p, ok := s.AuthenticateSSHKey("ssh-ed25519 AAA", "default")
	if !ok || p.TenantID != "tenant-a" || p.ActorID != "actor-a" {
		t.Fatalf("principal=%+v ok=%v", p, ok)
	}
	if _, ok := s.AuthenticateSSHKey("ssh-ed25519 unknown", "default"); ok {
		t.Fatal("unknown key authenticated")
	}
}

func TestListPATsIsTenantAndActorScoped(t *testing.T) {
	s := NewService([]byte("test-key"))
	if _, _, err := s.IssuePAT("tenant-a", "actor-a", "a", nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.IssuePAT("tenant-b", "actor-b", "b", nil, nil); err != nil {
		t.Fatal(err)
	}
	if got := s.ListPATs("tenant-a", "actor-a"); len(got) != 1 || got[0].TenantID != "tenant-a" {
		t.Fatalf("got=%+v", got)
	}
	if got := s.ListPATs("tenant-a", "actor-b"); len(got) != 0 {
		t.Fatalf("cross actor got=%+v", got)
	}
}

// SPEC-0016 AC6: roles granted at issuance resolve on every authentication
// and appear on issued/list metadata, never the plaintext.
func TestPATRolesRoundTripThroughIssueAuthenticateAndList(t *testing.T) {
	s := NewService([]byte("test-key"))
	meta, token, err := s.IssuePAT("tenant-a", "actor-a", "ci", []string{"repo.read"}, []string{"developer", "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if len(meta.Roles) != 2 || meta.Roles[0] != "developer" || meta.Roles[1] != "admin" {
		t.Fatalf("issued metadata roles = %#v", meta.Roles)
	}
	p, ok := s.AuthenticatePAT(token)
	if !ok || len(p.Roles) != 2 || p.Roles[0] != "developer" || p.Roles[1] != "admin" {
		t.Fatalf("authenticated roles = %#v ok=%v", p.Roles, ok)
	}
	listed := s.ListPATs("tenant-a", "actor-a")
	if len(listed) != 1 || len(listed[0].Roles) != 2 || listed[0].Roles[0] != "developer" {
		t.Fatalf("listed roles = %#v", listed)
	}
	if strings.HasPrefix(token, "gfp_") && strings.Contains(token, "admin") {
		t.Fatal("plaintext token leaked role material")
	}
}

// SPEC-0016 AC4: expiry denies the very next authentication decision.  The
// clock is injected so this is a boundary test, not a sleep-based race.
func TestExpiredPATDeniesAuthentication(t *testing.T) {
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	s := NewServiceWithClock([]byte("test-key"), func() time.Time { return now })
	expiresAt := now.Add(time.Minute)
	_, token, err := s.IssuePAT("tenant-a", "actor-a", "ci", nil, nil, &expiresAt)
	if err != nil {
		t.Fatal(err)
	}
	now = expiresAt
	if _, ok := s.AuthenticatePAT(token); ok {
		t.Fatal("expired token authenticated")
	}
}

// SPEC-0016 AC4 applies equally to SSH credentials.
func TestRevokedSSHKeyDeniesNextAuthentication(t *testing.T) {
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	s := NewServiceWithClock([]byte("test-key"), func() time.Time { return now })
	const key = "ssh-ed25519 AAA"
	if err := s.RegisterSSHKey(key, "default", "tenant-a", "actor-a", []string{"developer"}); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeSSHKey("tenant-a", "actor-a", key, "default"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.AuthenticateSSHKey(key, "default"); ok {
		t.Fatal("revoked SSH key authenticated")
	}
}

// SPEC-0022 AC2/AC3: the configured key ID selects one verifier namespace;
// a key registered under another active ID cannot authenticate by probing it.
func TestSSHKeyRequiresMatchingVerifierKeyID(t *testing.T) {
	s := NewService([]byte("test-key"))
	const key = "ssh-ed25519 AAA"
	if err := s.RegisterSSHKey(key, "default", "tenant-a", "actor-a", []string{"developer"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.AuthenticateSSHKey(key, "key-2"); ok {
		t.Fatal("key authenticated through a different verifier key ID")
	}
}

// ADR-0043 / SPEC-0022 AC3: key IDs select one verifier key in O(1). A
// rotation keeps existing credentials usable only while their key remains in
// the configured ring; retiring it denies the very next use without probing.
func TestVerifierKeyRotationKeepsThenRetiresOldCredentials(t *testing.T) {
	s := NewServiceWithKeyRing("old", map[string][]byte{
		"old": []byte("old-key"),
		"new": []byte("new-key"),
	}, time.Now)
	_, oldToken, err := s.IssuePAT("tenant-a", "actor-a", "old", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(oldToken, "gfp_old_") {
		t.Fatalf("old token = %q, want public old key ID prefix", oldToken)
	}
	if err := s.ActivateVerifierKey("new"); err != nil {
		t.Fatal(err)
	}
	_, newToken, err := s.IssuePAT("tenant-a", "actor-a", "new", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(newToken, "gfp_new_") {
		t.Fatalf("new token = %q, want public new key ID prefix", newToken)
	}
	if _, ok := s.AuthenticatePAT(oldToken); !ok {
		t.Fatal("old active-key credential denied during rotation overlap")
	}
	if err := s.RetireVerifierKey("old"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.AuthenticatePAT(oldToken); ok {
		t.Fatal("retired-key credential authenticated")
	}
	if _, ok := s.AuthenticatePAT(newToken); !ok {
		t.Fatal("new-key credential denied after old-key retirement")
	}
}

// SPEC-0016 AC1/AC5: list metadata never exposes the verifier or plaintext.
func TestPATMetadataCarriesLifecycleButNeverVerifier(t *testing.T) {
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	s := NewServiceWithClock([]byte("test-key"), func() time.Time { return now })
	expiresAt := now.Add(time.Hour)
	issued, _, err := s.IssuePAT("tenant-a", "actor-a", "ci", []string{"repo.read"}, nil, &expiresAt)
	if err != nil {
		t.Fatal(err)
	}
	if issued.CreatedAt != now || issued.ExpiresAt == nil || !issued.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("issued lifecycle metadata = %+v", issued)
	}
	if issued.verifier != "" {
		t.Fatal("issuance metadata exposed verifier")
	}
	if err := s.RevokePAT("tenant-a", "actor-a", issued.ID); err != nil {
		t.Fatal(err)
	}
	got := s.ListPATs("tenant-a", "actor-a")
	if len(got) != 1 || got[0].RevokedAt == nil || got[0].verifier != "" {
		t.Fatalf("listed metadata = %+v", got)
	}
}
