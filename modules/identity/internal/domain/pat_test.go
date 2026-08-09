package domain

import (
	"testing"
	"time"
)

func TestPATRevocationDeniesNextAuthentication(t *testing.T) {
	s := NewService([]byte("test-key"))
	meta, token, err := s.IssuePAT("tenant-a", "actor-a", "ci", []string{"repo.read"})
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
	meta, _, err := s.IssuePAT("tenant-a", "actor-a", "ci", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RevokePAT("tenant-b", "actor-a", meta.ID); err == nil {
		t.Fatal("cross-tenant revoke succeeded")
	}
}

func TestSSHKeyAuthenticatesToSamePrincipalShape(t *testing.T) {
	s := NewService([]byte("test-key"))
	if err := s.RegisterSSHKey("ssh-ed25519 AAA", "tenant-a", "actor-a", []string{"developer"}); err != nil {
		t.Fatal(err)
	}
	p, ok := s.AuthenticateSSHKey("ssh-ed25519 AAA")
	if !ok || p.TenantID != "tenant-a" || p.ActorID != "actor-a" {
		t.Fatalf("principal=%+v ok=%v", p, ok)
	}
	if _, ok := s.AuthenticateSSHKey("ssh-ed25519 unknown"); ok {
		t.Fatal("unknown key authenticated")
	}
}

func TestListPATsIsTenantAndActorScoped(t *testing.T) {
	s := NewService([]byte("test-key"))
	if _, _, err := s.IssuePAT("tenant-a", "actor-a", "a", nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.IssuePAT("tenant-b", "actor-b", "b", nil); err != nil {
		t.Fatal(err)
	}
	if got := s.ListPATs("tenant-a", "actor-a"); len(got) != 1 || got[0].TenantID != "tenant-a" {
		t.Fatalf("got=%+v", got)
	}
	if got := s.ListPATs("tenant-a", "actor-b"); len(got) != 0 {
		t.Fatalf("cross actor got=%+v", got)
	}
}

// SPEC-0016 AC4: expiry denies the very next authentication decision.  The
// clock is injected so this is a boundary test, not a sleep-based race.
func TestExpiredPATDeniesAuthentication(t *testing.T) {
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	s := NewServiceWithClock([]byte("test-key"), func() time.Time { return now })
	expiresAt := now.Add(time.Minute)
	_, token, err := s.IssuePAT("tenant-a", "actor-a", "ci", nil, &expiresAt)
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
	if err := s.RegisterSSHKey(key, "tenant-a", "actor-a", []string{"developer"}); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeSSHKey("tenant-a", "actor-a", key); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.AuthenticateSSHKey(key); ok {
		t.Fatal("revoked SSH key authenticated")
	}
}

// SPEC-0016 AC1/AC5: list metadata never exposes the verifier or plaintext.
func TestPATMetadataCarriesLifecycleButNeverVerifier(t *testing.T) {
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	s := NewServiceWithClock([]byte("test-key"), func() time.Time { return now })
	expiresAt := now.Add(time.Hour)
	issued, _, err := s.IssuePAT("tenant-a", "actor-a", "ci", []string{"repo.read"}, &expiresAt)
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
