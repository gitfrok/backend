package domain

import "testing"

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
