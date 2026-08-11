package grpc

import (
	"context"
	"errors"
	"testing"
	"time"

	identityv1 "github.com/gitfrok/backend/gen/proto/identity/v1"
	"github.com/gitfrok/backend/modules/identity/api"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type fakeAuthenticator struct {
	principal  api.Principal
	ok         bool
	pat        api.PAT
	token      string
	err        error
	sshKey     string
	sshKeyID   string
	issueRoles []string
}

func (f fakeAuthenticator) AuthenticatePAT(context.Context, string) (api.Principal, bool) {
	return f.principal, f.ok
}
func (f *fakeAuthenticator) AuthenticateSSHKey(_ context.Context, key, keyID string) (api.Principal, bool) {
	f.sshKey = key
	f.sshKeyID = keyID
	return f.principal, f.ok
}
func (f *fakeAuthenticator) IssuePAT(_ context.Context, _, _, _ string, _, roles []string, _ *time.Time) (api.PAT, string, error) {
	f.issueRoles = roles
	return f.pat, f.token, f.err
}

// SPEC-0016 AC6: roles requested at issuance ride the wire to the store; the
// server never drops them before forwarding.
func TestIssuePATForwardsRequestedRoles(t *testing.T) {
	f := &fakeAuthenticator{}
	s := NewServer(f)
	req := &identityv1.IssuePATRequest{Roles: []string{"developer", "ci"}}
	if _, err := s.IssuePAT(t.Context(), req); err != nil {
		t.Fatal(err)
	}
	if len(f.issueRoles) != 2 || f.issueRoles[0] != "developer" || f.issueRoles[1] != "ci" {
		t.Fatalf("roles forwarded = %#v", f.issueRoles)
	}
}
func (f fakeAuthenticator) RevokePAT(context.Context, string, string, string) (api.PAT, error) {
	return f.pat, f.err
}
func (f fakeAuthenticator) ListPATs(context.Context, string, string) ([]api.PAT, error) {
	return []api.PAT{f.pat}, f.err
}

// SPEC-0016 AC1/AC5: only issuance contains a secret. Listing and revocation
// carry lifecycle metadata, never the token or its verifier.
func TestLifecycleResponsesExposeOnlyMetadata(t *testing.T) {
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	expires := now.Add(time.Hour)
	revoked := now.Add(2 * time.Hour)
	s := NewServer(&fakeAuthenticator{pat: api.PAT{ID: "pat-1", Label: "ci", Scopes: []string{"repo.read"}, CreatedAt: now, ExpiresAt: &expires, RevokedAt: &revoked}, token: "gfp_secret"})

	issue, err := s.IssuePAT(t.Context(), &identityv1.IssuePATRequest{ExpiresAt: timestamppb.New(expires)})
	if err != nil || issue.GetPlaintextToken() != "gfp_secret" {
		t.Fatalf("issue = %#v, %v", issue, err)
	}
	listed, err := s.ListPATs(t.Context(), &identityv1.ListPATsRequest{})
	if err != nil || len(listed.GetPats()) != 1 {
		t.Fatalf("list = %#v, %v", listed, err)
	}
	if got := listed.GetPats()[0]; got.GetCreatedAt().AsTime() != now || got.GetExpiresAt().AsTime() != expires || got.GetRevokedAt().AsTime() != revoked {
		t.Fatalf("metadata = %#v", got)
	}
	revocation, err := s.RevokePAT(t.Context(), &identityv1.RevokePATRequest{})
	if err != nil || revocation.GetPat().GetPatId() != "pat-1" {
		t.Fatalf("revoke = %#v, %v", revocation, err)
	}
}

// SPEC-0016 coarse denial means failed credential checks do not enumerate why.
func TestAuthenticationFailureReturnsEmptyPrincipal(t *testing.T) {
	s := NewServer(&fakeAuthenticator{})
	pat, err := s.AuthenticatePAT(t.Context(), &identityv1.AuthenticatePATRequest{PersonalAccessToken: "invalid"})
	if err != nil || pat.GetPrincipal() != nil {
		t.Fatalf("PAT response = %#v, %v", pat, err)
	}
	ssh, err := s.AuthenticateSSHKey(t.Context(), &identityv1.AuthenticateSSHKeyRequest{VerifiedPublicKey: []byte("unknown")})
	if err != nil || ssh.GetPrincipal() != nil {
		t.Fatalf("SSH response = %#v, %v", ssh, err)
	}
}

// SPEC-0022 AC1: the transport-selected, non-secret verifier key ID reaches
// Identity with the verified public-key proof. It is not a tenant or policy input.
func TestAuthenticateSSHKeyForwardsVerifierKeyID(t *testing.T) {
	auth := &fakeAuthenticator{principal: api.Principal{TenantID: "tenant-a", ActorID: "actor-a"}, ok: true}
	s := NewServer(auth)

	resp, err := s.AuthenticateSSHKey(t.Context(), &identityv1.AuthenticateSSHKeyRequest{
		VerifiedPublicKey: []byte("ssh-ed25519 AAA"),
		VerifierKeyId:     "key-2026-08",
	})
	if err != nil || resp.GetPrincipal().GetTenantId() != "tenant-a" {
		t.Fatalf("response = %#v, %v", resp, err)
	}
	if auth.sshKey != "ssh-ed25519 AAA" || auth.sshKeyID != "key-2026-08" {
		t.Fatalf("Identity received key=%q keyID=%q", auth.sshKey, auth.sshKeyID)
	}
}

func TestLifecycleErrorIsCoarsePermissionDenied(t *testing.T) {
	s := NewServer(&fakeAuthenticator{err: errors.New("token does not exist")})
	_, err := s.RevokePAT(t.Context(), &identityv1.RevokePATRequest{})
	if status.Code(err) != codes.PermissionDenied || status.Convert(err).Message() != "credential lifecycle denied" {
		t.Fatalf("error = %v", err)
	}
}
