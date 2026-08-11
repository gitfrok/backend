package gitfrontdoor

import (
	"context"
	"testing"
	"time"

	gitv1 "github.com/gitfrok/backend/gen/proto/git/v1"
	identityapi "github.com/gitfrok/backend/modules/identity/api"
)

type fakeAuthenticator struct {
	principal    identityapi.Principal
	ok           bool
	sshPrincipal identityapi.Principal
	sshOK        bool
	seenToken    string
}

func (f *fakeAuthenticator) AuthenticatePAT(_ context.Context, token string) (identityapi.Principal, bool) {
	f.seenToken = token
	return f.principal, f.ok
}

func (f *fakeAuthenticator) AuthenticateSSHKey(context.Context, string, string) (identityapi.Principal, bool) {
	return f.sshPrincipal, f.sshOK
}
func (f *fakeAuthenticator) IssuePAT(context.Context, string, string, string, []string, []string, *time.Time) (identityapi.PAT, string, error) {
	panic("not used")
}
func (f *fakeAuthenticator) RevokePAT(context.Context, string, string, string) (identityapi.PAT, error) {
	panic("not used")
}
func (f *fakeAuthenticator) ListPATs(context.Context, string, string) ([]identityapi.PAT, error) {
	panic("not used")
}

func TestRoutePATBindsAuthenticatedPrincipalToOpaqueRepositoryHandle(t *testing.T) {
	auth := &fakeAuthenticator{principal: identityapi.Principal{TenantID: "tenant-a", ActorID: "actor-a", Roles: []string{"member"}}, ok: true}
	router := Router{Authenticator: auth}

	context, err := router.RoutePAT(t.Context(), "tenant-a/repo-a.git", "pat-secret", "request-1", gitv1.GitTransport_GIT_TRANSPORT_SMART_HTTP_RPC)
	if err != nil {
		t.Fatal(err)
	}
	want := &gitv1.OperationContext{TenantId: "tenant-a", RepositoryId: "repo-a", ActorId: "actor-a", ActorRoles: []string{"member"}, RequestId: "request-1", Transport: gitv1.GitTransport_GIT_TRANSPORT_SMART_HTTP_RPC}
	if !sameContext(context, want) {
		t.Fatalf("operation context = %+v, want %+v", context, want)
	}
	if auth.seenToken != "pat-secret" {
		t.Fatalf("auth token = %q", auth.seenToken)
	}
}

func TestRoutePATDeniesBeforeStorageForInvalidOrCrossTenantIdentity(t *testing.T) {
	for _, test := range []struct {
		name string
		auth *fakeAuthenticator
	}{
		{name: "invalid", auth: &fakeAuthenticator{}},
		{name: "cross tenant", auth: &fakeAuthenticator{principal: identityapi.Principal{TenantID: "tenant-b", ActorID: "actor-a"}, ok: true}},
	} {
		t.Run(test.name, func(t *testing.T) {
			router := Router{Authenticator: test.auth}
			if _, err := router.RoutePAT(t.Context(), "tenant-a/repo-a.git", "secret", "request-1", gitv1.GitTransport_GIT_TRANSPORT_SMART_HTTP_RPC); err == nil {
				t.Fatal("RoutePAT succeeded for a denied credential")
			}
		})
	}
}

func TestParseHandleRejectsFilesystemPathsAndMalformedNames(t *testing.T) {
	for _, handle := range []string{"", "repo-a.git", "tenant-a/../repo-a.git", "tenant-a/repo-a", "/tenant-a/repo-a.git", "tenant-a/repo-a.git/extra"} {
		if _, _, err := ParseHandle(handle); err == nil {
			t.Errorf("ParseHandle(%q) succeeded", handle)
		}
	}
}

func sameContext(got, want *gitv1.OperationContext) bool {
	if got == nil || got.GetTenantId() != want.GetTenantId() || got.GetRepositoryId() != want.GetRepositoryId() || got.GetActorId() != want.GetActorId() || got.GetRequestId() != want.GetRequestId() || got.GetTransport() != want.GetTransport() || len(got.GetActorRoles()) != len(want.GetActorRoles()) {
		return false
	}
	for i := range want.GetActorRoles() {
		if got.GetActorRoles()[i] != want.GetActorRoles()[i] {
			return false
		}
	}
	return true
}
