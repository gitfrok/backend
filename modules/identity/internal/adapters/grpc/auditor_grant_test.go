package grpc

import (
	"context"
	"errors"
	"testing"
	"time"

	identityv1 "github.com/gitfrok/backend/gen/proto/identity/v1"
	"github.com/gitfrok/backend/modules/identity/api"
	"github.com/gitfrok/backend/platform/tenancy"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// SPEC-0033: the door translates shapes only. Authorization, idempotency and
// audit all happen behind api.AuditorGrants, and every failure the surface
// reports is the same coarse PermissionDenied — a denial never says why
// (SPEC-0001).

type fakeGrants struct {
	grant      api.AuditorGrant
	grants     []api.AuditorGrant
	err        error
	captured   context.Context
	issue      api.GrantIssue
	requestID  string
	revokeID   string
	listFilter string
}

func (f *fakeGrants) IssueGrant(ctx context.Context, c api.GrantContext, req api.GrantIssue) (api.AuditorGrant, error) {
	f.captured, f.issue, f.requestID = ctx, req, c.RequestID
	return f.grant, f.err
}

func (f *fakeGrants) RevokeGrant(ctx context.Context, c api.GrantContext, grantID string) (api.AuditorGrant, error) {
	f.captured, f.revokeID, f.requestID = ctx, grantID, c.RequestID
	return f.grant, f.err
}

func (f *fakeGrants) ListGrants(ctx context.Context, c api.GrantContext, auditorPrincipalID string) ([]api.AuditorGrant, error) {
	f.captured, f.listFilter, f.requestID = ctx, auditorPrincipalID, c.RequestID
	return f.grants, f.err
}

func (f *fakeGrants) GrantFacts(context.Context, string, string) (api.GrantDecisionFacts, bool, error) {
	return api.GrantDecisionFacts{}, false, nil
}

func (f *fakeGrants) GrantTransitions(context.Context, string, time.Time, time.Time, string) ([]api.GrantTransition, error) {
	return nil, nil
}

var grantNow = time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)

func sampleGrant() api.AuditorGrant {
	return api.AuditorGrant{
		GrantID: "grant-1", TenantID: "tenant-a", AuditorPrincipalID: "auditor-1",
		RangeFrom: grantNow.Add(-time.Hour), RangeTo: grantNow,
		RepositoryID: "repo-1", PackIDs: []string{"pack-1"},
		ExpiresAt: grantNow.Add(time.Hour), GrantedBy: "admin-a",
		IssuedAt: grantNow, State: api.GrantActive,
	}
}

func grantCtx() *identityv1.AuditorGrantContext {
	return &identityv1.AuditorGrantContext{
		TenantId: "tenant-a", ActorId: "admin-a", ActorRoles: []string{"owner"}, RequestId: "req-1",
	}
}

// The door derives the tenant-scoped principal from the request's verified
// context message and hands it to the surface — the seam the credential door
// uses. The surface still passes the PDP with that identity.
func TestCreateAuditorGrantDerivesTheVerifiedContext(t *testing.T) {
	f := &fakeGrants{grant: sampleGrant()}
	s := NewGrantServer(f)
	resp, err := s.CreateAuditorGrant(t.Context(), &identityv1.CreateAuditorGrantRequest{
		Context:            grantCtx(),
		AuditorPrincipalId: "auditor-1",
		RangeFrom:          timestamppb.New(grantNow.Add(-time.Hour)),
		RangeTo:            timestamppb.New(grantNow),
		RepositoryId:       "repo-1",
		PackIds:            []string{"pack-1"},
		ExpiresAt:          timestamppb.New(grantNow.Add(time.Hour)),
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if resp.GetGrant().GetGrantId() != "grant-1" ||
		resp.GetGrant().GetState() != identityv1.AuditorGrantState_AUDITOR_GRANT_STATE_ACTIVE {
		t.Fatalf("response grant = %+v", resp.GetGrant())
	}
	if f.requestID != "req-1" || f.issue.AuditorPrincipalID != "auditor-1" ||
		f.issue.RepositoryID != "repo-1" || len(f.issue.PackIDs) != 1 {
		t.Fatalf("issue forwarded = %+v requestID=%q", f.issue, f.requestID)
	}
	tenant, ok := tenancy.FromContext(f.captured)
	if !ok || string(tenant) != "tenant-a" {
		t.Fatalf("tenant in forwarded ctx = %q ok=%v", tenant, ok)
	}
	principal, err := api.RequirePrincipal(f.captured)
	//arch:allow-inline-authz asserts the door forwards the caller's claimed roles, never decides access
	if err != nil || principal.ActorID != "admin-a" || principal.TenantID != "tenant-a" || principal.Roles[0] != "owner" {
		t.Fatalf("principal in forwarded ctx = %+v err=%v", principal, err)
	}
}

func TestRevokeAndListForwardToTheSurface(t *testing.T) {
	f := &fakeGrants{grant: sampleGrant(), grants: []api.AuditorGrant{sampleGrant()}}
	s := NewGrantServer(f)

	if _, err := s.RevokeAuditorGrant(t.Context(), &identityv1.RevokeAuditorGrantRequest{
		Context: grantCtx(), GrantId: "grant-1",
	}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if f.revokeID != "grant-1" {
		t.Fatalf("revoke forwarded %q", f.revokeID)
	}

	resp, err := s.ListAuditorGrants(t.Context(), &identityv1.ListAuditorGrantsRequest{
		Context: grantCtx(), AuditorPrincipalId: "auditor-1",
	})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if f.listFilter != "auditor-1" || len(resp.GetGrants()) != 1 {
		t.Fatalf("list filter=%q grants=%d", f.listFilter, len(resp.GetGrants()))
	}
}

// SPEC-0033 AC6: every failure — whatever its cause — is the ONE coarse
// PermissionDenied. A caller probing the surface cannot distinguish
// nonexistent from cross-tenant from unauthorized.
func TestEveryFailureIsTheSameCoarseDenial(t *testing.T) {
	f := &fakeGrants{err: errors.New("whatever the real cause")}
	s := NewGrantServer(f)

	_, err := s.CreateAuditorGrant(t.Context(), &identityv1.CreateAuditorGrantRequest{Context: grantCtx()})
	if status.Code(err) != codes.PermissionDenied || !sameCoarse(err) {
		t.Fatalf("create denial = %v", err)
	}
	_, err = s.RevokeAuditorGrant(t.Context(), &identityv1.RevokeAuditorGrantRequest{Context: grantCtx(), GrantId: "grant-1"})
	if status.Code(err) != codes.PermissionDenied || !sameCoarse(err) {
		t.Fatalf("revoke denial = %v", err)
	}
	_, err = s.ListAuditorGrants(t.Context(), &identityv1.ListAuditorGrantsRequest{Context: grantCtx()})
	if status.Code(err) != codes.PermissionDenied || !sameCoarse(err) {
		t.Fatalf("list denial = %v", err)
	}
}

// sameCoarse asserts the denial message reveals nothing cause-specific.
func sameCoarse(err error) bool {
	return status.Convert(err).Message() == "auditor grant unavailable"
}

// The state enum renders every lifecycle the surface reports — and nothing
// the surface does not report.
func TestGrantProtoRendersEveryState(t *testing.T) {
	for state, want := range map[api.GrantState]identityv1.AuditorGrantState{
		api.GrantActive:     identityv1.AuditorGrantState_AUDITOR_GRANT_STATE_ACTIVE,
		api.GrantRevoked:    identityv1.AuditorGrantState_AUDITOR_GRANT_STATE_REVOKED,
		api.GrantExpired:    identityv1.AuditorGrantState_AUDITOR_GRANT_STATE_EXPIRED,
		api.GrantState(""):  identityv1.AuditorGrantState_AUDITOR_GRANT_STATE_UNSPECIFIED,
	} {
		g := sampleGrant()
		g.State = state
		if got := grantProto(g).GetState(); got != want {
			t.Fatalf("state %q rendered %v, want %v", state, got, want)
		}
	}
	// A zero revocation instant never rides the wire.
	if grantProto(sampleGrant()).GetRevokedAt() != nil {
		t.Fatal("an unrevoked grant rendered a RevokedAt")
	}
	revoked := sampleGrant()
	revoked.RevokedAt = grantNow
	if grantProto(revoked).GetRevokedAt() == nil {
		t.Fatal("a revoked grant rendered no RevokedAt")
	}
}
