// The gRPC door for the auditor grant surface (T-0027, SPEC-0033), over
// contracts/proto/identity/v1's AuditorGrantService.
//
// The adapter translates shapes only; authorization, idempotency and audit
// all happen behind api.AuditorGrants. Every failure — nonexistent,
// cross-tenant, already-revoked, expired, malformed or unauthorized — is the
// same coarse PermissionDenied, because a denial that said why would let
// probing enumerate grants and tenants (SPEC-0001).
package grpc

import (
	"context"

	identityv1 "github.com/gitfrok/backend/gen/proto/identity/v1"
	"github.com/gitfrok/backend/modules/identity/api"
	"github.com/gitfrok/backend/platform/tenancy"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// GrantServer serves AuditorGrantService over an api.AuditorGrants port.
type GrantServer struct {
	identityv1.UnimplementedAuditorGrantServiceServer
	grants api.AuditorGrants
}

// NewGrantServer wires the door over the grant surface.
func NewGrantServer(grants api.AuditorGrants) *GrantServer { return &GrantServer{grants: grants} }

// grantDenied is the ONE coarse shape for every failed grant operation: a
// caller must not be able to distinguish "does not exist" from "not yours",
// or probing this surface enumerates grants and tenants (SPEC-0001).
func grantDenied() error {
	return status.Error(codes.PermissionDenied, "auditor grant unavailable")
}

// withGrantContext derives the tenant-scoped principal context the grant
// lifecycle requires from the request's verified context message. It is the
// same documented seam the credential lifecycle door uses for the
// in-cluster gRPC door, which carries no interceptor: the request context is
// the only place the caller's identity can come from there, and every
// lifecycle action still passes the PDP with that identity — this wrapper
// supplies the subject; it cannot lift a decision. Production deployments
// front the door with an authenticating interceptor instead.
func withGrantContext(ctx context.Context, c *identityv1.AuditorGrantContext) context.Context {
	if c == nil {
		return ctx
	}
	ctx = tenancy.WithTenant(ctx, tenancy.ID(c.GetTenantId()))
	return api.WithPrincipal(ctx, api.Principal{
		TenantID: c.GetTenantId(),
		ActorID:  c.GetActorId(),
		Roles:    c.GetActorRoles(),
	})
}

// CreateAuditorGrant implements identityv1.AuditorGrantServiceServer.
func (s *GrantServer) CreateAuditorGrant(ctx context.Context, req *identityv1.CreateAuditorGrantRequest) (*identityv1.CreateAuditorGrantResponse, error) {
	issue := api.GrantIssue{
		AuditorPrincipalID: req.GetAuditorPrincipalId(),
		RepositoryID:       req.GetRepositoryId(),
		PackIDs:            req.GetPackIds(),
	}
	if req.GetRangeFrom() != nil {
		issue.RangeFrom = req.GetRangeFrom().AsTime()
	}
	if req.GetRangeTo() != nil {
		issue.RangeTo = req.GetRangeTo().AsTime()
	}
	if req.GetExpiresAt() != nil {
		issue.ExpiresAt = req.GetExpiresAt().AsTime()
	}
	grant, err := s.grants.IssueGrant(withGrantContext(ctx, req.GetContext()),
		api.GrantContext{RequestID: req.GetContext().GetRequestId()}, issue)
	if err != nil {
		return nil, grantDenied()
	}
	return &identityv1.CreateAuditorGrantResponse{Grant: grantProto(grant)}, nil
}

// RevokeAuditorGrant implements identityv1.AuditorGrantServiceServer.
func (s *GrantServer) RevokeAuditorGrant(ctx context.Context, req *identityv1.RevokeAuditorGrantRequest) (*identityv1.RevokeAuditorGrantResponse, error) {
	grant, err := s.grants.RevokeGrant(withGrantContext(ctx, req.GetContext()),
		api.GrantContext{RequestID: req.GetContext().GetRequestId()}, req.GetGrantId())
	if err != nil {
		return nil, grantDenied()
	}
	return &identityv1.RevokeAuditorGrantResponse{Grant: grantProto(grant)}, nil
}

// ListAuditorGrants implements identityv1.AuditorGrantServiceServer.
func (s *GrantServer) ListAuditorGrants(ctx context.Context, req *identityv1.ListAuditorGrantsRequest) (*identityv1.ListAuditorGrantsResponse, error) {
	grants, err := s.grants.ListGrants(withGrantContext(ctx, req.GetContext()),
		api.GrantContext{RequestID: req.GetContext().GetRequestId()}, req.GetAuditorPrincipalId())
	if err != nil {
		return nil, grantDenied()
	}
	out := make([]*identityv1.AuditorGrant, 0, len(grants))
	for _, g := range grants {
		out = append(out, grantProto(g))
	}
	return &identityv1.ListAuditorGrantsResponse{Grants: out}, nil
}

// grantProto renders one api.AuditorGrant as its contract shape. The state
// is the server's rendering of its own record at response time — never an
// input to any decision, which reads the fact fresh instead (SPEC-0033 AC7).
func grantProto(g api.AuditorGrant) *identityv1.AuditorGrant {
	pb := &identityv1.AuditorGrant{
		GrantId:            g.GrantID,
		TenantId:           g.TenantID,
		AuditorPrincipalId: g.AuditorPrincipalID,
		RangeFrom:          timestamppb.New(g.RangeFrom),
		RangeTo:            timestamppb.New(g.RangeTo),
		RepositoryId:       g.RepositoryID,
		PackIds:            g.PackIDs,
		ExpiresAt:          timestamppb.New(g.ExpiresAt),
		GrantedBy:          g.GrantedBy,
		IssuedAt:           timestamppb.New(g.IssuedAt),
	}
	if !g.RevokedAt.IsZero() {
		pb.RevokedAt = timestamppb.New(g.RevokedAt)
	}
	switch g.State {
	case api.GrantActive:
		pb.State = identityv1.AuditorGrantState_AUDITOR_GRANT_STATE_ACTIVE
	case api.GrantRevoked:
		pb.State = identityv1.AuditorGrantState_AUDITOR_GRANT_STATE_REVOKED
	case api.GrantExpired:
		pb.State = identityv1.AuditorGrantState_AUDITOR_GRANT_STATE_EXPIRED
	default:
		pb.State = identityv1.AuditorGrantState_AUDITOR_GRANT_STATE_UNSPECIFIED
	}
	return pb
}
