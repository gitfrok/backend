package grpc

import (
	"context"
	"time"

	identityv1 "github.com/gitfrok/backend/gen/proto/identity/v1"
	"github.com/gitfrok/backend/modules/identity/api"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type Server struct {
	identityv1.UnimplementedCredentialAuthenticatorServer
	auth api.Authenticator
}

func NewServer(auth api.Authenticator) *Server { return &Server{auth: auth} }
func principal(p api.Principal) *identityv1.Principal {
	return &identityv1.Principal{TenantId: p.TenantID, ActorId: p.ActorID, Roles: p.Roles}
}
func metadata(p api.PAT) *identityv1.PATMetadata {
	var expiresAt, revokedAt *timestamppb.Timestamp
	if p.ExpiresAt != nil {
		expiresAt = timestamppb.New(*p.ExpiresAt)
	}
	if p.RevokedAt != nil {
		revokedAt = timestamppb.New(*p.RevokedAt)
	}
	return &identityv1.PATMetadata{PatId: p.ID, Label: p.Label, ScopeLabels: p.Scopes, CreatedAt: timestamppb.New(p.CreatedAt), ExpiresAt: expiresAt, RevokedAt: revokedAt}
}
func lifecycleDenied() error {
	return status.Error(codes.PermissionDenied, "credential lifecycle denied")
}
func (s *Server) AuthenticatePAT(ctx context.Context, req *identityv1.AuthenticatePATRequest) (*identityv1.AuthenticateCredentialResponse, error) {
	p, ok := s.auth.AuthenticatePAT(ctx, req.GetPersonalAccessToken())
	if !ok {
		return &identityv1.AuthenticateCredentialResponse{}, nil
	}
	return &identityv1.AuthenticateCredentialResponse{Principal: principal(p)}, nil
}
func (s *Server) AuthenticateSSHKey(ctx context.Context, req *identityv1.AuthenticateSSHKeyRequest) (*identityv1.AuthenticateCredentialResponse, error) {
	p, ok := s.auth.AuthenticateSSHKey(ctx, string(req.GetVerifiedPublicKey()))
	if !ok {
		return &identityv1.AuthenticateCredentialResponse{}, nil
	}
	return &identityv1.AuthenticateCredentialResponse{Principal: principal(p)}, nil
}
func (s *Server) IssuePAT(ctx context.Context, req *identityv1.IssuePATRequest) (*identityv1.IssuePATResponse, error) {
	var expiresAt *timestamppb.Timestamp
	if req.GetExpiresAt() != nil {
		expiresAt = req.GetExpiresAt()
	}
	var expiry *time.Time
	if expiresAt != nil {
		value := expiresAt.AsTime()
		expiry = &value
	}
	p, t, e := s.auth.IssuePAT(ctx, req.GetTenantId(), req.GetActorId(), req.GetLabel(), req.GetScopeLabels(), expiry)
	if e != nil {
		return nil, lifecycleDenied()
	}
	return &identityv1.IssuePATResponse{PatId: p.ID, PlaintextToken: t, Metadata: metadata(p)}, nil
}
func (s *Server) RevokePAT(ctx context.Context, req *identityv1.RevokePATRequest) (*identityv1.RevokePATResponse, error) {
	p, e := s.auth.RevokePAT(ctx, req.GetTenantId(), req.GetActorId(), req.GetPatId())
	if e != nil {
		return nil, lifecycleDenied()
	}
	return &identityv1.RevokePATResponse{Pat: metadata(p)}, nil
}
func (s *Server) ListPATs(ctx context.Context, req *identityv1.ListPATsRequest) (*identityv1.ListPATsResponse, error) {
	ps, err := s.auth.ListPATs(ctx, req.GetTenantId(), req.GetActorId())
	if err != nil {
		return nil, lifecycleDenied()
	}
	out := make([]*identityv1.PATMetadata, 0, len(ps))
	for _, p := range ps {
		out = append(out, metadata(p))
	}
	return &identityv1.ListPATsResponse{Pats: out}, nil
}
