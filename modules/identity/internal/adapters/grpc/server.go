package grpc

import (
	"context"

	identityv1 "github.com/gitfrok/backend/gen/proto/identity/v1"
	"github.com/gitfrok/backend/modules/identity/api"
)

type Server struct {
	identityv1.UnimplementedCredentialAuthenticatorServer
	auth api.Authenticator
}

func NewServer(auth api.Authenticator) *Server { return &Server{auth: auth} }
func principal(p api.Principal) *identityv1.Principal {
	return &identityv1.Principal{TenantId: p.TenantID, ActorId: p.ActorID, Roles: p.Roles}
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
	p, t, e := s.auth.IssuePAT(ctx, req.GetTenantId(), req.GetActorId(), req.GetLabel(), req.GetScopeLabels())
	if e != nil {
		return nil, e
	}
	return &identityv1.IssuePATResponse{PatId: p.ID, PlaintextToken: t, Metadata: &identityv1.PATMetadata{PatId: p.ID, Label: p.Label, ScopeLabels: p.Scopes}}, nil
}
func (s *Server) RevokePAT(ctx context.Context, req *identityv1.RevokePATRequest) (*identityv1.RevokePATResponse, error) {
	if e := s.auth.RevokePAT(ctx, req.GetTenantId(), req.GetActorId(), req.GetPatId()); e != nil {
		return nil, e
	}
	return &identityv1.RevokePATResponse{}, nil
}
func (s *Server) ListPATs(ctx context.Context, req *identityv1.ListPATsRequest) (*identityv1.ListPATsResponse, error) {
	ps := s.auth.ListPATs(ctx, req.GetTenantId(), req.GetActorId())
	out := make([]*identityv1.PATMetadata, 0, len(ps))
	for _, p := range ps {
		out = append(out, &identityv1.PATMetadata{PatId: p.ID, Label: p.Label, ScopeLabels: p.Scopes})
	}
	return &identityv1.ListPATsResponse{Pats: out}, nil
}
