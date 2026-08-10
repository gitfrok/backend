package grpc

import (
	"context"

	identityv1 "github.com/gitfrok/backend/gen/proto/identity/v1"
	"github.com/gitfrok/backend/modules/identity/api"
)

// LoginVerifier is the OIDC half of Identity&Access: it turns the artifacts a
// browser flow produced into a tenant-scoped principal, or into nothing.
type LoginVerifier interface {
	ExchangeCode(ctx context.Context, code, codeVerifier, redirectURI, nonce string) (api.Principal, bool)
	VerifyIDToken(ctx context.Context, idToken, nonce string) (api.Principal, bool)
}

// OIDCServer adapts that port to its gRPC contract (ADR-0045, SPEC-0006).
type OIDCServer struct {
	identityv1.UnimplementedOIDCLoginServer
	verifier LoginVerifier
}

func NewOIDCServer(verifier LoginVerifier) *OIDCServer { return &OIDCServer{verifier: verifier} }

// ExchangeCode completes the Authorization Code Flow. A failure returns an empty
// response rather than an error: the same coarse denial AuthenticatePAT uses, so
// a caller cannot tell an expired code from a wrong audience from a tenant nobody
// mapped, and cannot use this surface to enumerate any of them.
func (s *OIDCServer) ExchangeCode(ctx context.Context, req *identityv1.ExchangeCodeRequest) (*identityv1.ExchangeCodeResponse, error) {
	verified, ok := s.verifier.ExchangeCode(ctx, req.GetCode(), req.GetCodeVerifier(), req.GetRedirectUri(), req.GetNonce())
	if !ok {
		return &identityv1.ExchangeCodeResponse{}, nil
	}
	return &identityv1.ExchangeCodeResponse{Principal: principal(verified)}, nil
}

// VerifyIDToken is the same verification without the token-endpoint round trip.
func (s *OIDCServer) VerifyIDToken(ctx context.Context, req *identityv1.VerifyIDTokenRequest) (*identityv1.VerifyIDTokenResponse, error) {
	verified, ok := s.verifier.VerifyIDToken(ctx, req.GetIdToken(), req.GetNonce())
	if !ok {
		return &identityv1.VerifyIDTokenResponse{}, nil
	}
	return &identityv1.VerifyIDTokenResponse{Principal: principal(verified)}, nil
}
