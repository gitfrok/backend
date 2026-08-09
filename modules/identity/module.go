package identity

import (
	"context"
	"time"

	"github.com/gitfrok/backend/modules/identity/api"
	identitygrpc "github.com/gitfrok/backend/modules/identity/internal/adapters/grpc"
	"github.com/gitfrok/backend/modules/identity/internal/domain"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
	"github.com/gitfrok/backend/platform/tenancy"
)

type service struct {
	domain *domain.Service
	pdp    policyapi.DecisionPoint
}

// NewInMemory assembles a test/development credential store. Lifecycle
// actions require the same PDP port as a durable deployment; nil is refused
// so an accidental unsecured composition cannot issue credentials.
func NewInMemory(key []byte, pdp policyapi.DecisionPoint) api.Authenticator {
	if pdp == nil {
		panic("identity: no PDP — credential lifecycle actions require authorization")
	}
	return service{domain: domain.NewService(key), pdp: pdp}
}
func NewGRPCServer(auth api.Authenticator) *identitygrpc.Server { return identitygrpc.NewServer(auth) }
func (s service) AuthenticatePAT(_ context.Context, token string) (api.Principal, bool) {
	p, ok := s.domain.AuthenticatePAT(token)
	return api.Principal{TenantID: p.TenantID, ActorID: p.ActorID, Roles: p.Roles}, ok
}
func (s service) AuthenticateSSHKey(_ context.Context, key string) (api.Principal, bool) {
	p, ok := s.domain.AuthenticateSSHKey(key)
	return api.Principal{TenantID: p.TenantID, ActorID: p.ActorID, Roles: p.Roles}, ok
}
func (s service) IssuePAT(ctx context.Context, t, a, l string, scopes []string, expiresAt *time.Time) (api.PAT, string, error) {
	if err := s.authorizeLifecycle(ctx, t, "identity.pat.issue", a); err != nil {
		return api.PAT{}, "", err
	}
	p, tok, e := s.domain.IssuePAT(t, a, l, scopes, expiresAt)
	return publicPAT(p), tok, e
}
func (s service) RevokePAT(ctx context.Context, t, a, id string) (api.PAT, error) {
	if err := s.authorizeLifecycle(ctx, t, "identity.pat.revoke", id); err != nil {
		return api.PAT{}, err
	}
	if err := s.domain.RevokePAT(t, a, id); err != nil {
		return api.PAT{}, err
	}
	for _, p := range s.domain.ListPATs(t, a) {
		if p.ID == id {
			return publicPAT(p), nil
		}
	}
	return api.PAT{}, nil
}
func (s service) ListPATs(ctx context.Context, t, a string) ([]api.PAT, error) {
	if err := s.authorizeLifecycle(ctx, t, "identity.pat.list", a); err != nil {
		return nil, err
	}
	ps := s.domain.ListPATs(t, a)
	out := make([]api.PAT, 0, len(ps))
	for _, p := range ps {
		out = append(out, publicPAT(p))
	}
	return out, nil
}
func (s service) authorizeLifecycle(ctx context.Context, requestedTenant, action, resourceID string) error {
	tenant, err := tenancy.Require(ctx)
	if err != nil {
		return err
	}
	principal, err := api.RequirePrincipal(ctx)
	if err != nil {
		return err
	}
	if string(tenant) != requestedTenant || principal.TenantID != requestedTenant {
		return api.ErrTenantMismatch
	}
	decision, err := s.pdp.Decide(ctx, policyapi.Request{
		TenantID: requestedTenant,
		Subject: policyapi.Subject{
			ID: principal.ActorID, TenantID: principal.TenantID, Roles: append([]string(nil), principal.Roles...),
		},
		Action:   action,
		Resource: policyapi.Resource{Type: "personal_access_token", ID: resourceID},
	})
	if err != nil || !decision.Allowed {
		return api.ErrAuthorizationDenied
	}
	return nil
}
func publicPAT(p domain.PAT) api.PAT {
	return api.PAT{ID: p.ID, TenantID: p.TenantID, ActorID: p.ActorID, Label: p.Label, Scopes: append([]string(nil), p.Scopes...), CreatedAt: p.CreatedAt, ExpiresAt: p.ExpiresAt, RevokedAt: p.RevokedAt}
}
