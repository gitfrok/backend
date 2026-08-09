package identity

import (
	"context"
	"github.com/gitfrok/backend/modules/identity/api"
	"github.com/gitfrok/backend/modules/identity/internal/domain"
)

type service struct{ domain *domain.Service }

func NewInMemory(key []byte) api.Authenticator { return service{domain.NewService(key)} }
func (s service) AuthenticatePAT(_ context.Context, token string) (api.Principal, bool) {
	p, ok := s.domain.AuthenticatePAT(token)
	return api.Principal{TenantID: p.TenantID, ActorID: p.ActorID, Roles: p.Roles}, ok
}
func (s service) AuthenticateSSHKey(_ context.Context, key string) (api.Principal, bool) {
	p, ok := s.domain.AuthenticateSSHKey(key)
	return api.Principal{TenantID: p.TenantID, ActorID: p.ActorID, Roles: p.Roles}, ok
}
func (s service) IssuePAT(_ context.Context, t, a, l string, scopes []string) (api.PAT, string, error) {
	p, tok, e := s.domain.IssuePAT(t, a, l, scopes)
	return api.PAT{ID: p.ID, TenantID: p.TenantID, ActorID: p.ActorID, Label: p.Label, Scopes: p.Scopes, Revoked: p.Revoked}, tok, e
}
func (s service) RevokePAT(_ context.Context, t, a, id string) error {
	return s.domain.RevokePAT(t, a, id)
}
