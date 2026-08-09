// Package api is the Identity&Access in-process surface (ADR-0022).
package api

import "context"

type Principal struct {
	TenantID, ActorID string
	Roles             []string
}
type PAT struct {
	ID, TenantID, ActorID, Label string
	Scopes                       []string
	Revoked                      bool
}
type Authenticator interface {
	AuthenticatePAT(ctx context.Context, token string) (Principal, bool)
	AuthenticateSSHKey(ctx context.Context, key string) (Principal, bool)
	IssuePAT(ctx context.Context, tenantID, actorID, label string, scopes []string) (PAT, string, error)
	RevokePAT(ctx context.Context, tenantID, actorID, patID string) error
}
