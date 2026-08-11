// Package api is the Identity&Access in-process surface (ADR-0022).
package api

import (
	"context"
	"errors"
	"time"
)

// ErrTenantMismatch means a lifecycle caller attempted to select a tenant
// different from the tenant scope that authenticated request carried.
var ErrTenantMismatch = errors.New("identity: request tenant does not match context")

// ErrNoPrincipal is a deny signal for lifecycle operations that reached the
// module without a verified OIDC session or equivalent authenticated caller.
var ErrNoPrincipal = errors.New("identity: no authenticated principal")

// ErrAuthorizationDenied means the PDP did not grant a lifecycle action.
var ErrAuthorizationDenied = errors.New("identity: authorization denied")

type Principal struct {
	TenantID, ActorID string
	Roles             []string
}

type principalKey struct{}

// WithPrincipal attaches an already verified caller to an in-process request.
// It is a transport boundary helper: gRPC/HTTP authentication must create this
// only after verifying credentials, never from client-controlled request fields.
func WithPrincipal(ctx context.Context, principal Principal) context.Context {
	principal.Roles = append([]string(nil), principal.Roles...)
	return context.WithValue(ctx, principalKey{}, principal)
}

// RequirePrincipal fails closed when no verified caller is present.
func RequirePrincipal(ctx context.Context) (Principal, error) {
	principal, ok := ctx.Value(principalKey{}).(Principal)
	if !ok || principal.TenantID == "" || principal.ActorID == "" {
		return Principal{}, ErrNoPrincipal
	}
	principal.Roles = append([]string(nil), principal.Roles...)
	return principal, nil
}

type PAT struct {
	ID, TenantID, ActorID, Label string
	Scopes, Roles                []string
	CreatedAt                    time.Time
	ExpiresAt, RevokedAt         *time.Time
}
type Authenticator interface {
	AuthenticatePAT(ctx context.Context, token string) (Principal, bool)
	AuthenticateSSHKey(ctx context.Context, key, verifierKeyID string) (Principal, bool)
	IssuePAT(ctx context.Context, tenantID, actorID, label string, scopes, roles []string, expiresAt *time.Time) (PAT, string, error)
	RevokePAT(ctx context.Context, tenantID, actorID, patID string) (PAT, error)
	ListPATs(ctx context.Context, tenantID, actorID string) ([]PAT, error)
}
