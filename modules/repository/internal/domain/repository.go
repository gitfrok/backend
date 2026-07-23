// Package domain is the Repository context's core model. It imports NO infrastructure
// (no pg/grpc/http/opa/redpanda) — dependencies point inward (invariant 16).
package domain

import "errors"

// TenantID scopes every aggregate; there is no un-tenant-scoped repository (invariant 1).
type TenantID string

// RepoID identifies a repository within a tenant.
type RepoID string

// Repository is the aggregate root of the Repository context.
type Repository struct {
	Tenant TenantID
	ID     RepoID
	Name   string
}

// ErrCrossTenant guards against tenant leakage inside the domain.
var ErrCrossTenant = errors.New("repository: cross-tenant access denied")

// NewRepository builds a valid, tenant-scoped repository aggregate.
func NewRepository(t TenantID, id RepoID, name string) (Repository, error) {
	if t == "" || id == "" || name == "" {
		return Repository{}, errors.New("repository: tenant, id and name are required")
	}
	return Repository{Tenant: t, ID: id, Name: name}, nil
}

// BelongsTo enforces tenant scoping at the aggregate boundary.
func (r Repository) BelongsTo(t TenantID) bool { return r.Tenant == t }
