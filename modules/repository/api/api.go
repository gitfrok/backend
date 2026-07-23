// Package api is the Repository context's in-process surface (ADR-0025). Other modules and
// the plane binaries depend ONLY on this package — never on internal/*. It exposes no
// infrastructure types (invariant 20), only plain data and behavioural ports.
package api

import "context"

// RepositoryView is the read model other modules receive; infra types never leak here.
type RepositoryView struct {
	TenantID string
	RepoID   string
	Name     string
}

// Reader is the synchronous read port of the Repository context.
type Reader interface {
	// Get returns a tenant-scoped repository view; callers pass the authorized tenant.
	Get(ctx context.Context, tenantID, repoID string) (RepositoryView, error)
}
