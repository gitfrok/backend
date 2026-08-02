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

// Reader is the synchronous read port of the Repository context. Consumers that only read depend
// on this narrower port, so a change to the write side is not a change to them.
type Reader interface {
	// Get returns a tenant-scoped repository view; callers pass the authorized tenant.
	Get(ctx context.Context, tenantID, repoID string) (RepositoryView, error)
}

// Writer is the synchronous write port of the Repository context.
type Writer interface {
	// Create records a new repository and announces it as RepositoryCreated.
	Create(ctx context.Context, tenantID, repoID, name, actorID string) (RepositoryView, error)
}

// Repositories is the context's full in-process surface, which is what the plane binary holds.
type Repositories interface {
	Reader
	Writer
}
