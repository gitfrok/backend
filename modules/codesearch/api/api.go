// Package api is the Code Search context's in-process surface (ADR-0025). Other modules and the
// plane binaries depend ONLY on this package — never on internal/*. It exposes no infrastructure
// types (invariant 20), only plain data and behavioural ports.
//
// The context itself is seeded here, not built: T-0008 needs a second module to prove the
// cross-module seam, and Code Search (ADR-0014) is the natural first reader of the Repository
// context's events. The real index, and the permission filtering PR-19 requires, are Phase-2 work.
package api

import "context"

// IndexedRepository is what the Code Search context knows about a repository. It is a projection
// fed by Repository events, never a read of that context's tables (invariant 15).
type IndexedRepository struct {
	TenantID string
	RepoID   string
	Name     string
	// Refs maps a ref name to the sha last seen for it.
	Refs map[string]string
}

// Index is the synchronous read port of the Code Search context.
type Index interface {
	// Lookup returns a tenant-scoped index entry; callers pass the authorized tenant.
	Lookup(ctx context.Context, tenantID, repoID string) (IndexedRepository, error)
}
