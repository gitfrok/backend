package api

import (
	"context"
)

// Directory is the read-only view of who a tenant's principals are, derived
// from the same membership state credential resolution already trusts
// (ADR-0043). It exists for server-side recipient derivation (SPEC-0063): the
// Notifications context must learn "who could review this" from a store fact,
// never from anything a caller asserts.
//
// It is a derivation read, not an authorization question: it names no
// permission outcome and grants nothing — what each principal may do is still
// decided by the PDP wherever an action is attempted. The tenant scope is the
// caller's own; there is no cross-tenant enumeration.
type Directory interface {
	// TenantActors enumerates the tenant's active principals with their
	// current roles. An actor holding several roles appears once, roles
	// aggregated. Empty when the tenant has none.
	TenantActors(ctx context.Context, tenantID string) ([]Principal, error)
}
