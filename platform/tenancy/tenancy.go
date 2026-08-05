// Package tenancy carries the tenant a request belongs to.
//
// It holds no infrastructure on purpose: the domain layer may import this (invariant 24 forbids it
// importing pg or http), and the data-access layer reads from it to scope every query. Keeping the
// carrier separate from the database code is what lets `domain` talk about tenants at all.
//
// SPEC-0001, T-0004. ADR-0003 (shared Postgres + RLS).
package tenancy

import (
	"context"
	"errors"
	"strings"
)

// ID identifies one tenant. A distinct type rather than a bare string so a tenant ID cannot be
// passed where a user ID or a repo name is expected — the mistake this whole mechanism exists to
// make impossible is passing the wrong scope.
type ID string

// ErrNoTenant is returned when a code path that must be tenant-scoped has no tenant in context.
// Callers must treat this as a denial, never as "read everything": invariant 1 and SPEC-0001 AC2.
var ErrNoTenant = errors.New("tenancy: no tenant in context")

// ErrInvalidTenant reports a syntactically unusable tenant ID. Rejected at the boundary rather than
// interpolated into a SET LOCAL, where a quote would become a SQL-injection primitive.
var ErrInvalidTenant = errors.New("tenancy: invalid tenant id")

type ctxKey struct{}

// WithTenant returns ctx carrying id. The ID is not validated here — validation belongs where the
// value is used, so a caller cannot be surprised by an error from a pure context assignment.
func WithTenant(ctx context.Context, id ID) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

// FromContext returns the tenant in ctx. The bool is deliberate: a caller that ignores it gets the
// zero ID, and Validate rejects that — so forgetting the check fails closed rather than silently
// scoping to "".
func FromContext(ctx context.Context) (ID, bool) {
	id, ok := ctx.Value(ctxKey{}).(ID)
	if !ok || id == "" {
		return "", false
	}
	return id, true
}

// Require returns the tenant in ctx or ErrNoTenant. This is the form data-access code should use:
// one call that cannot be accidentally ignored, because the error is the only other return.
func Require(ctx context.Context) (ID, error) {
	id, ok := FromContext(ctx)
	if !ok {
		return "", ErrNoTenant
	}
	if err := id.Validate(); err != nil {
		return "", err
	}
	return id, nil
}

// Validate accepts the conservative shape a tenant ID may take. It is intentionally narrower than
// "any text": the ID reaches Postgres inside `SET LOCAL app.tenant_id = '...'`, which takes no bind
// parameters, so the only safe input is one that cannot carry a quote, a backslash, or a newline.
func (id ID) Validate() error {
	if id == "" || len(id) > 64 {
		return ErrInvalidTenant
	}
	for _, r := range string(id) {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-', r == '_':
		default:
			return ErrInvalidTenant
		}
	}
	return nil
}

// String makes the ID printable in logs without a cast. It is not sensitive — a tenant ID identifies
// a customer, so it belongs in traces; the data behind it is what RLS protects.
func (id ID) String() string { return string(id) }

// Equal compares two IDs. Present so comparisons read the same everywhere and nobody reaches for
// strings.EqualFold: tenant IDs are case-sensitive, and treating them otherwise would merge tenants.
func (id ID) Equal(other ID) bool { return strings.Compare(string(id), string(other)) == 0 }
