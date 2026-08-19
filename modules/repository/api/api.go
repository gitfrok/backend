// Package api is the Repository context's in-process surface (ADR-0025). Other modules and
// the plane binaries depend ONLY on this package — never on internal/*. It exposes no
// infrastructure types (invariant 20), only plain data and behavioural ports.
package api

import (
	"context"
	"errors"
)

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

// ErrNoDecisionPoint reports a Repository service wired without an Authorizer. Listing is the
// context's first authorization-derived answer, so a missing one is a composition bug rather than
// a runtime condition — and it refuses loudly instead of returning an empty list, which a caller
// would read as "you may see nothing" (ADR-0006, SPEC-0052 AC4).
var ErrNoDecisionPoint = errors.New("repository: no authorizer wired; listing cannot be authorized")

// Authorizer answers whether one verified caller may see one repository.
//
// It is declared HERE, in the Repository context's own surface, rather than taken as the Policy
// context's DecisionPoint — because this module is a leaf. Everything depends on Repository and
// Repository depends on no module, which the architecture fitness function pins at fan-out zero
// (T-0009's graph report). Importing the Policy context to ask it a question would invert that
// for the sake of one call.
//
// So the dependency points the other way: the composition root, which may know both contexts,
// adapts the PDP onto this interface. The Repository context asks an abstraction it owns, and
// the answer still comes from the one decision point (invariant 2, ADR-0006).
type Authorizer interface {
	// MayRead reports whether the caller may see that the repository exists. An error is a
	// refusal, not a condition to work around: there is no third outcome in which listing it
	// anyway is correct.
	MayRead(ctx context.Context, tenantID, actorID string, roles []string, repoID string) (bool, error)
}

// ListQuery asks for the repositories one verified caller may see.
//
// It carries no repository set, filter or scope, and there is deliberately no field for one: the
// listable set is derived server-side from the caller's authorization at request time, the same
// property SPEC-0035 AC2 gives code search. A caller cannot widen what it is shown by asking
// differently, because there is nothing to ask differently with.
type ListQuery struct {
	TenantID   string
	ActorID    string
	ActorRoles []string
	// PageToken is opaque and bounded to the tenant that minted it.
	PageToken string
	PageSize  int32
}

// ListPage is one page of the caller's repositories.
//
// It has no total, and that absence is the point: no field here is capable of expressing how many
// repositories the caller may NOT see, so non-enumeration is a property of the type rather than a
// discipline someone has to remember (SPEC-0052 AC5, mirroring SPEC-0035 AC3).
type ListPage struct {
	Repositories  []RepositoryView
	NextPageToken string
}

// Lister is the listing port. It is separate from Reader because a list is a different question
// from a lookup: a lookup answers about a repository the caller named, and a list answers which
// repositories exist for them at all — which is an authorization-derived answer, not a read.
type Lister interface {
	List(ctx context.Context, q ListQuery) (ListPage, error)
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
	Lister
	// Settings arrived with SPEC-0057. It is part of the full surface rather than a separate
	// service over the same store: settings are properties of the registry record, and two
	// services over one row would be two places that decide what a repository is.
	Settings
}
