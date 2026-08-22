// Package domain is the Repository context's core model. It imports NO infrastructure
// (no pg/grpc/http/opa/redpanda) — dependencies point inward (invariant 16).
package domain

import (
	"errors"
	"time"
)

// TenantID scopes every aggregate; there is no un-tenant-scoped repository (invariant 1).
type TenantID string

// RepoID identifies a repository within a tenant.
type RepoID string

// Repository is the aggregate root of the Repository context.
//
// The settings fields (SPEC-0057) are properties of this aggregate rather than a separate one: a
// second aggregate keyed on the same identity would be a second answer to whether the repository
// exists, and ADR-0071 makes this record the product's truth for that.
type Repository struct {
	Tenant TenantID
	ID     RepoID
	Name   string
	// Description is prose about the repository. Empty is the ordinary state, not a missing value.
	Description string
	// ArchivedAt is when the repository was archived, zero when it is not. There is no paired
	// boolean: a flag and an instant can disagree.
	//
	// It is a LABEL. Nothing in this aggregate makes an archived repository read-only, and
	// nothing may: a read-only condition names its cause from api/readonly.go's two-member
	// vocabulary, and adding a third is a decision about the git write path (ADR-0076, SPEC-0057).
	ArchivedAt time.Time
	// SettingsUpdatedAt and SettingsUpdatedBy travel together — a record naming an actor with no
	// instant, or an instant with no actor, is half a record.
	SettingsUpdatedAt time.Time
	SettingsUpdatedBy string
	// MergeStrategy is the landing policy's strategy: empty means no explicit
	// choice, and merges land exactly as they always did — fast-forward when
	// possible (SPEC-0065 AC1). The vocabulary lives in api so the aggregate
	// stays a dumb holder of what the record says.
	MergeStrategy string
	// TrunkBased constrains the shape of landings, never who may land or
	// whether: merge commits are refused, fast-forward preferred, rebase the
	// fallback (ADR-0088). It is a property of the record like archival is.
	TrunkBased bool
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
