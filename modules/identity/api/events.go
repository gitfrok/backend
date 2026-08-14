// Auditor grant lifecycle events (SPEC-0033, T-0027, PRD PR-18).
//
// They mirror contracts/events/identity/v1: opaque identifiers, tenant scope
// and the grant's scope — never pack contents, source, or a policy allow
// flag. Each lifecycle transition names BOTH the granting admin and the
// auditor principal, because that pairing is the whole accountability story
// of an external party reading the tenant's evidence (SPEC-0033 AC4).
//
// These events announce the lifecycle on the bus; the immutable audit
// records AC4 requires are appended to the audit chain separately
// (ADR-0007) by the grant service, correlated to the PDP decisions that
// authorized each transition.
package api

import "time"

// Event names — the protobuf full names of the contracts/events messages,
// matching how every other event in this repo is keyed.
const (
	EventAuditorGrantIssued  = "gitsaas.events.identity.v1.AuditorGrantIssued"
	EventAuditorGrantRevoked = "gitsaas.events.identity.v1.AuditorGrantRevoked"
	EventAuditorGrantExpired = "gitsaas.events.identity.v1.AuditorGrantExpired"
)

// AuditorGrantIssued records that an authorized admin issued a scoped,
// read-only, time-boxed grant (SPEC-0033 AC4). It carries the grant's
// identity, scope and expiry — opaque identifiers and scope only, never pack
// contents. Replaying the issue request produces no second event.
type AuditorGrantIssued struct {
	EventID  string
	TenantID string
	// GrantID is the opaque, server-assigned grant identity.
	GrantID string
	// GrantedBy is the admin whose auditor.grant.manage decision issued the
	// grant, authenticated and PDP-authorized (SPEC-0033 AC4).
	GrantedBy string
	// AuditorPrincipalID is the auditor principal the grant authorizes.
	AuditorPrincipalID string
	// RangeFrom and RangeTo are the inclusive bounds of the evidence scope
	// the granted packs cover.
	RangeFrom time.Time
	RangeTo   time.Time
	// RepositoryID is the optional repository scope; empty covers the
	// tenant's repositories.
	RepositoryID string
	// PackIDs are the named packs the grant authorizes, as opaque pack
	// identities. Scope only: a pack's contents never travel in an event.
	PackIDs []string
	// ExpiresAt is the instant the grant stops authorizing reads, as the
	// server recognized it at issue time.
	ExpiresAt time.Time
	// DecisionID is the PDP decision that authorized issuance.
	DecisionID string
	OccurredAt time.Time
}

func (AuditorGrantIssued) EventName() string { return EventAuditorGrantIssued }
func (e AuditorGrantIssued) Tenant() string  { return e.TenantID }

// AuditorGrantRevoked records that an authorized admin terminated a grant
// (SPEC-0033 AC4). Revocation takes effect on the next decision — grant
// state is a decision-time fact, so there is no cache cycle to wait out
// (SPEC-0033 AC7). It names the revoking admin, the granting admin and the
// auditor principal.
type AuditorGrantRevoked struct {
	EventID  string
	TenantID string
	GrantID  string
	// ActorID is the admin who revoked the grant, authenticated and
	// PDP-authorized.
	ActorID string
	// GrantedBy is the admin who originally issued the grant.
	GrantedBy          string
	AuditorPrincipalID string
	// DecisionID is the PDP decision that authorized the revocation.
	DecisionID string
	OccurredAt time.Time
}

func (AuditorGrantRevoked) EventName() string { return EventAuditorGrantRevoked }
func (e AuditorGrantRevoked) Tenant() string  { return e.TenantID }

// AuditorGrantExpired records that a grant passed its expiry without any
// operator action (SPEC-0033 AC3). The actor is the platform itself, so the
// event carries no actor identity at all — while the granting admin and the
// auditor principal stay named, because an expiry is still a lifecycle fact
// about their pairing (SPEC-0033 AC4). From this instant every evidence read
// under the grant is denied by construction: expiry arrives as a
// decision-time fact.
type AuditorGrantExpired struct {
	EventID            string
	TenantID           string
	GrantID            string
	GrantedBy          string
	AuditorPrincipalID string
	OccurredAt         time.Time
}

func (AuditorGrantExpired) EventName() string { return EventAuditorGrantExpired }
func (e AuditorGrantExpired) Tenant() string  { return e.TenantID }
