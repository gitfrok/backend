// Auditor grant surface — the Identity&Access port for scoped, read-only,
// time-boxed auditor access (SPEC-0033, T-0027, PRD PR-18).
//
// A grant is a DISTINCT principal shape, not a role that happens to read
// less: it is scoped to a tenant, a closed date range and the named packs
// within it, is read-only, is time-boxed, and confers NO repository read.
// What this surface encodes mirrors contracts/proto/identity/v1/auditor_grant
// field for field, and what it excludes is as deliberate as what it carries:
//
//   - No request shape here carries grant state, a decision outcome, or a
//     renewal. State is a server fact derived at read time from the stored
//     record and the server's clock; widening a grant is a new issue
//     decision, never a field a caller can set (SPEC-0033 AC8).
//   - Every failed operation — nonexistent, cross-tenant, revoked, expired,
//     malformed, unauthorized — is the one coarse ErrGrantUnavailable, so
//     probing this surface cannot enumerate grants or tenants (SPEC-0001).
//   - Enforcement is a PDP decision (auditor.grant.manage asked about the
//     tenant; evidence.pack.read gated by decision-time grant facts), never
//     a role toggle or a token scope claim (SPEC-0033 AC5).
package api

import (
	"context"
	"errors"
	"time"
)

// ErrGrantUnavailable is the ONE coarse shape for every failed grant
// operation: a nonexistent, cross-tenant, already-revoked, expired,
// malformed or unauthorized request is indistinguishable from any other
// (SPEC-0001, SPEC-0033 AC6/AC7). A denial must never say why.
var ErrGrantUnavailable = errors.New("identity: auditor grant unavailable")

// GrantState is the lifecycle of a grant, as the string facts the reviewed
// policy consumes (governance/policies authz.rego, T-0027): "ACTIVE" is the
// only state that reads. The zero value is never a state a grant holds; a
// decision presented with it fails closed.
type GrantState string

const (
	// GrantActive: issued and not yet expired or revoked; readable under its
	// scope.
	GrantActive GrantState = "ACTIVE"
	// GrantRevoked: terminated by an authorized admin before expiry.
	// Immediate — the next decision reads the state fresh and fails
	// (SPEC-0033 AC7).
	GrantRevoked GrantState = "REVOKED"
	// GrantExpired: past its expiry. Expiry happens without an operator
	// action (SPEC-0033 AC3); the state is the server's rendering of its own
	// clock at read time.
	GrantExpired GrantState = "EXPIRED"
)

// AuditorGrant is one scoped, read-only, time-boxed grant record. Identity,
// state and timestamps are server-assigned; a caller supplies scope and
// requested expiry only. It carries no repository permission, no role that
// implies one, and no renewal-on-use — using a grant never mutates it
// (SPEC-0033 AC8).
type AuditorGrant struct {
	// GrantID is the opaque, server-assigned grant identity.
	GrantID string
	// TenantID is the tenant the grant is scoped to. A grant can never span
	// two tenants.
	TenantID string
	// AuditorPrincipalID is the auditor principal the grant authorizes.
	AuditorPrincipalID string
	// RangeFrom and RangeTo are the inclusive bounds of the evidence range
	// the granted packs must cover.
	RangeFrom time.Time
	RangeTo   time.Time
	// RepositoryID is the optional repository scope; empty covers the
	// tenant's repositories. It NARROWS which packs the grant can name — it
	// is not a repository permission and confers no repository read
	// (SPEC-0033 AC1).
	RepositoryID string
	// PackIDs are the named packs the grant authorizes reading, as opaque
	// pack identities. A pack not named here is out of scope, whatever its
	// range.
	PackIDs []string
	// ExpiresAt is the instant the grant stops authorizing reads, on the
	// server's clock. The server recognizes it at decision time; no operator
	// action is required for it to take effect (SPEC-0033 AC3).
	ExpiresAt time.Time
	// GrantedBy is the admin whose auditor.grant.manage decision issued the
	// grant — named on the record because grant lifecycle is itself
	// accountability evidence (SPEC-0033 AC4).
	GrantedBy string
	IssuedAt  time.Time
	// RevokedAt is set when the grant is revoked; zero otherwise.
	RevokedAt time.Time
	// State is the server-derived lifecycle at read time — a response
	// rendering of Identity&Access's own record, never an input to any
	// decision, which reads this fact fresh instead (SPEC-0033 AC7).
	State GrantState
}

// GrantContext carries the request identity the contract's
// AuditorGrantContext encodes. Tenant and actor are NOT fields here: they
// come from the authenticated request context (tenancy + principal), because
// a caller cannot assert them (SPEC-0033). The request ID is the idempotency
// key issuance replays against.
type GrantContext struct {
	RequestID string
}

// GrantIssue is the scope an admin requests when issuing a grant, and nothing
// else. It deliberately has no field for grant identity, state, versions, or
// an extension of an existing grant: widening a grant is a new decision, and
// state is a fact only the server can hold (SPEC-0033 AC8).
type GrantIssue struct {
	// AuditorPrincipalID is the auditor principal the grant will authorize.
	AuditorPrincipalID string
	// RangeFrom and RangeTo are the inclusive bounds of the evidence range.
	// Required; from after to is rejected — the range is closed, never
	// half-open.
	RangeFrom time.Time
	RangeTo   time.Time
	// RepositoryID optionally narrows which packs the grant may name.
	RepositoryID string
	// PackIDs are the packs the grant names. Required and non-empty: a grant
	// with no named packs authorizes nothing and is rejected at issue time.
	PackIDs []string
	// ExpiresAt is the requested expiry. A missing (zero) expiry is rejected
	// — a grant is time-boxed by construction (SPEC-0033 AC3).
	ExpiresAt time.Time
}

// GrantTransitionKind names one lifecycle transition the platform witnessed.
type GrantTransitionKind string

const (
	// GrantIssued: an authorized admin issued the grant (SPEC-0033 AC4).
	GrantIssued GrantTransitionKind = "ISSUED"
	// GrantRevocation: an authorized admin terminated the grant before expiry.
	GrantRevocation GrantTransitionKind = "REVOKED"
	// GrantExpiration: the grant passed its expiry without an operator action
	// (SPEC-0033 AC3). The actor is the platform itself.
	GrantExpiration GrantTransitionKind = "EXPIRED"
)

// GrantTransition is one lifecycle transition witnessed by Identity&Access,
// as first-party evidence: the immutable audit record's chain position, the
// principals AC4 names, and the decision that authorized the transition.
// Transitions are what the evidence pack's access-changes section cites
// (SPEC-0032 assumption) — scope and lifecycle only, never pack contents.
type GrantTransition struct {
	Kind GrantTransitionKind
	// ChainSeq and RecordHash are the chain position of the immutable audit
	// record witnessing the transition — the facts a pack consumer uses to
	// re-derive the citation from the tenant's chain (ADR-0007).
	ChainSeq   int64
	RecordHash string
	// GrantID is the grant the transition belongs to.
	GrantID string
	// ActorID is the admin whose action caused the transition — the granting
	// admin for ISSUED, the revoking admin for REVOKED. Empty for EXPIRED:
	// the actor is the platform itself, so the record carries no actor
	// identity at all.
	ActorID string
	// GrantedBy names the admin who issued the grant on EVERY transition,
	// because each one is evidence about that pairing (SPEC-0033 AC4).
	GrantedBy string
	// AuditorPrincipalID is the auditor the grant authorizes.
	AuditorPrincipalID string
	// RepositoryID is the grant's repository scope at issue time — empty
	// covers the tenant's repositories.
	RepositoryID string
	// DecisionID correlates to the PDP decision that authorized the
	// transition. Empty for EXPIRED: expiry takes effect without a decision.
	DecisionID string
	OccurredAt time.Time
}

// GrantDecisionFacts are the grant's validity facts a PEP supplies FRESH on
// every evidence.pack.read decision for an auditor principal
// (governance/policies authz.rego, T-0027). Grant state, expiry and scope
// are facts read from Identity&Access at decision time; none is a caller
// claim. A revoked or expired grant therefore fails the very next decision
// by construction — there is no cached decision or token to outlive it
// (SPEC-0033 AC7).
type GrantDecisionFacts struct {
	GrantID   string
	State     GrantState
	TenantID  string
	ExpiresAt time.Time
	RangeFrom time.Time
	RangeTo   time.Time
	// RepositoryID is the grant's repository scope as issued (SPEC-0033
	// AC1): empty covers the tenant's repositories, non-empty narrows them.
	// It travels to the decision additively so the policy CAN compare a
	// grant's scope against the pack's; the reviewed rego bundle does not
	// consume it yet — wiring it into a rule is a governance-first contract
	// change (SPEC-0033 AC8 forbids widening in the meantime, and AC1
	// describes this scope).
	RepositoryID string
	Packs        []string
}

// AuditorGrants is the Identity&Access auditor grant surface in-process,
// mirroring AuditorGrantService in contracts/proto/identity/v1 plus the two
// server-side reads the enforcement and evidence paths compose on: decision
// facts for the PEP (SPEC-0033 AC7) and lifecycle transitions for the
// evidence pack's access-changes section (SPEC-0032).
type AuditorGrants interface {
	// IssueGrant issues a scoped, read-only, time-boxed grant. Issuing is a
	// PDP decision (auditor.grant.manage, owner-only, asked about the
	// tenant) and appends the immutable audit record naming the granting
	// admin and the auditor principal (SPEC-0033 AC4). Idempotent per tenant
	// and request ID: replaying a request ID returns the same grant and
	// appends nothing new.
	IssueGrant(ctx context.Context, c GrantContext, req GrantIssue) (AuditorGrant, error)
	// RevokeGrant terminates a grant. Revocation takes effect on the next
	// decision: grant state is read at decision time (SPEC-0033 AC7).
	// Revoking is a PDP decision and is audited. Not-found, cross-tenant,
	// already-revoked, expired and unauthorized are the same coarse denial.
	RevokeGrant(ctx context.Context, c GrantContext, grantID string) (AuditorGrant, error)
	// ListGrants returns the tenant's grants for administration, optionally
	// narrowed to one auditor principal. Scope, state and lifecycle only —
	// never pack contents. Listing is a PDP decision (auditor.grant.manage);
	// a cross-tenant or unauthorized list is the same coarse denial as an
	// empty one. Grants past their expiry are rendered EXPIRED and their
	// expiry is recognized — no operator action is required (SPEC-0033 AC3).
	ListGrants(ctx context.Context, c GrantContext, auditorPrincipalID string) ([]AuditorGrant, error)
	// GrantFacts reads the decision-time validity facts for the grant this
	// tenant issued to auditorPrincipalID naming packID. ok is false when no
	// such grant exists — absent facts fail the decision closed
	// (SPEC-0033). The read recognizes expiry the same way listing does.
	GrantFacts(ctx context.Context, auditorPrincipalID, packID string) (GrantDecisionFacts, bool, error)
	// GrantTransitions returns the tenant's witnessed lifecycle transitions
	// whose instant lies within the inclusive range, narrowed to grants
	// scoped to repositoryID when non-empty (a grant with an empty repository
	// scope covers the tenant's repositories and is included either way).
	// The ctx tenant must match tenantID; a mismatch is a coarse error.
	GrantTransitions(ctx context.Context, tenantID string, from, to time.Time, repositoryID string) ([]GrantTransition, error)
}
