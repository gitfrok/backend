// Package api is the Residency context's in-process surface (T-0033, SPEC-0040, PRD G7).
//
// The context owns the two halves of residency the control plane is authoritative for:
// the DECLARATION — a tenant's chosen cloud and region, control-plane state recorded by an
// authorized owner decision with a server-set effective time (AC1, AC6) — and the registry
// of OBSERVED placements: where each data plane actually runs, as reported at enrolment and
// reconciled against the declaration (AC4). Observed and declared are different facts and
// the evidence pack shows both; a data plane reports placement, it never declares residency
// (SPEC-0040 "Data owned").
//
// Enforcement is a refusal at placement time (AC2): work that would place tenant data or
// compute outside the declared cloud/region is refused, and the refusal is witnessed with
// the declared and the attempted placement. A contradiction between a declaration and an
// already-observed placement is a visible violation state, raised synchronously — inside
// any configured detection window (AC3).
//
// What this surface carries and what it excludes is deliberate:
//
//   - No request shape carries a timestamp, a provenance or an outcome. Effective time is
//     the server's clock; violation state is a server fact derived from its own records.
//     A caller cannot assert either (AC1).
//   - Every failed operation — nonexistent, cross-tenant, malformed, unauthorized — is the
//     one coarse ErrResidencyUnavailable, so probing this surface cannot enumerate tenants
//     or declarations (SPEC-0001). The placement refusal is its own shape only because the
//     enrolment path must tell "refused" from "failed" to hand back a coarse enrolment
//     denial rather than an error.
//   - Setting a declaration is a PDP decision (residency.declaration.set, owner-only,
//     asked about the tenant — governance/policies authz.rego), never a role toggle
//     (invariant 2).
package api

import (
	"context"
	"errors"
	"time"
)

// ErrResidencyUnavailable is the ONE coarse shape for every failed residency operation: a
// nonexistent, cross-tenant, malformed or unauthorized request is indistinguishable from
// any other (SPEC-0001). A denial must never say why.
var ErrResidencyUnavailable = errors.New("residency: unavailable")

// ErrPlacementRefused reports a placement attempt outside the tenant's declared residency
// (SPEC-0040 AC2). The refusal itself is witnessed with both placements; the error is the
// enrolment path's signal to hand the presenter a coarse denial. It carries no placements —
// the presenter learns nothing more than "denied" (SPEC-0038 AC9).
var ErrPlacementRefused = errors.New("residency: placement refused")

// Declaration is one tenant's declared residency as control-plane state (AC1). Identity and
// the effective time are server-assigned; a caller supplies cloud and region only.
type Declaration struct {
	TenantID string
	Cloud    string
	Region   string
	// EffectiveAt is the server's instant the declaration was witnessed — the instant it
	// takes effect. It is a server fact, never a caller input: the pack answers "where was
	// this tenant pinned during the range" from these times, not from a claim (AC6).
	EffectiveAt time.Time
	// ActorID is the owner whose residency.declaration.set decision recorded the
	// declaration — named because residency is accountability evidence (G3).
	ActorID string
	// ChainSeq and RecordHash are the chain position of the immutable audit record
	// witnessing the declaration — the facts a pack consumer uses to re-derive the
	// citation from the tenant's chain (ADR-0007).
	ChainSeq   int64
	RecordHash string
}

// ObservedPlacement is one data plane's latest placement as the control plane observed it —
// the registry fact AC4 cites (SPEC-0040 "Data owned"). It names the plane and the
// placement, and nothing of the declaration: observed and declared are different facts.
type ObservedPlacement struct {
	DataPlaneID string
	Cloud       string
	Region      string
}

// Config is the per-environment residency configuration (invariant 13). No production value
// is compiled in; cmd/ supplies every field and tests inject clocks and short windows.
type Config struct {
	// DetectionWindow bounds how long a contradiction between declared and observed
	// placement may go unflagged (AC3). Detection runs synchronously when a placement is
	// observed and when a declaration takes effect, so realized latency is bounded by this
	// window by construction; the field exists so the bound is configuration an operator
	// can reason about, never a compiled-in constant.
	DetectionWindow time.Duration
	// MaxReportInterval is how long a data plane's placement reporting may be silent
	// before the evidence pack's residency section renders the silence as a gap rather
	// than reading it as compliance (AC5). The evidence assembler consumes this value
	// (SPEC-0040 non-functional); zero is fail-safe — every interval renders as a gap.
	MaxReportInterval time.Duration
	// Now is the clock every effective time and detection decision reads.
	Now func() time.Time
}

// WitnessEntry is one first-party record the residency lifecycle asks to be witnessed: who
// acted (empty when the actor is the platform itself), on which tenant or data plane, with
// which placements. It carries no outcome and no provenance — a residency record is always
// a control-plane-observed, first-party fact; the witness assigns the chain position and
// renders both when it adapts the tenant's trail.
type WitnessEntry struct {
	TenantID string
	// Action is the audited action vocabulary the platform appends under
	// (platform/audit): residency.declaration.set, residency.placement.observed,
	// residency.placement.refused, residency.placement.contradiction.
	Action string
	// ActorID is the principal whose action caused the record. Empty when the platform
	// itself is the actor — a refusal at enrolment or a contradiction raised at
	// declaration time carries no operator identity.
	ActorID string
	// Resource is what the record is about: "tenant/<tenant>" for a declaration,
	// "data_plane/<plane>" for a placement fact.
	Resource string
	// Detail carries BOTH placements the record relates, under the platform/audit
	// DetailResidency* keys: pinned (the declaration in force) and observed (the reported
	// or attempted placement). A consumer never needs a second record to judge either side.
	Detail map[string]string
	// Denied marks violation records — a refusal or a contradiction — so the witness
	// renders the trail outcome honestly. A declaration or an admitted observation is not
	// denied.
	Denied bool
	// OccurredAt is the server's instant the act was witnessed.
	OccurredAt time.Time
}

// WitnessRecord is the record as persisted: the chain position the witnessed fact cites
// (ADR-0007).
type WitnessRecord struct {
	Seq  int64
	Hash string
}

// Witness is the append-only first-party log the residency lifecycle writes its immutable
// records to. The Residency context declares what it needs of that log in its own terms
// and never imports the Audit module's surface: the composition root adapts the tenant's
// audit trail onto this port, keeping the module graph acyclic (invariant 14) and the
// direction honest (Residency is a producer of accountability evidence, not a consumer of
// Audit). A residency act that cannot be witnessed does not happen: an unrecorded
// declaration is a worse failure than a refused one.
type Witness interface {
	// AppendResidencyRecord appends one entry and returns the record as persisted,
	// including the chain position the writer assigned.
	AppendResidencyRecord(ctx context.Context, e WitnessEntry) (WitnessRecord, error)
}

// Service is the Residency context's surface: declare the tenant's residency, observe the
// placements its data planes actually run at, and read back the declaration in force. Every
// method that changes state appends the audit record for that act (SPEC-0040 G3/G6).
type Service interface {
	// Declare sets the tenant's declared residency. Declaring is a PDP decision
	// (residency.declaration.set, owner-only, asked about the tenant) and appends the
	// immutable audit record with the server-set effective time (AC1). A declaration is a
	// CHANGE, not a flattening: the record keeps its own effective time so a pack over a
	// range shows the change when one falls inside it (AC6). If a data plane's already-
	// observed placement contradicts the new declaration, the contradiction is witnessed
	// as a visible violation state before Declare returns (AC3). Changing a declared
	// residency is undesigned as migration (SPEC-0040 out of scope): a new declaration
	// renders as a change with no mechanism to move existing data.
	Declare(ctx context.Context, tenantID, actorID string, roles []string, cloud, region string) (Declaration, error)
	// Declaration reads the tenant's declaration in force. ok is false when the tenant
	// has declared nothing — an undeclared tenant pins nothing, and placement is then
	// unconstrained by residency. Cross-tenant and unauthorized reads are the same coarse
	// denial as an absent one (SPEC-0001).
	Declaration(ctx context.Context, tenantID string) (Declaration, bool, error)
	// ObservePlacement records one placement the control plane observed for a data plane
	// — the placement reported at enrolment (SPEC-0040 "Contracts touched"). With a
	// declaration in force, a contradicting placement is REFUSED: the refusal is
	// witnessed with the declared and the attempted placement and ErrPlacementRefused is
	// returned (AC2); the declaration is never redefined by the attempt (AC1). A matching
	// placement — or any placement for an undeclared tenant — is witnessed as observed.
	ObservePlacement(ctx context.Context, tenantID, dataPlaneID, cloud, region string) error
}
