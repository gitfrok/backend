// Residency audit vocabulary (T-0033, SPEC-0040).
//
// Residency is G7: a tenant's declared cloud and region, enforced on placement, with the
// contradiction evidence an auditor can re-derive from the tenant's own chain. Every act the
// Residency context witnesses appends an immutable, first-party record through the context's
// own witness port (the GrantWitness pattern, ADR-0022): the declaration and its effective
// time, each control-plane-observed placement, each refused placement attempt, and each
// contradiction between a declaration and an already-observed placement. The dotted
// vocabulary lives in the audit contract's comment; adding one is additive by construction.
//
// The residency section of the evidence pack classifies exactly these four actions out of
// the tenant's chain (SPEC-0040 AC4): the chain IS the projection the Residency context
// feeds, so the section cites only control-plane-observed, first-party facts — a customer
// claim has no path into these actions (SPEC-0040 AC7).
package audit

const (
	// ActionResidencyDeclarationSet is both the reviewed policy action for setting a
	// tenant's declared residency (governance/policies authz.rego, owner-only, asked about
	// the tenant) and the `action` value the witnessing trail record carries — the same
	// shape evidence-pack generation uses. The record's effective time is the server's
	// clock at witness time; a caller never supplies one (SPEC-0040 AC1, AC6).
	ActionResidencyDeclarationSet = "residency.declaration.set"
	// ActionResidencyPlacementObserved records one placement the control plane observed:
	// the placement a data plane reported at enrolment, reconciled against the tenant's
	// declaration in force and admitted (SPEC-0040 AC4).
	ActionResidencyPlacementObserved = "residency.placement.observed"
	// ActionResidencyPlacementRefused records one refused placement attempt: work that
	// would place tenant data or compute outside the declared cloud/region is refused,
	// with the declared and the attempted placement both on the record (SPEC-0040 AC2).
	ActionResidencyPlacementRefused = "residency.placement.refused"
	// ActionResidencyPlacementContradiction records a visible violation state: a
	// declaration taking effect against a placement already observed for one of the
	// tenant's data planes. Detection is synchronous at declaration time, so the state is
	// raised inside any configured detection window (SPEC-0040 AC3).
	ActionResidencyPlacementContradiction = "residency.placement.contradiction"
)

// Detail keys the residency witness writes onto its trail records. The evidence pack's
// residency classifier reads exactly these keys; they are server-produced facts, never
// caller claims. Every residency record carries both placements it relates — pinned
// (the declaration in force) and observed (the placement reported or attempted) — so a
// consumer never needs a second record to judge either side (SPEC-0040 AC2, AC4).
const (
	DetailResidencyPinnedCloud    = "pinned_cloud"
	DetailResidencyPinnedRegion   = "pinned_region"
	DetailResidencyObservedCloud  = "observed_cloud"
	DetailResidencyObservedRegion = "observed_region"
)
