package audit

import "time"

// ActionReplicaForcePromote is the `action` value for an operator force-promotion of an async
// replica after a confirmed dual primary+sync loss (ADR-0018, ADR-0042 §4, ADR-0046, SPEC-0018 AC5).
//
// Force-promote is the only auditable action the Replica context emits: it is the point where a
// deliberate, possibly data-losing recovery decision is taken, and the trail must capture the shard,
// the old/new fencing terms, the selected replica, the estimated RPO window, the authorizing actor,
// and the PDP decision that permitted it. The coordinator publishes exactly one such event per
// accepted force-promote and never for a denial (denials use the existing policy.decision.denied path).
const ActionReplicaForcePromote = "replica.force_promote"

// ForcePromote records one accepted replica force-promotion. It carries no filesystem path, no
// repository contents, no credentials, and no caller-provided authorization assertion: the PDP
// decision ID is audit context only (ADR-0046 §2). The `detail` map on the stored AuditEvent is
// assembled from these bounded fields by the audit writer.
type ForcePromote struct {
	TenantID            string
	RepositoryID        string
	PreviousTerm        uint64
	ResultingTerm       uint64
	TargetNode          string // operator-selected async replica
	EstimatedRPOSeconds uint32
	ActorID             string // verified platform-operator principal
	PolicyDecisionID    string // the PDP allow that authorized this recovery
	OccurredAt          time.Time
}

// EventName is the routing key — the contract's message full name, as for every audit event.
func (ForcePromote) EventName() string { return EventAudit }

// Action is the dotted action this event records, carried in the contract's `action` field.
func (ForcePromote) Action() string { return ActionReplicaForcePromote }

// Tenant reports the owning tenant so the bus honours invariant 1.
func (e ForcePromote) Tenant() string { return e.TenantID }
