package audit

import "time"

// ActionFindingsTriaged is the `action` value for a recorded triage
// transition (SPEC-0026 AC4).
const ActionFindingsTriaged = "findings.triaged"

// FindingsTriaged records that an authorized actor set a triage state on a
// finding identity. SPEC-0026 AC4: a triage transition is a control action —
// authorized by the PDP and audited — so every accepted transition appends
// exactly ONE immutable record naming the actor, the finding, the prior and
// new state, and the decision ID that authorized it (ADR-0006, ADR-0007).
//
// It carries no justification text and no provenance bytes: the
// justification stays with the triage record in Security/Findings' own
// store, and an audit reader needs the transition, not the prose. The replay
// and version-mismatch guards in the triage service are what keep this
// emission exactly-once per recorded transition.
type FindingsTriaged struct {
	TenantID     string
	ActorID      string
	RepositoryID string
	FindingID    string
	// TriageID is the opaque identity of the triage record the transition
	// wrote.
	TriageID string
	// PriorState and NewState are the transition's endpoints, as the
	// Security/Findings vocabulary strings; PriorState is empty for the
	// first decision on a finding.
	PriorState string
	NewState   string
	RequestID  string
	// PolicyDecisionID correlates the record with the PDP decision that
	// authorized the transition (SPEC-0026 AC4).
	PolicyDecisionID string
	OccurredAt       time.Time
}

func (FindingsTriaged) EventName() string { return EventAudit }
func (e FindingsTriaged) Action() string  { return ActionFindingsTriaged }
func (e FindingsTriaged) Tenant() string  { return e.TenantID }
