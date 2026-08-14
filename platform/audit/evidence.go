// Evidence pack lifecycle events (T-0026, SPEC-0031, SPEC-0032).
//
// They mirror contracts/events/audit/v1's EvidencePackRequested and
// EvidencePackCompleted: opaque identifiers, tenant scope, range bounds and
// section counts — never record contents, source, or provenance bytes
// (SPEC-0032 G9). The statistics travel here; the records travel in the pack.
package audit

import "time"

// Event names — the protobuf full names of the contracts/events messages,
// matching how every other event in this repo is keyed.
const (
	EventEvidencePackRequested = "gitsaas.events.audit.v1.EvidencePackRequested"
	EventEvidencePackCompleted = "gitsaas.events.audit.v1.EvidencePackCompleted"
)

// The reviewed action vocabulary T-0026 adds (SPEC-0032): generation is the
// compliance owner's act, asked about the tenant; retrieval is asked about
// the pack itself. Both are PDP decisions with server-derived context.
const (
	ActionEvidencePackGenerate = "evidence.pack.generate"
	ActionEvidencePackRead     = "evidence.pack.read"
)

// EvidencePackRequested records that a compliance owner requested a
// date-ranged evidence pack. It is emitted after the PDP authorized
// generation; a denied request is the PDP's own denial record, not this.
type EvidencePackRequested struct {
	EventID   string
	TenantID  string
	ActorID   string
	PackID    string
	RequestID string
	// The closed range the pack covers, exactly as requested.
	RangeFrom time.Time
	RangeTo   time.Time
	// The optional repository scope; empty covers the tenant's repositories.
	RepositoryID string
	OccurredAt   time.Time
}

func (EvidencePackRequested) EventName() string { return EventEvidencePackRequested }
func (e EvidencePackRequested) Tenant() string  { return e.TenantID }

// EvidencePackCompleted records that a requested pack finished assembling —
// ready, or failed. It carries section counts, never record contents, source,
// or provenance bytes (SPEC-0032 G9).
type EvidencePackCompleted struct {
	EventID  string
	TenantID string
	// ActorID is the actor whose request produced the pack.
	ActorID string
	PackID  string
	// State is READY or FAILED, as the string rendering of audit.v1.PackState.
	// A string rather than an import of the RPC enum: the event keeps no
	// dependency on the audit RPC wire shape, and a new state is additive by
	// construction.
	State string
	// SectionCounts are the control records assembled per section, keyed by
	// section name: "approvals", "policy_decisions", "scan_gates",
	// "access_changes".
	SectionCounts map[string]int64
	// AppendixRecordCount counts the attested records assembled into the
	// labelled appendix. A statistic only: attested content itself travels in
	// the pack, never in this event.
	AppendixRecordCount int64
	// The closed range the pack covers.
	RangeFrom  time.Time
	RangeTo    time.Time
	OccurredAt time.Time
}

func (EvidencePackCompleted) EventName() string { return EventEvidencePackCompleted }
func (e EvidencePackCompleted) Tenant() string  { return e.TenantID }
