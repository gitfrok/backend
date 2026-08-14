package api

import "time"

// The Security/Findings context's domain events (SPEC-0024, SPEC-0025). They
// are part of the module's public surface: other contexts react to them
// through platform/bus rather than calling in (invariant 17), building their
// own tenant-scoped local projections and never calling back into
// Security/Findings on a hot path (ADR-0022).
//
// They are plain structs, not the generated protobuf types, because a
// module's api/ exposes no infrastructure (invariant 20). Each one mirrors a
// message in governance/contracts/events/security/v1 field-for-field, and
// events_contract_test.go fails if the two drift — that parity is what makes
// moving a subscription onto Redpanda a transport swap rather than a payload
// rewrite (ADR-0025, ADR-0026).
//
// The names are the protobuf full names: the bus routing key and the future
// topic key are the same string.
const (
	EventScanIngested    = "gitsaas.events.security.v1.ScanIngested"
	EventFindingOpened   = "gitsaas.events.security.v1.FindingOpened"
	EventFindingResolved = "gitsaas.events.security.v1.FindingResolved"
	EventFindingTriaged  = "gitsaas.events.security.v1.FindingTriaged"
)

// Event is the contract a Security/Findings event satisfies. It is
// structurally identical to bus.Event; declaring it here keeps the api/
// surface self-describing without importing the platform.
type Event interface {
	EventName() string
	Tenant() string
}

// ScanIngested records that a completed scan's results were ingested. It is
// emitted once per scan, after the final chunk lands; a replayed ingest
// emits nothing new (SPEC-0025 AC1). Like every event here it carries opaque
// identifiers, tenant and repository scope, tool identity, and severity
// facts — never provenance bytes, scanner credentials, source code, or a
// policy allow flag.
type ScanIngested struct {
	EventID      string
	TenantID     string
	RepositoryID string
	ScanID       string
	ScannerClass ScannerClass
	ToolName     string
	ToolVersion  string
	Revision     string
	FindingCount int64
	OccurredAt   time.Time
}

// EventName is the routing key, matching the contracts/events message full name.
func (ScanIngested) EventName() string { return EventScanIngested }

// Tenant reports the owning tenant; the bus refuses to publish without one (invariant 1).
func (e ScanIngested) Tenant() string { return e.TenantID }

// FindingOpened records that ingestion produced a finding no scan had
// reported before. Its identity is the one the server computed (SPEC-0024);
// the event never carries a caller-supplied one.
type FindingOpened struct {
	EventID      string
	FindingID    string
	TenantID     string
	RepositoryID string
	ScanID       string
	ScannerClass ScannerClass
	ToolName     string
	RuleID       string
	Severity     Severity
	OccurredAt   time.Time
}

// EventName is the routing key, matching the contracts/events message full name.
func (FindingOpened) EventName() string { return EventFindingOpened }

// Tenant reports the owning tenant; the bus refuses to publish without one (invariant 1).
func (e FindingOpened) Tenant() string { return e.TenantID }

// FindingResolved records that a later scan no longer reports an open
// finding. The finding is resolved, not deleted: its identity and history
// remain retrievable (SPEC-0024 AC9).
type FindingResolved struct {
	EventID      string
	FindingID    string
	TenantID     string
	RepositoryID string
	// ScanID is the scan that first failed to report the finding again.
	ScanID       string
	ScannerClass ScannerClass
	ToolName     string
	RuleID       string
	Severity     Severity
	OccurredAt   time.Time
}

// EventName is the routing key, matching the contracts/events message full name.
func (FindingResolved) EventName() string { return EventFindingResolved }

// Tenant reports the owning tenant; the bus refuses to publish without one (invariant 1).
func (e FindingResolved) Tenant() string { return e.TenantID }

// FindingTriaged records that an authorized actor set a triage state on a
// finding identity (SPEC-0026, SPEC-0027). It carries prior and new state so
// a consumer can project transitions without reading back; PriorState is
// TriageStateUnspecified for the first decision on a finding. It never
// carries justification text, provenance bytes, source code, or a policy
// outcome — the decision that authorized the transition lives in the audit
// record (SPEC-0026 AC4), not in this event.
type FindingTriaged struct {
	EventID      string
	FindingID    string
	TenantID     string
	RepositoryID string
	// TriageID is the opaque identity of the triage record this transition
	// wrote.
	TriageID   string
	PriorState TriageState
	NewState   TriageState
	// ActorID is the verified actor who recorded the decision.
	ActorID    string
	OccurredAt time.Time
}

// EventName is the routing key, matching the contracts/events message full name.
func (FindingTriaged) EventName() string { return EventFindingTriaged }

// Tenant reports the owning tenant; the bus refuses to publish without one (invariant 1).
func (e FindingTriaged) Tenant() string { return e.TenantID }

var (
	_ Event = ScanIngested{}
	_ Event = FindingOpened{}
	_ Event = FindingResolved{}
	_ Event = FindingTriaged{}
)
