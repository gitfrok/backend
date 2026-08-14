package api

import "time"

// The Code Search context's domain events (SPEC-0034, SPEC-0035). Like the Repository context's
// events they are plain structs, not the generated protobuf types, because a module's api/ exposes
// no infrastructure (invariant 20). Each one mirrors a message in
// governance/contracts/events/search/v1 field-for-field, and events_contract_test.go fails if the
// two drift — that parity is what makes moving a subscription onto Redpanda a transport swap
// rather than a payload rewrite (ADR-0025, ADR-0026).
//
// Events carry opaque identifiers, tenant scope, revision and lag; they never carry matched
// content, source code, or a permission fact (SPEC-0035).
//
// The names are the protobuf full names: the bus routing key and the future topic key are the
// same string.
const (
	EventRepositoryIndexed = "gitsaas.events.search.v1.RepositoryIndexed"
	EventIndexLagged       = "gitsaas.events.search.v1.IndexLagged"
)

// Event is the contract a Code Search event satisfies. It is structurally identical to bus.Event;
// declaring it here keeps the api/ surface self-describing without importing the platform.
type Event interface {
	EventName() string
	Tenant() string
}

// RepositoryIndexed records that the index absorbed a repository revision. Indexing is
// incremental off Repository/Git's ref-update events (SPEC-0034 AC4); each absorbed revision
// lands one of these.
type RepositoryIndexed struct {
	EventID      string
	TenantID     string
	RepositoryID string
	// Revision is the opaque revision the index absorbed.
	Revision   string
	OccurredAt time.Time
}

// EventName is the routing key, matching the contracts/events message full name.
func (RepositoryIndexed) EventName() string { return EventRepositoryIndexed }

// Tenant reports the owning tenant; the bus refuses to publish without one (invariant 1).
func (e RepositoryIndexed) Tenant() string { return e.TenantID }

// IndexLagged records that a repository's index freshness exceeded the stated bound. Exceeding
// the bound is a reported condition, not a silent delay (SPEC-0034 non-functional); the event
// carries the measured lag, never matched content or a permission fact.
type IndexLagged struct {
	EventID      string
	TenantID     string
	RepositoryID string
	// LastIndexedRevision is the opaque revision the index last absorbed when the lag was
	// measured.
	LastIndexedRevision string
	// Lag is the measured freshness lag at reporting time.
	Lag        time.Duration
	OccurredAt time.Time
}

// EventName is the routing key, matching the contracts/events message full name.
func (IndexLagged) EventName() string { return EventIndexLagged }

// Tenant reports the owning tenant; the bus refuses to publish without one (invariant 1).
func (e IndexLagged) Tenant() string { return e.TenantID }

var (
	_ Event = RepositoryIndexed{}
	_ Event = IndexLagged{}
)
