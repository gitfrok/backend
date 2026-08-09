package api

import "time"

// The Repository context's domain events. These are part of the module's public surface: other
// modules react to them through platform/bus rather than calling in (invariant 17).
//
// They are plain structs, not the generated protobuf types, because a module's api/ exposes no
// infrastructure (invariant 20). Each one mirrors a message in
// governance/contracts/events/repository/v1 field-for-field, and events_contract_test.go fails if
// the two drift — that parity is what makes moving a subscription onto Redpanda a transport swap
// rather than a payload rewrite (ADR-0025, ADR-0026).
//
// The names are the protobuf full names: the bus routing key and the future topic key are the
// same string.
const (
	EventRepositoryCreated = "gitsaas.events.repository.v1.RepositoryCreated"
	EventRefUpdated        = "gitsaas.events.repository.v1.RefUpdated"
)

// Event is the contract a Repository event satisfies. It is structurally identical to bus.Event;
// declaring it here keeps the api/ surface self-describing without importing the platform.
type Event interface {
	EventName() string
	Tenant() string
}

// RepositoryCreated is emitted once a repository exists and is durable.
type RepositoryCreated struct {
	EventID    string
	TenantID   string
	RepoID     string
	CreatedBy  string
	OccurredAt time.Time
}

// EventName is the routing key, matching the contracts/events message full name.
func (RepositoryCreated) EventName() string { return EventRepositoryCreated }

// Tenant reports the owning tenant; the bus refuses to publish without one (invariant 1).
func (e RepositoryCreated) Tenant() string { return e.TenantID }

// RefUpdated is emitted when a ref moves. The git write path that publishes it lands with the
// Git-RPC service (T-0010); the shape is declared here so consumers can be written against it now.
type RefUpdated struct {
	EventID    string
	TenantID   string
	RepoID     string
	Ref        string
	OldSha     string
	NewSha     string
	ActorID    string
	ActorRoles []string
	OccurredAt time.Time
}

// EventName is the routing key, matching the contracts/events message full name.
func (RefUpdated) EventName() string { return EventRefUpdated }

// Tenant reports the owning tenant; the bus refuses to publish without one (invariant 1).
func (e RefUpdated) Tenant() string { return e.TenantID }

var (
	_ Event = RepositoryCreated{}
	_ Event = RefUpdated{}
)
