// Package audit carries security-relevant events to whatever will eventually persist them.
//
// SPEC-0001 AC3 requires a cross-tenant write attempt to be *audited*, not merely rejected: a
// rejection tells the attacker they failed, an audit event tells us they tried.
//
// SCOPE, stated plainly because it is easy to over-read what this package does. It emits onto the
// in-process bus (T-0008). It does not persist anything, does not hash-chain, and provides no
// tamper-evidence — that is T-0006 (ADR-0007), which also owns adding `AuditEvent` to
// `governance/contracts/events`. Until that lands there is no subscriber, so today these events are
// published and dropped. That is deliberate: the emission point is the part that must live at the
// place the violation is detected, and retrofitting it later means auditing the code paths again.
//
// RESOLVED BY T-0006: the routing key is no longer provisional. contracts/events/audit/v1 now
// defines a single generic AuditEvent, so this event's name is that message's full name and the
// specific case is carried in `action`. T-0004 flagged the rename as free while nothing subscribed;
// this is that rename, made on exactly those terms.
package audit

import "time"

// EventAudit is the routing key: the protobuf full name of the contracts/events message, matching
// how every other event in this repo is keyed.
const EventAudit = "gitsaas.events.audit.v1.AuditEvent"

// ActionTenantIsolationViolation is the `action` value for a write refused by row-level security.
// The dotted vocabulary lives in the contract's comment; adding one is additive by construction.
const ActionTenantIsolationViolation = "tenant.isolation.violation"

// EventTenantIsolationViolation is retained as a deprecated alias for one release so that anything
// still keying off T-0004's provisional name fails loudly at compile time rather than silently
// subscribing to a topic nothing publishes.
//
// Deprecated: use EventAudit with ActionTenantIsolationViolation.
const EventTenantIsolationViolation = EventAudit

// TenantIsolationViolation records that a request scoped to one tenant tried to write outside that
// scope and the database refused it.
//
// It carries no row contents and no SQL parameters on purpose: an audit record of a cross-tenant
// attempt must not itself become the vehicle that copies one tenant's data somewhere less protected
// (G1, and ADR-0007's "no payloads in audit events").
type TenantIsolationViolation struct {
	// TenantID is the scope the request was operating under — the *attacker's* tenant, not the
	// victim's. Which tenant was targeted is deliberately absent: RLS makes the target invisible to
	// the request, so the application genuinely does not know it, and inventing a value would put a
	// guess into an audit log.
	TenantID string
	// Operation is the SQL verb that was refused, e.g. "INSERT". Not the statement.
	Operation string
	// SQLState is the Postgres error code that rejected it (42501 for an RLS policy violation),
	// so a reader can tell a policy denial from a permissions error without re-running anything.
	SQLState string
	// Detail is the database's own message, which names the policy but not the row data.
	Detail string
	// OccurredAt is when the rejection was observed.
	OccurredAt time.Time
}

// EventName is the routing key — the contract's message full name (T-0006).
func (TenantIsolationViolation) EventName() string { return EventAudit }

// Action is the dotted action this event records, carried in the contract's `action` field.
func (TenantIsolationViolation) Action() string { return ActionTenantIsolationViolation }

// Tenant reports the scope the attempt was made under. The bus refuses an event without one
// (invariant 1), which is also why this cannot be emitted for an unscoped request — there is no
// tenant to attribute it to, and such a request is denied before it reaches the database anyway.
func (v TenantIsolationViolation) Tenant() string { return v.TenantID }
