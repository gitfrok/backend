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
// CONSEQUENCE OF THAT: EventName below is a *provisional* routing key. Every other event in this
// repo mirrors a protobuf full name in contracts/events and is held to it by a parity test
// (see modules/repository/api/events_contract_test.go). This one cannot be, because the contract
// does not exist yet. T-0006 must either adopt this name additively or change it — and since
// nothing subscribes, changing it costs nothing today and considerably more later.
package audit

import "time"

// EventTenantIsolationViolation is the routing key for a rejected cross-tenant access attempt.
//
// PROVISIONAL — see the package comment. T-0006 owns the real contracts/events name.
const EventTenantIsolationViolation = "gitsaas.events.audit.v1.TenantIsolationViolation"

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

// EventName is the routing key. See the package comment on why this one is provisional.
func (TenantIsolationViolation) EventName() string { return EventTenantIsolationViolation }

// Tenant reports the scope the attempt was made under. The bus refuses an event without one
// (invariant 1), which is also why this cannot be emitted for an unscoped request — there is no
// tenant to attribute it to, and such a request is denied before it reaches the database anyway.
func (v TenantIsolationViolation) Tenant() string { return v.TenantID }
