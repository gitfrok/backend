// The grant lifecycle's witness port (SPEC-0033 AC4, T-0027).
//
// Issuing, revoking and expiring a grant each append exactly one immutable,
// first-party record naming the principals the lifecycle pairs. Identity&
// Access declares what it needs of that log in its own terms — an
// append-only witness returning the chain position it assigned — and never
// imports the Audit module's surface: the composition root adapts the
// tenant's audit trail onto this port, keeping the module graph acyclic
// (invariant 14) and the direction honest (Identity&Access is a producer of
// accountability evidence, not a consumer of Audit).
package api

import (
	"context"
	"time"
)

// GrantWitnessEntry is one first-party record the grant lifecycle asks to be
// witnessed: who acted, on which grant, with what scope, when. It carries no
// outcome and no provenance — a grant lifecycle record is always an
// authorized, witnessed transition, and it is always first-party; the
// composition root renders both when it adapts the tenant's trail.
type GrantWitnessEntry struct {
	TenantID string
	// Action is the audited action vocabulary the platform appends under
	// (platform/audit): identity.auditor_grant.issued, .revoked, .expired.
	Action string
	// ActorID is the admin whose action caused the transition. Empty for
	// expiry: the actor is the platform itself (SPEC-0033 AC3).
	ActorID string
	// Resource is the grant the record is about: "auditor_grant/<grant>".
	Resource string
	// Detail names the AC4 pairing and the decision that authorized the
	// transition — the facts an investigator re-derives the record from.
	Detail map[string]string
	// OccurredAt is the server's instant the transition was witnessed.
	OccurredAt time.Time
}

// GrantWitnessRecord is the record as persisted: the chain position the
// witnessed transition cites (ADR-0007).
type GrantWitnessRecord struct {
	Seq  int64
	Hash string
}

// GrantWitness is the append-only first-party log the grant lifecycle writes
// its immutable AC4 records to. A grant that cannot be witnessed is not
// issued: an unrecorded grant is a worse failure than a refused one.
type GrantWitness interface {
	// AppendGrantRecord appends one entry and returns the record as
	// persisted, including the chain position the writer assigned.
	AppendGrantRecord(ctx context.Context, e GrantWitnessEntry) (GrantWitnessRecord, error)
}
