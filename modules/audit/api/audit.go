// Package api is the Audit context's in-process surface (ADR-0025).
//
// It is deliberately asymmetric: callers may Append and they may Verify, and there is no Update, no
// Delete, and no way to obtain a handle that has one. SPEC-0003 AC1 is "there is no update/delete
// API surface" — not "the update path is guarded", because a guard is a thing someone can decide to
// pass. The absence is the mechanism (invariant 5, ADR-0007).
//
// SPEC-0003, T-0006.
package api

import (
	"context"
	"time"
)

// Action is the dotted vocabulary from contracts/events/audit/v1 — a string rather than an enum so
// a new auditable action is additive, never a coordinated deploy (see the contract's comment).
type Action string

// The actions in use today. New ones are added here as they are emitted; the type is open on
// purpose, so a module can audit something this package has never heard of.
const (
	// ActionTenantIsolationViolation is a write refused by row-level security — T-0004's event,
	// renamed here now that a contract exists for it.
	ActionTenantIsolationViolation Action = "tenant.isolation.violation"
)

// Outcome mirrors the contract enum. Refusals are the more investigation-relevant half.
type Outcome string

const (
	OutcomeAllowed Outcome = "ALLOWED"
	OutcomeDenied  Outcome = "DENIED"
)

// Entry is one record as a caller submits it. What the caller does NOT supply is as important as
// what it does: no sequence number and no hashes. Those are assigned by the writer when the entry
// is appended, because a producer able to state its own position in the chain could also lie about
// it (ADR-0007).
type Entry struct {
	TenantID   string
	Action     Action
	ActorID    string
	Resource   string
	Outcome    Outcome
	Detail     map[string]string
	OccurredAt time.Time
}

// Record is a persisted entry, including the chain fields the writer assigned.
type Record struct {
	Seq        int64
	TenantID   string
	Action     Action
	ActorID    string
	Resource   string
	Outcome    Outcome
	Detail     map[string]string
	OccurredAt time.Time
	// PrevHash is the hash of the preceding record; empty for the first.
	PrevHash string
	// Hash covers this record's content *and* PrevHash, which is what makes the chain
	// tamper-evident rather than merely checksummed.
	Hash string
}

// Log is the audit trail. Append and Verify — nothing else.
//
// Note there is no Delete, no Update, and no Truncate, and that Read is absent too: reading the
// trail is the Audit UI's job (Phase 2, PR-17/PR-18) and giving every caller a reader now would
// invite the trail to be used as a general query surface.
type Log interface {
	// Append adds one entry and returns the record as persisted.
	Append(ctx context.Context, e Entry) (Record, error)
	// Verify walks the chain and reports the first inconsistency it finds.
	Verify(ctx context.Context) (VerifyResult, error)
}

// VerifyResult is the outcome of a chain walk.
type VerifyResult struct {
	// Checked is how many records were walked.
	Checked int64
	// OK is true when the chain is intact.
	OK bool
	// BrokenAtSeq is the sequence number of the first record that failed, valid when OK is false.
	BrokenAtSeq int64
	// Reason says what failed — a recomputed hash mismatch, a broken link, or a gap in the
	// sequence. Distinguishing them matters: a mutated row and a deleted row are different
	// incidents, and an investigator should not have to guess which one happened.
	Reason string
}
