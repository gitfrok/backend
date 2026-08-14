package api

import (
	"context"
	"time"
)

// The triage and dashboard-read surface of the Security/Findings context
// (SPEC-0026, SPEC-0027).
//
// Triage is a CONTROL ACTION, not a UI preference (SPEC-0026): recording an
// ACCEPT is a claim an auditor may later read (PR-17), so every transition is
// a PDP decision with server-derived context and appends exactly one
// immutable audit record naming the actor, the finding, the prior and new
// state, and the decision ID (SPEC-0026 AC4).
//
// The load-bearing shape decision is that a triage record is a resource of
// its own, keyed by the finding's SPEC-0024 identity — never a field of the
// Finding message. A later scan re-reports the identity and the record,
// keyed to it, is untouched: "survives a re-scan" is true by construction,
// not by a reattachment step (SPEC-0027). No triage request type carries a
// finding's severity, a lifecycle state, or an authorization flag: those are
// server facts, and the request shapes have no fields to assert them in.

// TriageState is the one decision vocabulary a triage record carries
// (SPEC-0026): accept the risk, mark the finding a false positive, fix it,
// or defer the decision.
type TriageState string

const (
	TriageAccept        TriageState = "ACCEPT"
	TriageFalsePositive TriageState = "FALSE_POSITIVE"
	TriageFix           TriageState = "FIX"
	TriageDefer         TriageState = "DEFER"
)

// TriageStateUnspecified names the ABSENCE of a prior state in a transition
// (the first decision on a finding); it is never a state a record holds, and
// SetTriage rejects it — clearing a decision is not a v1 operation, history
// is only superseded, never erased (SPEC-0026 AC5).
const TriageStateUnspecified TriageState = ""

// Valid reports whether the state is one a record can hold.
func (s TriageState) Valid() bool {
	switch s {
	case TriageAccept, TriageFalsePositive, TriageFix, TriageDefer:
		return true
	}
	return false
}

// MaxJustificationBytes bounds the caller-supplied justification text. The
// contract carries the field without settling whether a state requires a
// non-empty one (SPEC-0027 open question); the bound is the module's own.
const MaxJustificationBytes = 2048

// TriageRecord is one triage decision attached to a finding identity — a
// resource of its own, never a field of the finding message (SPEC-0027).
// Records are immutable once written; superseding a decision appends a new
// record with a higher version and retains the old one (SPEC-0026 AC5,
// SPEC-0027 AC6).
type TriageRecord struct {
	// TriageID is the opaque, server-assigned identity of the record.
	TriageID string
	// FindingID is the finding identity this record is keyed to (SPEC-0024).
	FindingID string
	TenantID  string
	// RepositoryID is the repository the finding belongs to; it is copied
	// from the finding row server-side, never asserted by the request.
	RepositoryID string
	State        TriageState
	// Justification is the bounded, caller-supplied text. It travels in no
	// event (SPEC-0027): the FindingTriaged bus event and the audit detail
	// name states and identifiers, never the text.
	Justification string
	// Version is the server-assigned positive version within the finding's
	// triage history. Versions are dense and ascending; a higher version
	// supersedes the lower ones without erasing them.
	Version int64
	// ActorID is the verified actor who recorded the decision, from
	// authenticated identity — never a caller assertion.
	ActorID string
	// OccurredAt is when the transition was recorded.
	OccurredAt time.Time
}

// TriageTransition is one SetTriage request as the service sees it. It
// deliberately carries no severity, no lifecycle, and no authorization flag
// (SPEC-0027): there is no field here a caller could assert them through.
type TriageTransition struct {
	Context
	// FindingID is the opaque, server-assigned identity of the finding to
	// triage.
	FindingID string
	// State is the decision being recorded. An invalid or unspecified state
	// is a boundary refusal (ErrMalformed).
	State TriageState
	// Justification is bounded by MaxJustificationBytes.
	Justification string
	// ExpectedVersion is the version of the triage record the caller
	// expects to supersede: the version last read. Zero expects no record at
	// all. A mismatch changes no state and reports the current record, so
	// concurrent triage resolves by re-read rather than by last-write-wins
	// (SPEC-0027 AC1).
	ExpectedVersion int64
}

// SetTriageOutcome is what one SetTriage produced.
type SetTriageOutcome struct {
	// Record is the record now in force: the one this request wrote, or —
	// on a replayed request ID or a version mismatch — the one already
	// there (SPEC-0027 AC1).
	Record TriageRecord
	// PriorState is the state the finding carried before this transition;
	// TriageStateUnspecified for the first decision on a finding. Valid
	// only when the transition wrote a record (!Replayed && !Mismatch).
	PriorState TriageState
	// Replayed reports the request ID was already recorded for this
	// finding: nothing new was created, and the caller must emit no event
	// and no audit record (SPEC-0027 AC1).
	Replayed bool
	// Mismatch reports the expected version did not match: no state
	// changed, and Record is the current one.
	Mismatch bool
}

// FindingsSummary is counts and facet values for the unified dashboard,
// computed under the caller's authorization (SPEC-0026 AC6). TotalCount
// counts only findings the caller may read, and a facet value that exists
// only in a repository the caller may not read is absent, not zero — the
// shape cannot serve an unfiltered pre-aggregate with a late mask
// (SPEC-0027 AC4).
type FindingsSummary struct {
	TotalCount int64
	Facets     []SummaryFacet
}

// SummaryFacet is one requested dimension's authorized distribution.
type SummaryFacet struct {
	Dimension string
	Values    []SummaryFacetValue
}

// SummaryFacetValue is one value within a facet and the count of authorized
// findings carrying it.
type SummaryFacetValue struct {
	Value string
	Count int64
}

// The facet dimensions GetFindingsSummary accepts. Unknown dimensions are
// rejected at the boundary (SPEC-0027).
const (
	FacetSeverity     = "severity"
	FacetScannerClass = "scanner_class"
	FacetLifecycle    = "lifecycle"
	FacetOwningTeam   = "owning_team"
)

// ValidFacetDimensions is the closed set; the gRPC adapter and the service
// both refuse anything else.
var ValidFacetDimensions = map[string]bool{
	FacetSeverity:     true,
	FacetScannerClass: true,
	FacetLifecycle:    true,
	FacetOwningTeam:   true,
}

// SummaryRequest asks for counts and facets under the same filters
// ListRequest accepts. It names no repository allow-list and carries no
// authorization flag: the caller's readable scope is derived server-side
// from PDP repo.read / findings.summary.read decisions, and an org-wide
// summary is the same request with no repository filter (SPEC-0026 AC1).
type SummaryRequest struct {
	Context
	RepositoryFilter   string
	ScannerClassFilter ScannerClass
	SeverityFilter     Severity
	LifecycleFilter    Lifecycle
	// MinAgeDays and MaxAgeDays bound the finding's age in whole days since
	// first sight; zero on either bound leaves that side unbounded.
	MinAgeDays int
	MaxAgeDays int
	// OwningTeamFilter is the owning team as an opaque identifier fed by
	// Identity & Access (SPEC-0026). Empty is no filter.
	OwningTeamFilter string
	// FacetDimensions are the requested dimensions; unknown ones are a
	// boundary refusal. The requested set is server-derived PDP context for
	// findings.summary.read (SPEC-0027).
	FacetDimensions []string
}

// Triage is the context's triage and dashboard-read surface (SPEC-0026,
// SPEC-0027). Every operation is a PDP decision with server-derived context;
// the caller's readable repository set is derived per request — never cached
// across queries — and applied inside the store's query, never as a mask
// over an unfiltered pre-aggregate (SPEC-0027 AC4).
type Triage interface {
	// SetTriage records a triage decision on a finding identity. Guarded by
	// expected version and idempotent per request ID; a superseded record
	// is retained, never mutated (SPEC-0026 AC5, SPEC-0027 AC1). A PDP
	// denial creates no record and returns the coarse ErrDenied.
	SetTriage(ctx context.Context, req TriageTransition) (SetTriageOutcome, error)
	// GetTriage reads a finding's triage record: the latest when version is
	// zero, an exact superseded version otherwise (SPEC-0027 AC6). Absence
	// and denial are the same coarse shape: found is false and no record is
	// returned for a nonexistent finding, a cross-tenant one, an
	// unauthorized one, and one with no record (or none at that version).
	GetTriage(ctx context.Context, c Context, findingID string, version int64) (TriageRecord, bool, error)
	// GetFindingsSummary returns counts and facet values computed under the
	// caller's authorization (SPEC-0026 AC6).
	GetFindingsSummary(ctx context.Context, req SummaryRequest) (FindingsSummary, error)
}
