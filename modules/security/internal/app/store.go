// Package app orchestrates findings ingestion and reads. It owns the ingest
// choreography — PDP decision with server-derived context, server-computed
// identity, chunk assembly, and the OPEN/RESOLVED set comparison — while
// persistence is an explicit port so the service never reaches an adapter's
// internals.
package app

import (
	"context"
	"time"

	"github.com/gitfrok/backend/modules/security/api"
)

// PreparedFinding is a raw finding plus the identity the server computed for
// it (SPEC-0024). Identity is computed in the service, before anything
// touches storage: no adapter and no store can assert or forge one
// (SPEC-0025 AC3).
type PreparedFinding struct {
	Identity string
	Raw      api.RawFinding
}

// IngestParams is one chunk's worth of server-derived ingest state, handed to
// the store. Everything a caller could assert has already been validated or
// computed server-side by the time it arrives here.
type IngestParams struct {
	TenantID     string
	RepositoryID string
	// Revision is the opaque revision the scan ran against, recorded so reads
	// can name what was scanned. Identity is invariant to it (SPEC-0024).
	Revision string
	Scan     api.Scan
	// ScanID is the server-derived opaque identity of the scan record. It is
	// a deterministic function of the scan descriptor, so a redelivered chunk
	// of the same scan lands on the same record.
	ScanID string
	// ChunkIndex and RequestID key idempotency: per tenant, scan, chunk, and
	// request ID (SPEC-0025 AC1).
	ChunkIndex int
	RequestID  string
	FinalChunk bool
	// Findings carry server-computed identities.
	Findings []PreparedFinding
}

// IngestOutcome is what one chunk produced.
type IngestOutcome struct {
	ScanID           string
	FindingsRecorded int64
	// Completed reports the chunk finished the scan's batch: only then is any
	// of the scan visible to a reader (SPEC-0025).
	Completed bool
	// Replayed reports the request ID was already recorded for this scan and
	// chunk. The outcome is the recorded one; nothing new was created, and
	// the caller must emit no event (SPEC-0025 AC1).
	Replayed bool
	// AuditAlreadyRecorded reports — on a Replayed COMPLETED chunk — that
	// the ingest's one audit record already landed (its claim marker
	// exists). A completed replay WITHOUT it means the first attempt
	// committed but its audit publish never landed: the replay path must
	// backfill the missing record so a committed ingest can never lack it
	// (SPEC-0025 AC5: one, and at least one).
	AuditAlreadyRecorded bool
	// Opened and Resolved are valid when Completed && !Replayed: the findings
	// this scan opened (first sight) and resolved (no longer reported),
	// carrying everything the corresponding events need (SPEC-0024 AC9).
	Opened   []api.Finding
	Resolved []api.Finding
}

// ListFilter is the server-enforced filter set for a tenant-scoped listing.
// An empty value is no filter. AfterID is the cursor position: the page
// starts after it.
//
// Repository scoping (SPEC-0026 AC6): RepositoryIDs is the caller's
// authorization-derived readable set, applied INSIDE the query; a non-nil
// empty set matches nothing (fail closed). RepositoryID names a single
// repository and is honored when RepositoryIDs is nil, so the adapter-level
// reads keep their shape.
type ListFilter struct {
	RepositoryID  string
	RepositoryIDs []string
	ScannerClass  api.ScannerClass
	Severity      api.Severity
	Lifecycle     api.Lifecycle
	// MinAgeDays and MaxAgeDays bound the finding's age in whole days since
	// first sight; zero leaves the side unbounded (SPEC-0026 AC2).
	MinAgeDays int
	MaxAgeDays int
	// OwningTeam scopes to the owning team of the finding's repository
	// (SPEC-0026); empty is no filter.
	OwningTeam string
	AfterID    string
	Limit      int
}

// SummaryQuery is the server-enforced input for GetFindingsSummary: the
// same filters as a listing — including the authorization-derived
// RepositoryIDs set the aggregate runs under — plus the requested facet
// dimensions. The authorization filter is part of the query, not a mask
// applied late (SPEC-0026 non-functional, SPEC-0027 AC4).
type SummaryQuery struct {
	ListFilter
	Facets []string
}

// SetTriageParams is one triage transition's server-derived state, handed to
// the store. Everything a caller could assert has already been validated or
// computed server-side by the time it arrives here: the finding row exists,
// the PDP allowed the transition, and the triage ID, actor and timestamp are
// server-assigned.
type SetTriageParams struct {
	TenantID     string
	RepositoryID string
	FindingID    string
	// RequestID keys idempotency per (tenant, finding, request ID): a
	// replay reports the recorded record and creates nothing new
	// (SPEC-0027 AC1).
	RequestID string
	// TriageID is the server-assigned opaque identity of the record this
	// transition writes.
	TriageID      string
	State         api.TriageState
	Justification string
	// ExpectedVersion guards the transition: the record is written only if
	// the finding's current version equals it (zero expects no record at
	// all). A mismatch changes no state (SPEC-0027 AC1).
	ExpectedVersion int64
	ActorID         string
	OccurredAt      time.Time
}

// SetTriageResult is what one SetTriage produced at the store level.
type SetTriageResult struct {
	// Record is the record written, or — on Replayed/Mismatch — the one
	// already in force.
	Record api.TriageRecord
	// Replayed: the request ID was already recorded for this finding; the
	// result is the recorded one, nothing new was created, and the caller
	// must emit no event and no audit record (SPEC-0027 AC1).
	Replayed bool
	// Mismatch: the expected version did not match; no state changed.
	Mismatch bool
}

// ReportedFinding is one finding of a scan's reported set: the SPEC-0024
// identity the scan reported plus the finding row recorded for it. The
// identity is the attribution join key (SPEC-0028); the row carries the
// rendering facts (severity, location, lifecycle) as they stand now.
type ReportedFinding struct {
	Identity string
	Finding  api.Finding
}

// ScanReport is the reported set of the latest COMPLETE scans at a
// revision — one per scanner class, so a revision scanned by semgrep AND
// gitleaks reports both tools' sets (SPEC-0026 AC1, SPEC-0028 AC1). Within
// a class, the latest completed scan is the report: everything it reported,
// keyed by identity. The set is a durable server fact of the scan — a later
// scan re-reporting an identity never rewrites an earlier scan's reported
// set (SPEC-0028 attribution rule).
type ScanReport struct {
	ScanIDs  []string
	Findings []ReportedFinding
}

// Store persists scans, findings, and triage records. Implementations: the
// in-memory store for dev and tests, and the Postgres adapter under
// adapters/postgres. Both are tenant-scoped; the Postgres one additionally
// binds under row-level security (SPEC-0001).
type Store interface {
	// IngestChunk applies one chunk, serializably per scan: a partially
	// delivered batch leaves no half-ingested scan visible to a reader
	// (SPEC-0025 non-functional).
	IngestChunk(ctx context.Context, p IngestParams) (IngestOutcome, error)
	// GetFinding returns one finding for the tenant, or an error if the
	// tenant has no such finding.
	GetFinding(ctx context.Context, tenantID, findingID string) (api.Finding, error)
	// ListFindings returns one page of the tenant's findings matching f, in
	// identity order.
	ListFindings(ctx context.Context, tenantID string, f ListFilter) ([]api.Finding, error)
	// SetTriage appends one triage record, serializably per finding:
	// guarded by expected version and idempotent per (tenant, finding,
	// request ID). Superseded records are retained, never mutated
	// (SPEC-0026 AC5).
	SetTriage(ctx context.Context, p SetTriageParams) (SetTriageResult, error)
	// GetTriage returns the finding's triage record: the latest when
	// version is zero, the exact history version otherwise. Found is false
	// when there is no record (or none at that version).
	GetTriage(ctx context.Context, tenantID, findingID string, version int64) (api.TriageRecord, bool, error)
	// RepositoriesWithFindings returns the distinct repositories holding
	// the tenant's findings, in stable order. It is the candidate set the
	// service asks the PDP about when deriving the caller's readable
	// repository set (SPEC-0026 AC1); it reveals no counts.
	RepositoriesWithFindings(ctx context.Context, tenantID string) ([]string, error)
	// FindingsSummary computes counts and facet values under q — including
	// the authorization-derived repository set — in one scoped aggregate
	// (SPEC-0027 AC4).
	FindingsSummary(ctx context.Context, tenantID string, q SummaryQuery) (api.FindingsSummary, error)
	// SetRepositoryOwningTeam records the repository-level owning-team
	// attribution, the v1 shape SPEC-0026 assumes: an opaque team
	// identifier per repository, fed from Identity & Access. The feed
	// itself arrives with Identity & Access' team events; the attribution
	// lives here because Security/Findings owns the attribution it derives
	// (SPEC-0026 data owned), never by reading another context's tables.
	SetRepositoryOwningTeam(ctx context.Context, tenantID, repositoryID, owningTeam string) error
	// ScanReportAt returns the reported set of the latest COMPLETE scans the
	// tenant ran at the repository's revision, spanning every ingested
	// scanner class (one latest scan per class). Found is false when no
	// completed scan exists at that revision: attribution renders that as
	// UNAVAILABLE, never as an empty reported set (SPEC-0028 AC7).
	ScanReportAt(ctx context.Context, tenantID, repositoryID, revision string) (ScanReport, bool, error)
	// ClaimIngestAuditMarker records that the ingest's one audit record has
	// landed for (tenant, scan, chunk, request ID), so a replay of the same
	// chunk can tell "record already appended" from "first attempt committed
	// but its audit publish failed — backfill" (SPEC-0025 AC5). The claim is
	// append-only and idempotent: a re-claim changes nothing.
	ClaimIngestAuditMarker(ctx context.Context, tenantID, scanID string, chunkIndex int, requestID string) error
}
