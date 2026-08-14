// Package app orchestrates findings ingestion and reads. It owns the ingest
// choreography — PDP decision with server-derived context, server-computed
// identity, chunk assembly, and the OPEN/RESOLVED set comparison — while
// persistence is an explicit port so the service never reaches an adapter's
// internals.
package app

import (
	"context"

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
	Scan       api.Scan
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
	// the caller must emit no event or audit record (SPEC-0025 AC1).
	Replayed bool
	// Opened and Resolved are valid when Completed && !Replayed: the findings
	// this scan opened (first sight) and resolved (no longer reported),
	// carrying everything the corresponding events need (SPEC-0024 AC9).
	Opened   []api.Finding
	Resolved []api.Finding
}

// ListFilter is the server-enforced filter set for a tenant-scoped listing.
// An empty value is no filter. AfterID is the cursor position: the page
// starts after it.
type ListFilter struct {
	RepositoryID string
	ScannerClass api.ScannerClass
	Severity     api.Severity
	Lifecycle    api.Lifecycle
	AfterID      string
	Limit        int
}

// Store persists scans and findings. Implementations: the in-memory store for
// dev and tests, and the Postgres adapter under adapters/postgres. Both are
// tenant-scoped; the Postgres one additionally binds under row-level
// security (SPEC-0001).
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
}
