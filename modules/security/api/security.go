// Package api is the Security/Findings context's in-process surface
// (SPEC-0024, SPEC-0025, SPEC-0026, SPEC-0027).
//
// It exposes the normalized finding model, the ingestion surface, the
// triage resource, and the dashboard read surface as plain data and
// behavioural ports. What it deliberately does NOT expose is as load
// bearing as what it does: no request type COMPUTES or asserts a finding
// identity — a caller may only refer to a finding by the opaque identity
// the server returned — no request carries a lifecycle state or a
// first-seen value, and nothing carries an authorization outcome, a
// severity claim on a triage request, or a triage field on a finding
// (SPEC-0027 AC7). Ingest, read, triage and summary are PDP decisions
// with server-derived context (ADR-0006, SPEC-0025 AC3/AC4, SPEC-0027
// AC5).
package api

import (
	"context"
	"errors"
	"time"
)

// ErrDenied is the coarse refusal every failed ingest or read returns. It
// deliberately does not distinguish a missing finding or repository from one
// in another tenant from a policy refusal, so the surface cannot be used to
// enumerate any of them (SPEC-0001, SPEC-0025 AC2).
var ErrDenied = errors.New("security: finding unavailable")

// ErrMalformed is the boundary refusal for a request that violates the
// ingestion contract itself: an oversized or media-type-less provenance blob,
// an unknown scanner class, a chunk sequence that skips, or a batch past the
// bound. The request is rejected whole — no partial ingest (SPEC-0025 AC6).
// It reveals nothing about tenants or findings.
var ErrMalformed = errors.New("security: malformed ingest request")

// ScannerClass is the one-of-five scanner classes the normalized model covers
// (SPEC-0024 AC1).
type ScannerClass string

const (
	ScannerClassSAST       ScannerClass = "SAST"
	ScannerClassDependency ScannerClass = "DEPENDENCY"
	ScannerClassSecrets    ScannerClass = "SECRETS"
	ScannerClassContainer  ScannerClass = "CONTAINER"
	ScannerClassDAST       ScannerClass = "DAST"
)

// Valid reports whether the class is one of the five; the boundary rejects
// anything else whole (SPEC-0025 AC6).
func (c ScannerClass) Valid() bool {
	switch c {
	case ScannerClassSAST, ScannerClassDependency, ScannerClassSecrets,
		ScannerClassContainer, ScannerClassDAST:
		return true
	}
	return false
}

// Severity is the one normalized severity scale across scanner classes
// (SPEC-0025). The tool's native severity is preserved in provenance; it
// never travels as a first-class field.
type Severity string

const (
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

// Lifecycle is server-computed state. A caller cannot supply it: it appears
// in no request type (SPEC-0025 AC3).
type Lifecycle string

const (
	LifecycleOpen     Lifecycle = "OPEN"
	LifecycleResolved Lifecycle = "RESOLVED"
)

// Location is the content-derived half of a finding's identity input set
// (SPEC-0024). Its components are derived from content, not from a commit or
// an absolute line number. For dependency and container findings the affected
// component and version stand in place of a file location.
type Location struct {
	// ArtifactPath is the artifact within the repository the finding sits in.
	ArtifactPath string
	// EnclosingContent is the enclosing content that carries the finding,
	// content-derived (normalized snippet or enclosing symbol). The exact
	// construction is an implementation choice constrained by SPEC-0024
	// AC2/AC3.
	EnclosingContent string
	// Component and ComponentVersion are the dependency/container substitute
	// for a file location.
	Component        string
	ComponentVersion string
}

// RawFinding is one normalized finding as a scanner adapter delivers it. It
// deliberately carries no identity, no lifecycle state, and no first-seen
// value: identity is computed server-side per SPEC-0024, lifecycle is server
// state, and first-seen is server history (SPEC-0025 AC3). It also has no
// scanner-specific field: whatever a tool knows beyond rule, severity, and
// location crosses the boundary only inside Provenance (SPEC-0024 AC6).
type RawFinding struct {
	// RuleID is the rule the reporting tool fired on. Together with the scan
	// descriptor's tool identity and the location, this is the per-finding
	// half of the identity input set.
	RuleID string
	// Severity is the normalized severity. It is a fact the adapter derives
	// from the tool's output at the boundary, never a claim that reaches
	// authorization as a caller assertion (SPEC-0025: severity values are
	// facts produced by Security/Findings from ingested state).
	Severity Severity
	// Location is the content-derived location.
	Location Location
	// Provenance is the scanner-native payload, carried byte-for-byte and
	// never interpreted by the domain (SPEC-0025 AC6). It round-trips only
	// with its media type.
	Provenance []byte
	// ProvenanceMediaType is the media type of the provenance blob, e.g.
	// "application/json". Required whenever Provenance is non-empty.
	ProvenanceMediaType string
}

// Scan names the tool that produced a batch. Tool identity is part of the
// identity input set: the same defect reported by two tools is two findings,
// never one (SPEC-0024 AC3). The tool's VERSION is deliberately not one of
// the identity inputs — an upgrade re-reports the same defect — but it is
// recorded so a reader can name what scanned.
type Scan struct {
	ScannerClass ScannerClass
	ToolName     string
	ToolVersion  string
	StartedAt    time.Time
	EndedAt      time.Time
}

// Finding is the normalized shape every scanner class lands in (SPEC-0024
// AC1). It deliberately excludes filesystem paths outside the repository,
// credentials, scanner API tokens, policy outcomes, triage state, and audit
// sequences — none of those is representable here (SPEC-0025).
type Finding struct {
	// ID is the opaque, server-computed identity (SPEC-0024 identity rule).
	ID string
	// TenantID and RepositoryID scope the finding; every read is scoped with
	// them (SPEC-0001).
	TenantID     string
	RepositoryID string
	ScannerClass ScannerClass
	// ToolName and ToolVersion are the reporting tool, as delivered in the
	// scan descriptor that first produced the finding.
	ToolName    string
	ToolVersion string
	// RuleID is the rule the tool fired on.
	RuleID string
	// Severity is the normalized severity at last sight.
	Severity Severity
	// Location is the content-derived location at last sight.
	Location Location
	// Lifecycle is OPEN or RESOLVED, server-computed. A finding a later scan
	// no longer reports is RESOLVED, never deleted (SPEC-0024 AC9).
	Lifecycle Lifecycle
	// FirstSeenScanID and LastSeenScanID are the scans that first and last
	// reported this finding. They are server history: a caller cannot supply
	// them (SPEC-0025 AC3).
	FirstSeenScanID string
	LastSeenScanID  string
	// Provenance is the scanner-native payload of the scan that last reported
	// the finding, stored and returned byte-for-byte with its media type; the
	// domain never parses it (SPEC-0025 AC6).
	Provenance          []byte
	ProvenanceMediaType string
}

// Context is the verified identity an operation is evaluated under. The actor
// and its roles come from authenticated identity; a caller cannot assert
// them, and an empty or cross-tenant context is a coarse denial (SPEC-0025).
type Context struct {
	TenantID, RepositoryID, ActorID, RequestID string
	ActorRoles                                 []string
}

// IngestChunk is one bounded chunk of a completed scan's batch of normalized
// findings. A large scan arrives as consecutive chunks of the same scan;
// nothing of the scan is visible to a reader until the final chunk completes
// (SPEC-0025). It carries no finding identity, no lifecycle, no first-seen,
// and no authorization outcome.
type IngestChunk struct {
	Context
	// Revision is the opaque revision the scan ran against. Identity is
	// invariant to it (SPEC-0024); it is recorded so reads can name what was
	// scanned.
	Revision string
	// Scan names the tool that produced the batch.
	Scan Scan
	// Findings is this chunk's bounded batch of normalized findings.
	Findings []RawFinding
	// ChunkIndex is the chunk's zero-based position within the scan's batch
	// sequence. Chunks must arrive contiguous from zero.
	ChunkIndex int
	// FinalChunk completes the scan's batch; only then does the scan become
	// visible and its lifecycle consequences apply.
	FinalChunk bool
}

// Bounds on one ingest request. They exist so a malformed or hostile batch is
// rejected at the boundary without partial ingest (SPEC-0025 AC6) and so a
// large scan is chunked rather than unbounded (SPEC-0025 non-functional).
const (
	// MaxFindingsPerChunk bounds one chunk's findings.
	MaxFindingsPerChunk = 1000
	// MaxProvenanceBytes bounds one provenance blob.
	MaxProvenanceBytes = 1 << 20 // 1 MiB
)

// IngestResult is the outcome of one chunk. FindingsRecorded counts the
// findings THIS request recorded; a replay of the same request ID reports the
// same outcome and creates nothing new (SPEC-0025 AC1).
type IngestResult struct {
	// ScanID is the server-assigned opaque identity of the scan record.
	ScanID string
	// FindingsRecorded is how many findings this request recorded.
	FindingsRecorded int64
	// Completed reports whether this chunk completed the scan's batch.
	Completed bool
	// Replayed reports that the request ID was already ingested for this
	// scan and chunk: the result is the recorded one, nothing new was
	// created, and no event or audit record is emitted again.
	Replayed bool
}

// ListRequest pages a tenant-scoped, filtered list of findings. An empty
// filter value is no filter. Facets and counts obey the same authorization
// as the result list (SPEC-0025).
//
// Dashboard semantics (SPEC-0026): an EMPTY RepositoryFilter lists across
// every repository the caller may read — the readable set is derived
// server-side from PDP decisions per request and applied inside the query,
// never as a mask over an unfiltered pre-aggregate (SPEC-0027 AC4). A
// non-empty RepositoryFilter names one repository; naming one the caller
// may not read is the same coarse denial as naming one that does not exist.
type ListRequest struct {
	Context
	RepositoryFilter   string
	ScannerClassFilter ScannerClass
	SeverityFilter     Severity
	LifecycleFilter    Lifecycle
	// MinAgeDays and MaxAgeDays bound the finding's age in whole days since
	// first sight; zero on either bound leaves that side unbounded
	// (SPEC-0026 AC2).
	MinAgeDays int
	MaxAgeDays int
	// OwningTeamFilter is the owning team as an opaque identifier fed by
	// Identity & Access (SPEC-0026). Empty is no filter.
	OwningTeamFilter string
	// PageSize is the maximum number of findings to return. Zero means
	// DefaultPageSize; anything above MaxPageSize is clamped to it.
	PageSize int
	// PageToken is the token a previous page returned. Empty starts at the
	// first page. Tokens are signed and bound to the tenant and the filters
	// that issued them; a forged or mismatched token yields no content.
	PageToken string
}

// Paging bounds for a findings read.
const (
	DefaultPageSize = 50
	MaxPageSize     = 200
)

// ListPage is one page of findings.
type ListPage struct {
	Findings []Finding
	// NextPageToken is empty when this is the last page.
	NextPageToken string
}

// Findings is the context's full in-process surface: ingestion of completed
// scans, tenant-scoped reads, triage, dashboard reads, and merge-request
// attribution reads (SPEC-0024, SPEC-0025, SPEC-0026, SPEC-0027, SPEC-0028).
// Every operation is a PDP decision with server-derived context; identity,
// lifecycle, and attribution are server-computed.
type Findings interface {
	Triage
	// IngestScanResults ingests one chunk of a completed scan's batch.
	// Idempotent per tenant, scan, and request ID: replaying a request
	// creates no duplicate finding, event, or audit record (SPEC-0025 AC1).
	IngestScanResults(ctx context.Context, chunk IngestChunk) (IngestResult, error)
	// GetFinding returns one finding. Not-found, cross-tenant, and
	// unauthorized are the same coarse denial (SPEC-0001).
	GetFinding(ctx context.Context, c Context, findingID string) (Finding, error)
	// ListFindings pages a tenant-scoped, filtered list of findings.
	ListFindings(ctx context.Context, req ListRequest) (ListPage, error)
	// ListMergeRequestFindings pages the findings attributable to one merge
	// request (SPEC-0028). The merge request is known to this context only
	// through Code Review's events; naming one it has not been told about —
	// or one in another tenant or repository — is the same coarse denial as
	// a policy refusal (SPEC-0001). An UNAVAILABLE summary with an empty
	// list is still UNAVAILABLE, never "no findings" (SPEC-0028 AC7).
	ListMergeRequestFindings(ctx context.Context, req MergeRequestFindingsRequest) (MergeRequestFindingsPage, error)
}
