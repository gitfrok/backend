// Package api is the Code Search context's in-process surface (ADR-0025). Other modules and the
// plane binaries depend ONLY on this package — never on internal/*. It exposes no infrastructure
// types (invariant 20), only plain data and behavioural ports.
//
// T-0028 replaces the Phase-1 stub with the real permission-filtered surface (SPEC-0034,
// SPEC-0035, PR-19): substring, regex and symbol queries whose searchable repository set is
// derived by the server from the caller's permissions at query time, incremental indexing off
// Repository events with a measured freshness bound, and an index-status surface that reveals
// nothing about repositories the caller may not read.
package api

import (
	"context"
	"errors"
	"time"
)

// IndexedRepository is what the Code Search context knows about a repository. It is a projection
// fed by Repository events, never a read of that context's tables (invariant 15).
type IndexedRepository struct {
	TenantID string
	RepoID   string
	Name     string
	// Refs maps a ref name to the sha last seen for it.
	Refs map[string]string
}

// Index is the synchronous read port of the Code Search context.
type Index interface {
	// Lookup returns a tenant-scoped index entry; callers pass the authorized tenant.
	Lookup(ctx context.Context, tenantID, repoID string) (IndexedRepository, error)
}

// QueryMode selects the query language. Every mode is permission-filtered on every result path
// (SPEC-0034 AC2).
type QueryMode int

// The query modes mirror gitsaas.search.v1.QueryMode.
const (
	QueryModeUnspecified QueryMode = 0
	// QueryModeSubstring is a code-aware substring match with identifier and camelCase
	// tokenization (SPEC-0034 AC1).
	QueryModeSubstring QueryMode = 1
	// QueryModeRegex is RE2 evaluation, bounded so a pathological pattern cannot monopolize the
	// index or become a timing oracle (SPEC-0035 non-functional).
	QueryModeRegex QueryMode = 2
	// QueryModeSymbol matches identifiers in the index's code-aware symbol table.
	QueryModeSymbol QueryMode = 3
)

// Bounded inputs: no query streams unbounded memory (SPEC-0035 non-functional). Regex patterns
// beyond the cap are a coarse refusal rather than an unbounded evaluation.
const (
	MaxQueryTextLength    = 512
	MaxRegexPatternLength = 256
)

// FileEntry is one file the Repository contract lists at a revision. It carries the opaque path
// and size only — never content, which travels through ReadFile.
type FileEntry struct {
	Path      string
	SizeBytes int64
}

// ContentSource is the route Code Search takes to repository content: the Repository/Git contract
// surface, never Git storage and never another context's tables (ADR-0022, SPEC-0035 AC7). The
// plane injects the gRPC adapter; tests inject fakes. Either way the indexing code knows no other
// way to reach content.
type ContentSource interface {
	// ListFiles enumerates the files of one repository at one revision.
	ListFiles(ctx context.Context, tenantID, repoID, revision string) ([]FileEntry, error)
	// ReadFile returns the bytes of one file at one revision.
	ReadFile(ctx context.Context, tenantID, repoID, revision, path string) ([]byte, error)
}

// Query is one search request with its verified context. Every field that could be caller-asserted
// in the wire contract is absent here by design: there is no repository allow-list, no permission
// claim, no "include unauthorized" flag and no scoring override (SPEC-0035 AC2). The searchable
// repository set is a server fact derived at query time.
type Query struct {
	TenantID   string
	ActorID    string
	ActorRoles []string
	RequestID  string
	// Text is the query string, interpreted per Mode.
	Text string
	Mode QueryMode
	// ResultLimit bounds one page; zero means the server default, values above the server
	// maximum are clamped.
	ResultLimit int32
	// ContextLineLimit bounds the lines of context around each match; zero means none.
	ContextLineLimit int32
	// PageToken is an opaque, signed, tenant-bound cursor from a previous page. Empty starts at
	// the first page.
	PageToken string
}

// Match is one authorized result. It carries opaque identifiers and bounded content only — no
// filesystem location outside the repository, no credential, no blob handle, and no permission
// fact (SPEC-0035).
type Match struct {
	RepositoryID string
	// Revision is the opaque revision the match was indexed at.
	Revision string
	Path     string
	// LineStart and LineEnd are one-based and inclusive over MatchedContent.
	LineStart      int64
	LineEnd        int64
	MatchedContent string
}

// Page is one page of authorized matches. It deliberately has no field capable of expressing a
// total that includes unauthorized matches: non-enumeration is a type property, not a filter
// applied late (SPEC-0035 AC3). The zero Page is the one shape a no-match query and an
// unauthorized-only query both return (SPEC-0035 AC4).
type Page struct {
	Matches []Match
	// NextPageToken is empty when there are no more authorized matches. Its presence is itself
	// authorization-derived (SPEC-0034 AC2).
	NextPageToken string
}

// IndexStatusEntry is the freshness record of one repository the caller may read (SPEC-0035 AC6).
type IndexStatusEntry struct {
	RepositoryID string
	// LastIndexedRevision is the opaque revision the index last absorbed.
	LastIndexedRevision string
	// IndexedAt is when the index absorbed that revision.
	IndexedAt time.Time
	// FreshnessLag is the measured lag between the indexed revision and the repository's
	// admitted head at status time (SPEC-0034 AC4).
	FreshnessLag time.Duration
}

// Errors are deliberately coarse: one refusal shape for every cause, so denial and not-found do
// not distinguish nonexistent, cross-tenant and unauthorized repositories (SPEC-0035
// non-functional). The specific cause, where one exists, goes to the audit trail.
var (
	// ErrMalformed reports a request the contract cannot honour: missing context, an empty or
	// oversized query, an unknown mode, or an uncompilable regex.
	ErrMalformed = errors.New("codesearch: malformed request")
	// ErrDenied reports a refusal the PDP decided, or a failure to reach one. Both are refusals;
	// there is no third outcome in which proceeding is correct (ADR-0006).
	ErrDenied = errors.New("codesearch: unavailable")
)

// Service is the Code Search context's full in-process surface: the Phase-1 projection read, plus
// the permission-filtered query and status paths SPEC-0034 and SPEC-0035 define. What the plane
// binary holds is this interface, so nothing downstream can depend on which implementation it got.
type Service interface {
	Index

	// Search runs one tenant-scoped query across the repositories the caller may read, derived
	// server-side at query time. A permission revocation binds on this query: no reindex, cache
	// cycle, or cursor reuse serves revoked content (SPEC-0034 AC6, SPEC-0035 AC5). A query whose
	// only matches are unauthorized returns the zero Page (SPEC-0034 AC3).
	Search(ctx context.Context, q Query) (Page, error)

	// GetIndexStatus reports per-repository freshness for repositories the caller may read, and
	// nothing for others — not even existence (SPEC-0035 AC6).
	GetIndexStatus(ctx context.Context, q Query) ([]IndexStatusEntry, error)

	// AttachContentSource wires the route to repository content once the plane has one. Before it
	// is attached the context tracks freshness but absorbs no revisions. It is a composition
	// seam, not a caller operation: cmd/ calls it, and only once.
	AttachContentSource(cs ContentSource)

	// Backfill enqueues indexing for every repository with an admitted revision the index has not
	// absorbed yet, paced so backfill yields to interactive indexing.
	Backfill(ctx context.Context) error

	// Drain blocks until every enqueued indexing job has completed or ctx is done. It is the
	// graceful-shutdown and test-observability seam: after Drain, every push this context has
	// seen is searchable or has reported its lag.
	Drain(ctx context.Context) error

	// TenantIndexSize measures the tenant's index footprint in bytes against the fair-use
	// code-search index size dimension (PRD §6, SPEC-0034 AC7). This spec records the measure and
	// implements no metering; the wire contract has no field capable of carrying it.
	TenantIndexSize(ctx context.Context, tenantID string) (int64, error)
}
