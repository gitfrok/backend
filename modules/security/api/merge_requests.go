package api

// The merge-request findings read surface (SPEC-0028): findings attributed
// to one merge request, computed as the difference between what the MR's
// head revision reports and what its merge base reports.
//
// The merge request reaches Security/Findings only as an opaque identifier,
// fed by Code Review's events into a tenant-scoped local projection;
// Security/Findings reads no Code Review table, and the request carries no
// head revision, no merge base, no attribution claim, and no authorization
// outcome — all of those are server facts (ADR-0022, SPEC-0028).

import "context"

// AttributionStatus is the outcome of comparing what a merge request's head
// revision reports against what its merge base reports (SPEC-0028). It is
// server-derived state: no request carries it, and a caller-asserted
// attribution is not representable in v1.
type AttributionStatus string

const (
	// AttributionAttributed: present at the MR's head revision and absent at
	// the merge base — the merge request introduced it (SPEC-0028 attribution
	// rule).
	AttributionAttributed AttributionStatus = "ATTRIBUTED"
	// AttributionPreExisting: present at both the head and the merge base —
	// it predates the merge request and is never attributed to it, whatever
	// its first-seen time (SPEC-0028 AC1/AC2).
	AttributionPreExisting AttributionStatus = "PRE_EXISTING"
	// AttributionUnavailable: attribution cannot be computed because one side
	// of the comparison is missing. The reason is in
	// AttributionUnavailableReason, never in an empty result set
	// (SPEC-0028 AC7).
	AttributionUnavailable AttributionStatus = "UNAVAILABLE"
)

// AttributionStatusUnspecified names the absence of a filter value; it is
// never a status a view carries.
const AttributionStatusUnspecified AttributionStatus = ""

// Valid reports whether the status is one a view or a summary can hold.
func (s AttributionStatus) Valid() bool {
	switch s {
	case AttributionAttributed, AttributionPreExisting, AttributionUnavailable:
		return true
	}
	return false
}

// AttributionUnavailableReason names why attribution is UNAVAILABLE. The
// reason is an honest rendering of a scan that failed, timed out, has not
// run, or cannot be compared — never "no findings" (SPEC-0028).
type AttributionUnavailableReason string

const (
	// AttributionUnavailableBaseNotScanned: the merge base has never been
	// scanned (SPEC-0028 attribution rule).
	AttributionUnavailableBaseNotScanned AttributionUnavailableReason = "BASE_NOT_SCANNED"
	// AttributionUnavailableHeadScanFailed: the scan of the MR's head
	// revision failed (SPEC-0028 AC7). Representable in v1; the failure feed
	// that would produce it is not wired yet.
	AttributionUnavailableHeadScanFailed AttributionUnavailableReason = "HEAD_SCAN_FAILED"
	// AttributionUnavailableHeadScanTimedOut: the scan of the MR's head
	// revision timed out (SPEC-0028 AC7). Representable in v1; the failure
	// feed that would produce it is not wired yet.
	AttributionUnavailableHeadScanTimedOut AttributionUnavailableReason = "HEAD_SCAN_TIMED_OUT"
	// AttributionUnavailableHeadScanNotRun: no scan of the MR's head revision
	// has run yet (SPEC-0028 AC7).
	AttributionUnavailableHeadScanNotRun AttributionUnavailableReason = "HEAD_SCAN_NOT_RUN"
	// AttributionUnavailableNoMergeBase: no merge base exists for the
	// source/target pair — e.g. unrelated histories — so nothing can be
	// compared against. The merge request reports UNAVAILABLE rather than
	// attributing everything (SPEC-0028 open questions).
	AttributionUnavailableNoMergeBase AttributionUnavailableReason = "NO_MERGE_BASE"
)

// MergeRequestFindingsRequest pages the findings attributable to one merge
// request (SPEC-0028). It carries no head revision, no merge base, no
// attribution claim, and no authorization outcome: the request can only name
// the merge request and the filters to render it under.
type MergeRequestFindingsRequest struct {
	Context
	// MergeRequestID is the opaque, Code Review-assigned merge-request
	// identity.
	MergeRequestID string
	// Filters: an empty value is no filter for its dimension, and filters
	// combine, as in ListFindings (SPEC-0026 AC2).
	ScannerClassFilter ScannerClass
	SeverityFilter     Severity
	// AttributionFilter is AttributionStatusUnspecified for no filter.
	AttributionFilter AttributionStatus
	// PageSize: zero means DefaultPageSize; anything above MaxPageSize is
	// clamped to it.
	PageSize int
	// PageToken is the token a previous page returned. Tokens are signed and
	// bound to the tenant and the filters that issued them; a forged or
	// mismatched token yields no content (SPEC-0025).
	PageToken string
}

// MergeRequestFindingView is one finding as it renders on the merge request
// under review: the finding itself, the triage state attached to its
// identity, its location at the head revision, and its attribution status
// (SPEC-0028). Triage travels here as view state, never as a field of the
// Finding (SPEC-0027 AC7): a triaged finding renders in its triaged state
// rather than as new (SPEC-0028 AC5).
type MergeRequestFindingView struct {
	Finding Finding
	// Triage is the latest triage record on the finding's identity. Nil —
	// and nil alone — means no triage decision has been recorded
	// (SPEC-0001: denial is a coarse denial of the whole request, never a
	// view with an empty triage).
	Triage *TriageRecord
	// HeadLocation is the finding's location as resolved at the MR's head
	// revision. Identity is revision-invariant (SPEC-0024), so a later push
	// within the MR re-resolves the location without changing the finding
	// (SPEC-0028 AC4).
	HeadLocation Location
	Attribution  AttributionStatus
	// UnavailableReason is set only when Attribution is
	// AttributionUnavailable: the honest reason the comparison cannot be
	// computed (SPEC-0028 AC7).
	UnavailableReason AttributionUnavailableReason
}

// AttributionSummary is the response-level statement of what was compared
// and what the comparison produced. Attribution is reproducible from two
// named revisions (SPEC-0028 G5), so the summary names them.
type AttributionSummary struct {
	Status AttributionStatus
	// UnavailableReason is set only when Status is AttributionUnavailable.
	UnavailableReason AttributionUnavailableReason
	// HeadRevision is the MR's current head as Security/Findings learned it
	// from Code Review's events.
	HeadRevision string
	// MergeBaseRevision is the merge base of the MR's source and target,
	// resolved through Repository/Git (repository.v1
	// RepositoryReader.GetMergeBase). Empty when no merge base exists; the
	// summary then reports UNAVAILABLE with AttributionUnavailableNoMergeBase.
	MergeBaseRevision string
	// Stale reports a recomputation is pending or the served attribution
	// lags the MR's current head/base. A stale attribution is reported as
	// stale, never served as current (SPEC-0028 non-functional).
	Stale bool
	// Counts of ATTRIBUTED findings by severity. A summary can never be
	// wider than the list it summarizes (SPEC-0026 AC6).
	AttributedLow      int64
	AttributedMedium   int64
	AttributedHigh     int64
	AttributedCritical int64
}

// MergeRequestFindingsPage is one page of merge-request findings plus the
// comparison it was served from. The summary is always present: the shape
// has no way to say "no findings" without also saying what was compared
// (SPEC-0028 AC7).
type MergeRequestFindingsPage struct {
	Views []MergeRequestFindingView
	// NextPageToken is empty when this is the last page.
	NextPageToken string
	Summary       AttributionSummary
}

// MergeBaseResolver resolves the merge base of two refs for one repository.
// It is the port Security/Findings knows Repository/Git by for attribution
// (SPEC-0028): the composition root supplies the repository.v1
// RepositoryReader.GetMergeBase route, and an unresolved resolver leaves
// attribution honestly UNAVAILABLE rather than guessing.
type MergeBaseResolver interface {
	// MergeBase returns the merge-base revision of refA and refB. Found is
	// false — not an error — when the pair has no common ancestor. An error
	// means the comparison could not be answered at all.
	MergeBase(ctx context.Context, tenantID, repositoryID, actorID, refA, refB string) (mergeBase string, found bool, err error)
}
