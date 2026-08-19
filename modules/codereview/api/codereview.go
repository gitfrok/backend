// Package api is the Code Review context's in-process surface (SPEC-0019).
//
// It exposes merge requests, reviews, and exact-ref branch protection as plain
// data and behavioural ports. It deliberately exposes no approval count, no
// protection outcome, and no allow flag: those are server-derived facts the PDP
// consumes, never values a caller can assert (invariant 2, SPEC-0019 AC5).
package api

import (
	"context"
	"errors"
	"time"
)

// ErrDenied is the coarse refusal every failed command returns. It deliberately
// does not distinguish a missing merge request from one in another tenant, so the
// surface cannot be used to enumerate either (SPEC-0019 AC2).
var ErrDenied = errors.New("codereview: merge request unavailable")

// ErrVersionConflict is returned when a mutation carries a stale expected
// version. It changes no state.
var ErrVersionConflict = errors.New("codereview: stale version")

// State is the merge-request lifecycle. A merge is terminal, and a closed
// request can be neither reviewed nor merged.
type State string

const (
	StateOpen   State = "OPEN"
	StateClosed State = "CLOSED"
	StateMerged State = "MERGED"
)

// Disposition is one actor's current position on a merge request. Only APPROVE,
// against the merge request's current head revision, is a valid approval.
type Disposition string

const (
	DispositionApprove        Disposition = "APPROVE"
	DispositionRequestChanges Disposition = "REQUEST_CHANGES"
	DispositionComment        Disposition = "COMMENT"
)

// Context is the verified identity a command is evaluated under. The actor and
// its roles come from authenticated identity; a caller cannot assert them, and an
// empty or cross-tenant context is a coarse denial.
type Context struct {
	TenantID, RepositoryID, ActorID, RequestID string
	ActorRoles                                 []string
}

// MergeRequest is the bounded review state. It carries no filesystem location,
// credential, Git pack bytes, policy outcome, approval count, or audit sequence.
type MergeRequest struct {
	ID, TenantID, RepositoryID string
	SourceRef, TargetRef       string
	Title, Description         string
	CreatorID                  string
	State                      State
	HeadRevision               string
	// TargetRevision is where the target ref stood when this context last saw it.
	// A merge names it so the ref move lands only on the state the merge was
	// decided against. It comes from Repository/Git's own ref announcements — a
	// caller cannot assert it, which is what stops one naming a state of its
	// choosing.
	TargetRevision       string
	CreatedAt, UpdatedAt time.Time
	// Version is server-assigned and positive. Every mutation is guarded by it.
	Version int64
	// ExternalIssues are references to issues in the customer's own tracker
	// (SPEC-0059). They are inert: nothing here satisfies a merge policy, changes a
	// review outcome, or closes anything — see external_issue.go.
	ExternalIssues []ExternalIssue
}

// BranchProtection is an exact `refs/heads/...` rule. Zero required approvals
// still protects the ref from direct pushes while permitting authorized merges.
type BranchProtection struct {
	TenantID, RepositoryID, TargetRef string
	RequiredApprovals                 int32
	Version                           int64
}

// OpenRequest opens a merge request from one source ref to one target ref.
type OpenRequest struct {
	Context
	SourceRef, TargetRef string
	Title, Description   string
}

// ReviewRequest records one actor's current disposition. A later submission by
// the same actor supersedes their previous one without mutating prior audit
// evidence.
type ReviewRequest struct {
	Context
	MergeRequestID  string
	Disposition     Disposition
	Comment         string
	HeadRevision    string
	ExpectedVersion int64
}

// MergeRequestCommand merges an open request. It carries no target ref, commit
// SHA, approval count, policy result, or force flag.
type MergeRequestCommand struct {
	Context
	MergeRequestID  string
	ExpectedVersion int64
}

// ProtectionRequest replaces the exact-ref rule for a target ref.
type ProtectionRequest struct {
	Context
	TargetRef         string
	RequiredApprovals int32
	ExpectedVersion   int64
}

// ImportState is the coarse lifecycle of an import job (SPEC-0011).
type ImportState string

const (
	ImportPending  ImportState = "PENDING"
	ImportRunning  ImportState = "RUNNING"
	ImportComplete ImportState = "COMPLETE"
	ImportFailed   ImportState = "FAILED"
	ImportStalled  ImportState = "STALLED"
	ImportRevoked  ImportState = "REVOKED"
)

// Import is the import job's state, scoped to one tenant and repository. It
// carries no source token, no audit content, and no credential (SPEC-0011
// AC22).
type Import struct {
	ID, TenantID, RepositoryID string
	SourceURL                  string
	SourceSystem               string
	SourceInstance             string
	State                      ImportState
	ManifestDigest             string
	GitPhaseComplete           bool
	HistoryPhaseComplete       bool
	RecordCounts               map[string]int64
	FailureReason              string
	CreatedAt, UpdatedAt       time.Time
}

// CreateImportRequest starts (or resumes) an import of one source repository.
type CreateImportRequest struct {
	Context
	SourceURL, SourceSystem, SourceInstance string
	SourceToken                             string
}

// RevokeImportRequest tombstones an import's records.
type RevokeImportRequest struct {
	Context
	ImportID string
}

// ListImportedHistoryRequest reads one page of an import's imported merge
// requests, so a reader can render them beside first-party history while
// telling the two apart (SPEC-0011 AC20, which AC23's rendering depends on).
type ListImportedHistoryRequest struct {
	Context
	ImportID string
	// PageSize is the maximum number of records to return. Zero means
	// DefaultImportedHistoryPageSize; anything above MaxImportedHistoryPageSize
	// is clamped to it. An import may hold tens of thousands of records, so no
	// caller can ask for the whole set in one response.
	PageSize int
	// PageToken is the token a previous result returned. Empty starts at the
	// first page.
	PageToken string
}

// Paging bounds for an imported-history read.
const (
	DefaultImportedHistoryPageSize = 50
	MaxImportedHistoryPageSize     = 200
)

// ImportedHistoryPage is one page of imported merge requests. It is empty for a
// revoked import: its records are dropped from every read (SPEC-0011 AC17).
type ImportedHistoryPage struct {
	MergeRequests []ImportedMergeRequest
	// NextPageToken is empty when this is the last page.
	NextPageToken string
}

// DeclaredActorMapping is one tenant admin's assertion that a foreign handle is
// a platform identity (SPEC-0011 AC10/AC22-AC24).
//
// It lives beside the imported records, never inside them: an imported record is
// immutable (AC13), so a mapping is a later first-party claim *about* one. It
// changes the label a reader sees and never the class of the record — a mapped
// handle's approval is still an imported approval and still satisfies no merge
// policy.
type DeclaredActorMapping struct {
	MappingID string
	TenantID  string
	ImportID  string
	// DeclaredActor and SourceInstance together identify the handle. Neither
	// alone does: the same handle on two source instances is two people.
	DeclaredActor  string
	SourceInstance string
	// ActorID is the platform identity the admin asserts the handle belongs to.
	ActorID string
	// AssertedBy is the tenant admin who made the claim, kept here as well as in
	// the audit event so a reader of the mapping never has to join to the trail
	// to see who is accountable for it.
	AssertedBy string
	AssertedAt time.Time
}

// MapDeclaredActorRequest asserts one mapping. Every identifier the platform
// cares about comes from the verified context; the request contributes only the
// handle, its instance, and the identity being asserted.
type MapDeclaredActorRequest struct {
	Context
	ImportID       string
	DeclaredActor  string
	SourceInstance string
	// MappedActorID is the platform identity being asserted. It is deliberately
	// not named ActorID: the embedded Context already carries an ActorID — the
	// admin making the assertion — and two fields of that name in one request is
	// how the asserter and the asserted-about end up swapped.
	MappedActorID string
}

// ImportService is the import surface. Code Review owns imported history as
// ATTESTED_IMPORT domain data (ADR-0029 §2); Audit owns only the
// HistoryImported/HistoryImportRevoked events.
type ImportService interface {
	Create(context.Context, CreateImportRequest) (Import, error)
	Get(context.Context, Context, string) (Import, error)
	List(context.Context, Context, string) ([]Import, error)
	Revoke(context.Context, RevokeImportRequest) (Import, error)
	ListImportedHistory(context.Context, ListImportedHistoryRequest) (ImportedHistoryPage, error)
	// VerifyImport recomputes the manifest digest over the imported set as it
	// stands now and reports whether it still matches what the HistoryImported
	// event recorded (SPEC-0011 AC16). It is a read: a mismatch is a finding, not
	// something to repair, and the original chain entry is never touched.
	VerifyImport(context.Context, Context, string) (bool, error)
	// MapDeclaredActor records a named tenant admin's assertion that a foreign
	// handle belongs to a platform identity (SPEC-0011 AC10/AC22). It is an
	// assertion, never an inference: no comparison of emails or names produces a
	// mapping, and the asserting admin is recorded with it.
	MapDeclaredActor(context.Context, MapDeclaredActorRequest) (DeclaredActorMapping, error)
	// ListDeclaredActorMappings returns the mappings asserted for one import.
	ListDeclaredActorMappings(context.Context, Context, string) ([]DeclaredActorMapping, error)
}

// Provenance is the immutable ADR-0029 block attached to every imported
// history record. It asserts what was fetched from a foreign system; it never
// claims the content is true. declared_at is display-only.
type Provenance struct {
	Class          string // FIRST_PARTY | ATTESTED_IMPORT
	ImportID       string
	SourceSystem   string
	SourceInstance string
	SourceRef      string
	DeclaredActor  string
	DeclaredAt     time.Time
	PayloadDigest  string
}

// Attest classes. Only FIRST_PARTY may enter the audit log (ADR-0029 §1).
const (
	AttestFirstParty = "FIRST_PARTY"
	AttestImported   = "ATTESTED_IMPORT"
)

// ImportedThread is one imported review thread (SPEC-0011 AC4). The anchor
// degrades from DIFF to FILE to MERGE rather than dropping a comment (AC5).
type ImportedThread struct {
	ThreadID       string
	MergeRequestID string
	Path           string
	Anchor         string // DIFF | FILE | MERGE
	Comments       []ImportedComment
	Provenance     Provenance
}

// Anchor precisions for an imported thread. DIFF is the only exact anchor: the
// source still declared a resolvable diff position. FILE and MERGE are
// approximate, and the read surface marks them so the UI can render them as
// such (SPEC-0011 AC5/AC19).
const (
	AnchorDiff  = "DIFF"
	AnchorFile  = "FILE"
	AnchorMerge = "MERGE"
)

// DeclaredAnchor is the strongest anchor an import may claim from what the
// source declared alone: the file when the source named a path, the merge
// request when it named none. No comment is ever dropped for want of an anchor
// (AC5).
//
// It deliberately never returns DIFF. A diff anchor asserts that the position
// still resolves, and only the imported git tree can settle that — the source's
// own payload cannot: GitLab echoes a diff note's original path and line even
// after the file is deleted, so trusting it would mark a stale anchor exact.
// Until an import resolves positions against the refs it imported, every
// imported anchor is approximate and says so.
func DeclaredAnchor(path string) string {
	if path != "" {
		return AnchorFile
	}
	return AnchorMerge
}

// Approximate reports whether a thread's anchor is weaker than the diff
// position it was written against, which is what the UI labels as approximate
// (AC5, AC23).
func (t ImportedThread) Approximate() bool { return t.Anchor != AnchorDiff }

// ImportedComment is one imported review comment.
type ImportedComment struct {
	CommentID     string
	DeclaredActor string
	Body          string
	DeclaredAt    time.Time
	Provenance    Provenance
}

// ImportedApproval is one imported approval. It never satisfies a merge policy
// and is never rendered as a platform approval (ADR-0029 §4).
type ImportedApproval struct {
	ApprovalID     string
	MergeRequestID string
	DeclaredActor  string
	DeclaredAt     time.Time
	Provenance     Provenance
}

// ImportedMergeRequest is one imported MR: title, description, state, refs,
// threads, approvals, declared_actor and declared_at as declared (AC4).
type ImportedMergeRequest struct {
	MergeRequestID string
	SourceRef      string
	TargetRef      string
	Title          string
	Description    string
	// State is the source's own state string ("open", "merged", "closed", …),
	// never this platform's MergeRequestState: an imported MR never enters our
	// lifecycle.
	State string
	// DeclaredCreator is the declared author as an opaque foreign handle. It is
	// deliberately not named CreatorID: MergeRequest.CreatorID is a resolvable
	// platform actor, and a field of the same name here would invite a reader to
	// resolve a foreign handle as a platform user (ADR-0029 §4, SPEC-0011 AC14).
	DeclaredCreator string
	Threads         []ImportedThread
	Approvals       []ImportedApproval
	Provenance      Provenance
}

// ImportedRecordStore persists imported history as ATTESTED_IMPORT domain data
// (ADR-0029 §2). Append-only within the context; tombstoned on revoke. No
// individual update or delete path exists (AC13).
type ImportedRecordStore interface {
	// PutImport stores the imported MRs for one import, idempotently per
	// (import_id, merge_request_id).
	PutImport(ctx context.Context, importID string, records []ImportedMergeRequest) error
	// ListImport returns the imported MRs for one import, or nil if revoked.
	ListImport(ctx context.Context, importID string) ([]ImportedMergeRequest, error)
	// Tombstone marks every record of an import excluded from reads.
	Tombstone(ctx context.Context, importID string) error
	// PutMapping records one declared-actor mapping, idempotently per
	// (import_id, declared_actor, source_instance). Re-asserting the same
	// identity returns the existing mapping; asserting a *different* identity for
	// a handle already mapped is refused — a silent overwrite would let one admin
	// replace another's claim with no trace of the first.
	PutMapping(ctx context.Context, mapping DeclaredActorMapping) (DeclaredActorMapping, error)
	// ListMappings returns the mappings asserted for one import, or nil if the
	// import is revoked: a mapping describes records that are gone from reads
	// (SPEC-0011 AC24).
	ListMappings(ctx context.Context, importID string) ([]DeclaredActorMapping, error)
}

// ErrMappingConflict is returned when a handle is already mapped to a different
// platform identity. It is not a retryable error: resolving it is a human act,
// and the existing claim stays until someone accountable changes it.
var ErrMappingConflict = errors.New("codereview: this handle is already mapped to another identity")

// MergeRequests is the context's full in-process surface.
type MergeRequests interface {
	Open(context.Context, OpenRequest) (MergeRequest, error)
	Get(context.Context, Context, string) (MergeRequest, error)
	Review(context.Context, ReviewRequest) (MergeRequest, error)
	Merge(context.Context, MergeRequestCommand) (MergeRequest, error)
	SetProtection(context.Context, ProtectionRequest) (BranchProtection, error)
	// LinkExternalIssue and UnlinkExternalIssue reference an issue that lives
	// elsewhere (SPEC-0059). They are on this port rather than a new one because a
	// reference is a property of a merge request, and there is no Issues context
	// for them to belong to — which is the whole of ADR-0074's accepted scope.
	LinkExternalIssue(context.Context, LinkExternalIssueRequest) (MergeRequest, error)
	UnlinkExternalIssue(context.Context, UnlinkExternalIssueRequest) (MergeRequest, error)
}
