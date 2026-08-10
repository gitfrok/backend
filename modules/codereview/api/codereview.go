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

// MergeRequests is the context's full in-process surface.
type MergeRequests interface {
	Open(context.Context, OpenRequest) (MergeRequest, error)
	Get(context.Context, Context, string) (MergeRequest, error)
	Review(context.Context, ReviewRequest) (MergeRequest, error)
	Merge(context.Context, MergeRequestCommand) (MergeRequest, error)
	SetProtection(context.Context, ProtectionRequest) (BranchProtection, error)
}
