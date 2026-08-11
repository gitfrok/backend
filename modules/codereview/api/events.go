package api

import "time"

// The event names mirror `contracts/events/codereview/v1` exactly; the parity
// test in this package fails if the two drift.
const (
	EventMergeRequestOpened      = "gitsaas.events.codereview.v1.MergeRequestOpened"
	EventReviewSubmitted         = "gitsaas.events.codereview.v1.ReviewSubmitted"
	EventMergeRequestMerged      = "gitsaas.events.codereview.v1.MergeRequestMerged"
	EventBranchProtectionChanged = "gitsaas.events.codereview.v1.BranchProtectionChanged"
)

// MergeRequestOpened announces a new merge request. Like every event here it
// carries opaque IDs and tenant scope, never review text, credentials, Git
// objects, or a policy allow flag.
type MergeRequestOpened struct {
	EventID, MergeRequestID, TenantID, RepositoryID string
	SourceRef, TargetRef, CreatorID                 string
	OccurredAt                                      time.Time
}

func (MergeRequestOpened) EventName() string { return EventMergeRequestOpened }
func (e MergeRequestOpened) Tenant() string  { return e.TenantID }

// ReviewSubmitted announces one actor's current disposition and the revision it
// was made against. The review comment is deliberately absent.
type ReviewSubmitted struct {
	EventID, MergeRequestID, TenantID, RepositoryID string
	ActorID                                         string
	Disposition                                     Disposition
	HeadRevision                                    string
	OccurredAt                                      time.Time
}

func (ReviewSubmitted) EventName() string { return EventReviewSubmitted }
func (e ReviewSubmitted) Tenant() string  { return e.TenantID }

// MergeRequestMerged announces a completed merge.
type MergeRequestMerged struct {
	EventID, MergeRequestID, TenantID, RepositoryID string
	ActorID, TargetRef, HeadRevision                string
	OccurredAt                                      time.Time
}

func (MergeRequestMerged) EventName() string { return EventMergeRequestMerged }
func (e MergeRequestMerged) Tenant() string  { return e.TenantID }

// BranchProtectionChanged is the only Code Review event Repository/Git consumes,
// into its own tenant-scoped projection. Repository/Git never reads Code Review's
// tables and never calls it on the receive-pack path (SPEC-0019 AC7).
type BranchProtectionChanged struct {
	EventID, TenantID, RepositoryID, TargetRef string
	RequiredApprovals                          int32
	OccurredAt                                 time.Time
	// ActorID is the verified subject whose authorized SetProtection produced
	// this change. Cross-process consumers re-derive the PDP subject from it
	// when they apply the rule at their own enforcement point.
	ActorID string
	// ActorRoles are the roles the subject held when the change was decided,
	// carried so a cross-process consumer can re-run its own PDP decision with
	// the same subject the authorizing PEP saw (events/ci RefUpdated precedent).
	// They are identity attributes, never a policy outcome.
	ActorRoles []string
}

func (BranchProtectionChanged) EventName() string { return EventBranchProtectionChanged }
func (e BranchProtectionChanged) Tenant() string  { return e.TenantID }
