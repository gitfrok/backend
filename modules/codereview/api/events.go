package api

import "time"

// The event names mirror `contracts/events/codereview/v1` exactly; the parity
// test in this package fails if the two drift.
const (
	EventMergeRequestOpened      = "gitsaas.events.codereview.v1.MergeRequestOpened"
	EventMergeRequestUpdated     = "gitsaas.events.codereview.v1.MergeRequestUpdated"
	EventReviewSubmitted         = "gitsaas.events.codereview.v1.ReviewSubmitted"
	EventMergeRequestMerged      = "gitsaas.events.codereview.v1.MergeRequestMerged"
	EventBranchProtectionChanged = "gitsaas.events.codereview.v1.BranchProtectionChanged"
	// EventMergeRequestReady announces a draft's one transition (ADR-0087,
	// SPEC-0064). Notifications consumes it as the review-requested fact it
	// is (SPEC-0063): before this event, everything about a draft was quiet
	// by decision.
	EventMergeRequestReady = "gitsaas.events.codereview.v1.MergeRequestReady"
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

// MergeRequestUpdated records that an open merge request moved: a push to its
// source ref advanced the head revision. Security/Findings consumes it to
// recompute attribution against the new head (SPEC-0028).
type MergeRequestUpdated struct {
	EventID, MergeRequestID, TenantID, RepositoryID string
	ActorID, HeadRevision, SourceRef, TargetRef     string
	OccurredAt                                      time.Time
}

func (MergeRequestUpdated) EventName() string { return EventMergeRequestUpdated }
func (e MergeRequestUpdated) Tenant() string  { return e.TenantID }

// ReviewSubmitted announces one actor's current disposition and the revision it
// was made against. The review comment is deliberately absent. CreatorID is the
// MR's author, carried so a recipient-deriving consumer can notify the author
// and never the reviewer from the event alone (SPEC-0063).
type ReviewSubmitted struct {
	EventID, MergeRequestID, TenantID, RepositoryID string
	ActorID                                         string
	Disposition                                     Disposition
	HeadRevision                                    string
	OccurredAt                                      time.Time
	CreatorID                                       string
}

func (ReviewSubmitted) EventName() string { return EventReviewSubmitted }
func (e ReviewSubmitted) Tenant() string  { return e.TenantID }

// MergeRequestMerged announces a completed merge. CreatorID is the MR's author
// and CountedApprovalActors the names whose approvals counted at the gate —
// APPROVE dispositions at head, author excluded (ADR-0085) — both carried so a
// recipient-deriving consumer needs no reach-back (SPEC-0063). Names only:
// never a count, never an outcome.
type MergeRequestMerged struct {
	EventID, MergeRequestID, TenantID, RepositoryID string
	ActorID, TargetRef, HeadRevision                string
	OccurredAt                                      time.Time
	CreatorID                                       string
	CountedApprovalActors                           []string
}

func (MergeRequestMerged) EventName() string { return EventMergeRequestMerged }
func (e MergeRequestMerged) Tenant() string  { return e.TenantID }

// MergeRequestReady announces a draft's one transition to OPEN (ADR-0087,
// SPEC-0064). It is the draft's first and only announcement: everything
// between Open and MarkReady published nothing by decision.
type MergeRequestReady struct {
	EventID, MergeRequestID, TenantID, RepositoryID string
	// ActorID is the verified actor who marked it ready.
	ActorID string
	// HeadRevision was re-read from the source ref at the transition.
	HeadRevision, TargetRef string
	OccurredAt              time.Time
}

func (MergeRequestReady) EventName() string { return EventMergeRequestReady }
func (e MergeRequestReady) Tenant() string  { return e.TenantID }

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
