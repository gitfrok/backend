package audit

import "time"

// ActionMergeRequestApproved is the `action` value for an accepted review
// approval (SPEC-0019 AC6).
const ActionMergeRequestApproved = "codereview.review.approved"

// ActionMergeRequestMerged is the `action` value for an accepted merge
// (SPEC-0019 AC6).
const ActionMergeRequestMerged = "codereview.merge.approved"

// MergeRequestApproved records one accepted approval, correlated to the PDP
// decision that admitted it. It carries no review text, no approval count, and no
// authorization result: a denial uses the existing PolicyDecisionDenied record.
type MergeRequestApproved struct {
	TenantID         string
	ActorID          string
	RepositoryID     string
	MergeRequestID   string
	HeadRevision     string
	RequestID        string
	PolicyDecisionID string
	OccurredAt       time.Time
}

func (MergeRequestApproved) EventName() string { return EventAudit }
func (MergeRequestApproved) Action() string    { return ActionMergeRequestApproved }
func (e MergeRequestApproved) Tenant() string  { return e.TenantID }

// MergeRequestMerged records one accepted merge, correlated to the PDP decision
// that admitted it.
type MergeRequestMerged struct {
	TenantID         string
	ActorID          string
	RepositoryID     string
	MergeRequestID   string
	TargetRef        string
	HeadRevision     string
	RequestID        string
	PolicyDecisionID string
	OccurredAt       time.Time
}

func (MergeRequestMerged) EventName() string { return EventAudit }
func (MergeRequestMerged) Action() string    { return ActionMergeRequestMerged }
func (e MergeRequestMerged) Tenant() string  { return e.TenantID }
