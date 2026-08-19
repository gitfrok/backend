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

// ActionMergeRequestExternalIssueLinked and ...Unlinked are the `action` values for
// referencing an issue that lives in the customer's own tracker (SPEC-0059).
const (
	ActionMergeRequestExternalIssueLinked   = "codereview.external_issue.linked"
	ActionMergeRequestExternalIssueUnlinked = "codereview.external_issue.unlinked"
)

// MergeRequestExternalIssue records one link or unlink act.
//
// It carries the tracker and the issue key, and NOT the URL. The key is the
// identifier an investigation needs — "this change was for PLAT-1421" — while a URL
// is customer-supplied text, and ADR-0074 decision 2 keeps issue content out of a
// control record. This product stores no issue title, body or state anywhere, so
// keeping the identifier and dropping the text is the whole of what that decision
// asks for here.
//
// Linked distinguishes the two acts rather than two types doing the same work: an
// investigation asks "when was this issue referenced, and was it removed", which is
// one question over one sequence of records.
type MergeRequestExternalIssue struct {
	TenantID       string
	ActorID        string
	RepositoryID   string
	MergeRequestID string
	Tracker        string
	IssueKey       string
	// Linked is true for a link and false for an unlink.
	Linked     bool
	RequestID  string
	OccurredAt time.Time
}

func (MergeRequestExternalIssue) EventName() string { return EventAudit }

// Action names which act this is, so the trail's action vocabulary distinguishes
// them without a consumer reading a boolean.
func (e MergeRequestExternalIssue) Action() string {
	if e.Linked {
		return ActionMergeRequestExternalIssueLinked
	}
	return ActionMergeRequestExternalIssueUnlinked
}

func (e MergeRequestExternalIssue) Tenant() string { return e.TenantID }
