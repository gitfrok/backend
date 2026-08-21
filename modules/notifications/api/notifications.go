// Package api is the Notifications context's in-process surface (SPEC-0063,
// ADR-0086). It exposes one aggregate — a thing a person has not read yet — as
// plain data and a behavioural port. Recipients never arrive from callers:
// they are derived server-side from bus events and the stores those events
// concern, exactly as attribution derives its diff.
package api

import (
	"context"
	"errors"
	"time"
)

// ErrDenied is the one coarse refusal. A notification that does not exist, one
// belonging to another recipient, and one in another tenant are the same
// refusal, so this surface cannot be used to enumerate any of them.
var ErrDenied = errors.New("notifications: notification unavailable")

// Kind is what happened, mirroring contracts/proto/notifications/v1's
// NotificationKind vocabulary. It exists so a reader renders "what happened"
// without parsing event names, and grows additively with the coverage table.
type Kind string

const (
	KindMergeRequestReadyForReview Kind = "MERGE_REQUEST_READY_FOR_REVIEW"
	KindReviewSubmitted            Kind = "REVIEW_SUBMITTED"
	KindMergeRequestMerged         Kind = "MERGE_REQUEST_MERGED"
	KindFindingsAttributed         Kind = "FINDINGS_ATTRIBUTED"
)

// Notification is one row: an act worth telling someone about, addressed to
// the one it concerns. ID is opaque and stable across replays of the event
// that produced it; RecipientID is derived server-side and never accepted
// from a caller.
type Notification struct {
	ID, TenantID, RecipientID string
	Kind                      Kind
	RepositoryID              string
	// MergeRequestID is empty for events not about a merge request.
	MergeRequestID string
	// ActorID is who did it — reviewed, merged, opened. Empty for events with
	// no actor (findings attribution).
	ActorID string
	// HeadRevision is the revision at the act, when the event carried one.
	HeadRevision string
	OccurredAt   time.Time
	Read         bool
}

// Context scopes a read to one verified caller. The recipient IS the actor on
// the context: there is no way to name somebody else's rows.
type Context struct {
	TenantID, ActorID string
}

// ListRequest reads one page of the caller's notifications, newest first.
type ListRequest struct {
	Context
	// PageSize zero means DefaultPageSize; above MaxPageSize it clamps.
	PageSize  int
	PageToken string
}

// Paging bounds for a notifications read.
const (
	DefaultPageSize = 50
	MaxPageSize     = 200
)

// Page is one page of notifications, newest first. NextPageToken is empty when
// this is the last page.
type Page struct {
	Notifications []Notification
	NextPageToken string
}

// Notifications is the context's read surface: list, unread count, mark-read.
// There is no create — rows exist because events happened, not because a
// caller asked (G5: nothing is notified that did not happen).
type Notifications interface {
	List(context.Context, ListRequest) (Page, error)
	UnreadCount(context.Context, Context) (int64, error)
	// MarkRead marks ONE notification read, by its opaque ID, for the caller
	// on the context. Marking one marks one (SPEC-0063 AC6).
	MarkRead(context.Context, Context, string) (Notification, error)
}
