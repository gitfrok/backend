// Package app derives recipients from events, writes one row per (recipient,
// event), and serves the reads the bell renders (SPEC-0063, ADR-0086).
//
// Two properties are load-bearing:
//
//   - Idempotency is keyed on the event ID: the bus delivers at-least-once in
//     principle (and the in-process stage redelivers on any retry), so a
//     replayed event must make no second row.
//   - Recipient coverage: every subscribed event names who should hear about
//     it, and the coverage table test fails when a known event type has no
//     rule — a forgotten case would otherwise be a silent non-notification,
//     invisible by construction (ADR-0086's named risk).
package app

import (
	"context"
	"slices"
	"time"

	"github.com/gitfrok/backend/modules/notifications/api"
)

// Row is one durable notification as the store sees it. The natural key is
// (tenant, recipient, event): at-least-once delivery, exactly-once rows.
type Row struct {
	EventID        string // also the row's opaque external ID
	TenantID       string
	RecipientID    string
	Kind           api.Kind
	RepositoryID   string
	MergeRequestID string
	ActorID        string
	HeadRevision   string
	OccurredAt     time.Time
}

// Store persists notification rows. Append is idempotent per the natural key:
// appending an existing row changes nothing. There is no delete path; read
// rows accumulate until retention is decided (SPEC-0063 open question 1).
type Store interface {
	Append(ctx context.Context, rows []Row) error
	List(ctx context.Context, tenantID, recipientID string, pageSize int, pageToken string) (api.Page, error)
	UnreadCount(ctx context.Context, tenantID, recipientID string) (int64, error)
	MarkRead(ctx context.Context, tenantID, recipientID, eventID string, readAt time.Time) (api.Notification, error)
}

// CreatorStore is the tenant-scoped projection of merge-request authors. The
// findings event does not carry the author, and this context never reads Code
// Review's tables (invariant 15): it keeps its own projection fed by the same
// opened/ready events everyone else sees — the security module's pattern.
type CreatorStore interface {
	PutCreator(ctx context.Context, tenantID, repositoryID, mergeRequestID, creatorID string) error
	Creator(ctx context.Context, tenantID, repositoryID, mergeRequestID string) (string, error)
}

// Directory names a tenant's review-capable principals for AC1/ready
// recipient derivation. The backend implementation reads identity's own
// memberships through that module's api surface (invariant 14) — a
// protection rule carries a required-approval count, not holder identities,
// so reviewers-to-be resolves to principals whose roles grant
// merge_request.review in governance/policies (owner, member).
type Directory interface {
	ReviewCapableActors(ctx context.Context, tenantID string) ([]string, error)
}

// Service implements api.Notifications and the bus handlers Subscribe wires.
type Service struct {
	store     Store
	creators  CreatorStore
	directory Directory
	now       func() time.Time
}

func New(store Store, creators CreatorStore, directory Directory) *Service {
	if store == nil {
		panic("notifications: no store")
	}
	return &Service{store: store, creators: creators, directory: directory, now: time.Now}
}

// List returns the caller's page. The recipient is the caller on the context;
// there is no way to read somebody else's rows through this port.
func (s *Service) List(ctx context.Context, req api.ListRequest) (api.Page, error) {
	if req.TenantID == "" || req.ActorID == "" {
		return api.Page{}, api.ErrDenied
	}
	size := req.PageSize
	if size == 0 {
		size = api.DefaultPageSize
	}
	if size > api.MaxPageSize {
		size = api.MaxPageSize
	}
	return s.store.List(ctx, req.TenantID, req.ActorID, size, req.PageToken)
}

// UnreadCount is exact: zero is zero (SPEC-0063 AC7).
func (s *Service) UnreadCount(ctx context.Context, c api.Context) (int64, error) {
	if c.TenantID == "" || c.ActorID == "" {
		return 0, api.ErrDenied
	}
	return s.store.UnreadCount(ctx, c.TenantID, c.ActorID)
}

// MarkRead marks one of the caller's own rows. An unknown or foreign ID is
// the same coarse refusal as anything else not the caller's own.
func (s *Service) MarkRead(ctx context.Context, c api.Context, id string) (api.Notification, error) {
	if c.TenantID == "" || c.ActorID == "" || id == "" {
		return api.Notification{}, api.ErrDenied
	}
	return s.store.MarkRead(ctx, c.TenantID, c.ActorID, id, s.now().UTC())
}

// append derives nothing further: it writes what the handler decided, once
// per recipient, idempotently.
func (s *Service) append(ctx context.Context, rows []Row) error {
	if len(rows) == 0 {
		return nil
	}
	return s.store.Append(ctx, rows)
}

// minus excludes the actor from a recipient set. Exclusion happens before the
// write: nobody is notified about their own act.
func minus(actors []string, exclude ...string) []string {
	out := make([]string, 0, len(actors))
	for _, a := range actors {
		if a != "" && !slices.Contains(exclude, a) {
			out = append(out, a)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}
