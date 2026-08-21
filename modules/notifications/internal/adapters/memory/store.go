package memory

import (
	"context"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gitfrok/backend/modules/notifications/api"
	"github.com/gitfrok/backend/modules/notifications/internal/app"
)

// Store is the in-memory notifications store for dev planes and tests. It
// holds the same idempotency and scoping properties the durable one grants:
// one row per (tenant, recipient, event), reads confined to one recipient.
type Store struct {
	mu       sync.Mutex
	rows     map[string]app.Row // key: tenant|recipient|event
	read     map[string]time.Time
	creators map[string]string // key: tenant|repo|mr -> creator
}

func New() *Store {
	return &Store{rows: map[string]app.Row{}, read: map[string]time.Time{}, creators: map[string]string{}}
}

func key(tenantID, recipientID, eventID string) string {
	return tenantID + "|" + recipientID + "|" + eventID
}

func creatorKey(tenantID, repositoryID, mergeRequestID string) string {
	return tenantID + "|" + repositoryID + "|" + mergeRequestID
}

func (s *Store) Append(_ context.Context, rows []app.Row) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range rows {
		k := key(r.TenantID, r.RecipientID, r.EventID)
		if _, exists := s.rows[k]; exists {
			continue // at-least-once delivery, exactly-once rows (AC4)
		}
		s.rows[k] = r
	}
	return nil
}

func (s *Store) view(r app.Row, now readAt) api.Notification {
	_, wasRead := s.read[key(r.TenantID, r.RecipientID, r.EventID)]
	return api.Notification{
		ID: r.EventID, TenantID: r.TenantID, RecipientID: r.RecipientID,
		Kind: r.Kind, RepositoryID: r.RepositoryID, MergeRequestID: r.MergeRequestID,
		ActorID: r.ActorID, HeadRevision: r.HeadRevision,
		OccurredAt: r.OccurredAt, Read: wasRead,
	}
}

type readAt = time.Time

func (s *Store) List(_ context.Context, tenantID, recipientID string, pageSize int, pageToken string) (api.Page, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	offset := 0
	if pageToken != "" {
		v, err := strconv.Atoi(pageToken)
		if err != nil || v < 0 {
			return api.Page{}, api.ErrDenied
		}
		offset = v
	}
	var matched []app.Row
	for k, r := range s.rows {
		if strings.SplitN(k, "|", 3)[0] == tenantID && r.RecipientID == recipientID {
			matched = append(matched, r)
		}
	}
	sort.Slice(matched, func(i, j int) bool {
		if !matched[i].OccurredAt.Equal(matched[j].OccurredAt) {
			return matched[i].OccurredAt.After(matched[j].OccurredAt)
		}
		return matched[i].EventID < matched[j].EventID
	})
	page := api.Page{}
	if offset >= len(matched) {
		return page, nil
	}
	end := min(offset+pageSize, len(matched))
	for _, r := range matched[offset:end] {
		page.Notifications = append(page.Notifications, s.view(r, time.Time{}))
	}
	if end < len(matched) {
		page.NextPageToken = strconv.Itoa(end)
	}
	return page, nil
}

func (s *Store) UnreadCount(_ context.Context, tenantID, recipientID string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int64
	for k, r := range s.rows {
		if r.TenantID == tenantID && r.RecipientID == recipientID {
			if _, unread := s.read[k]; !unread {
				n++
			}
		}
	}
	return n, nil
}

func (s *Store) MarkRead(_ context.Context, tenantID, recipientID, eventID string, readAt time.Time) (api.Notification, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.rows[key(tenantID, recipientID, eventID)]
	if !ok {
		return api.Notification{}, api.ErrDenied
	}
	if _, wasRead := s.read[key(tenantID, recipientID, eventID)]; !wasRead {
		s.read[key(tenantID, recipientID, eventID)] = readAt
	}
	return s.view(r, readAt), nil
}

// PutCreator records the projected author of one merge request.
func (s *Store) PutCreator(_ context.Context, tenantID, repositoryID, mergeRequestID, creatorID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.creators[creatorKey(tenantID, repositoryID, mergeRequestID)] = creatorID
	return nil
}

// Creator reports the projected author, empty when unknown.
func (s *Store) Creator(_ context.Context, tenantID, repositoryID, mergeRequestID string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.creators[creatorKey(tenantID, repositoryID, mergeRequestID)], nil
}

var (
	_ app.Store        = (*Store)(nil)
	_ app.CreatorStore = (*Store)(nil)
)

// Directory is the in-memory review-capable directory for dev planes and
// tests: principals by role, filtered to those whose roles grant
// merge_request.review.
type Directory struct {
	mu      sync.Mutex
	members map[string]map[string][]string // tenant -> actor -> roles
}

func NewDirectory() *Directory {
	return &Directory{members: map[string]map[string][]string{}}
}

// Put records one actor's roles for a tenant.
func (d *Directory) Put(tenantID, actorID string, roles ...string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	tenant, ok := d.members[tenantID]
	if !ok {
		tenant = map[string][]string{}
		d.members[tenantID] = tenant
	}
	tenant[actorID] = slices.Clone(roles)
}

// ReviewCapableActors names the actors holding a role that grants
// merge_request.review in governance/policies (owner, member).
func (d *Directory) ReviewCapableActors(_ context.Context, tenantID string) ([]string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []string
	for actorID, roles := range d.members[tenantID] {
		if slices.Contains(roles, "owner") || slices.Contains(roles, "member") {
			out = append(out, actorID)
		}
	}
	slices.Sort(out)
	return out, nil
}
