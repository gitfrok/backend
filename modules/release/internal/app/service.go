// Package app orchestrates the Release context's use cases (SPEC-0056, ADR-0075).
//
// What this package deliberately does NOT do is resolve a tag. The Release context never asks git
// what a tag means — not on publish (the commit arrives already resolved) and not on read (the
// recorded commit is returned as recorded). Asking would make this context depend on
// Repository/Git, which ADR-0022 forbids, and comparing then-and-now is the reading surface's job.
package app

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	policyapi "github.com/gitfrok/backend/modules/policy/api"
	"github.com/gitfrok/backend/modules/release/api"
)

// Store is the persistence port implemented by adapters.
type Store interface {
	Insert(ctx context.Context, r api.Release) error
	Get(ctx context.Context, tenantID, repositoryID, tag string) (api.Release, error)
	UpdateNotes(ctx context.Context, tenantID, repositoryID, tag, notes string, at time.Time) (api.Release, error)
	Page(ctx context.Context, tenantID, repositoryID string, after Cursor, limit int) ([]api.Release, error)
}

// Cursor is a position in the (published_at DESC, tag DESC) ordering.
type Cursor struct {
	PublishedAt time.Time
	Tag         string
}

// Service implements api.Releases.
type Service struct {
	store Store
	pdp   policyapi.DecisionPoint
	now   func() time.Time
}

// Option adjusts a Service at construction.
type Option func(*Service)

// WithClock replaces the time source so a test can assert on published_at.
func WithClock(now func() time.Time) Option { return func(s *Service) { s.now = now } }

// New builds the service. A nil pdp is accepted at construction and refused at every call: a
// misconfigured plane fails loudly rather than serving an empty list that reads as "no releases".
func New(store Store, pdp policyapi.DecisionPoint, opts ...Option) *Service {
	s := &Service{store: store, pdp: pdp, now: time.Now}
	for _, o := range opts {
		o(s)
	}
	return s
}

const (
	defaultPageSize = 50
	maxPageSize     = 200
)

// Publish records a release.
//
// The commit is whatever the composition root resolved the tag to a moment ago. It is recorded, not
// re-checked: this is the one instant at which the platform observed what the tag meant, and every
// later reading is a comparison against it.
func (s *Service) Publish(ctx context.Context, req api.PublishRequest) (api.Release, error) {
	if err := s.mayWrite(ctx, req.Context); err != nil {
		return api.Release{}, err
	}
	if !validTag(req.Tag) || req.PublishedCommit == "" || len(req.Notes) > api.MaxNotesBytes {
		return api.Release{}, api.ErrInvalid
	}
	record := api.Release{
		TenantID: req.Context.TenantID, RepositoryID: req.Context.RepositoryID,
		Tag: req.Tag, PublishedCommit: req.PublishedCommit, Notes: req.Notes,
		PublishedBy: req.Context.ActorID, PublishedAt: s.now().UTC(),
	}
	if err := s.store.Insert(ctx, record); err != nil {
		return api.Release{}, err
	}
	return record, nil
}

// Get returns one release exactly as recorded.
func (s *Service) Get(ctx context.Context, rc api.Context, tag string) (api.Release, error) {
	if err := s.mayRead(ctx, rc); err != nil {
		return api.Release{}, err
	}
	if !validTag(tag) {
		return api.Release{}, api.ErrInvalid
	}
	return s.store.Get(ctx, rc.TenantID, rc.RepositoryID, tag)
}

// UpdateNotes corrects the prose. The tag and the commit are not updatable: correcting a typo is
// editing documentation, changing what a release points at is publishing a different release.
func (s *Service) UpdateNotes(ctx context.Context, rc api.Context, tag, notes string) (api.Release, error) {
	if err := s.mayWrite(ctx, rc); err != nil {
		return api.Release{}, err
	}
	if !validTag(tag) || len(notes) > api.MaxNotesBytes {
		return api.Release{}, api.ErrInvalid
	}
	return s.store.UpdateNotes(ctx, rc.TenantID, rc.RepositoryID, tag, notes, s.now().UTC())
}

// List pages a repository's releases, newest first.
func (s *Service) List(ctx context.Context, q api.ListQuery) (api.ListPage, error) {
	if err := s.mayRead(ctx, q.Context); err != nil {
		return api.ListPage{}, err
	}
	limit := int(q.PageSize)
	if limit <= 0 {
		limit = defaultPageSize
	}
	if limit > maxPageSize {
		limit = maxPageSize
	}
	after, err := decodeCursor(q.PageToken, q.Context.TenantID)
	if err != nil {
		return api.ListPage{}, err
	}
	// One more than the page, so "is there another" is answered by the walk.
	found, err := s.store.Page(ctx, q.Context.TenantID, q.Context.RepositoryID, after, limit+1)
	if err != nil {
		return api.ListPage{}, err
	}
	page := api.ListPage{}
	if len(found) > limit {
		last := found[limit-1]
		page.Releases = found[:limit]
		page.NextPageToken = encodeCursor(q.Context.TenantID, Cursor{PublishedAt: last.PublishedAt, Tag: last.Tag})
	} else {
		page.Releases = found
	}
	return page, nil
}

// mayRead and mayWrite ask the PDP about the REPOSITORY. A release adds no permission of its own:
// seeing that a release exists is reading something about the repository, and publishing one is
// writing to it.
func (s *Service) mayRead(ctx context.Context, rc api.Context) error {
	return s.decide(ctx, rc, "repo.read")
}

func (s *Service) mayWrite(ctx context.Context, rc api.Context) error {
	return s.decide(ctx, rc, "repo.write")
}

func (s *Service) decide(ctx context.Context, rc api.Context, action string) error {
	if rc.TenantID == "" || rc.RepositoryID == "" || rc.ActorID == "" {
		return api.ErrInvalid
	}
	if s.pdp == nil {
		return errors.New("release: no decision point wired")
	}
	d, err := s.pdp.Decide(ctx, policyapi.Request{
		TenantID: rc.TenantID,
		Subject:  policyapi.Subject{ID: rc.ActorID, TenantID: rc.TenantID, Roles: rc.ActorRoles},
		Action:   action,
		Resource: policyapi.Resource{Type: "repository", ID: rc.RepositoryID},
	})
	// Deny-by-default: an error and a not-allowed decision are the same refusal, and the refusal is
	// ErrNotFound rather than a permission error — a caller must not learn a release exists.
	if err != nil || !d.Allowed {
		return api.ErrNotFound
	}
	return nil
}

// validTag refuses what the contract does not name. A tag reaches no command line from this
// context, but it does reach a primary key, and an empty or oversized one is not a tag.
func validTag(tag string) bool {
	return tag != "" && len(tag) <= api.MaxTagLength && !strings.ContainsAny(tag, "\x00\n\r")
}

// The cursor is a position in the store's ordering, bound to the tenant that minted it.
const cursorVersion = "v1"

func encodeCursor(tenantID string, c Cursor) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strings.Join([]string{
		cursorVersion, tenantID, c.PublishedAt.UTC().Format(time.RFC3339Nano), c.Tag,
	}, "\x00")))
}

func decodeCursor(token, tenantID string) (Cursor, error) {
	if token == "" {
		return Cursor{}, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return Cursor{}, api.ErrInvalid
	}
	parts := strings.Split(string(raw), "\x00")
	if len(parts) != 4 || parts[0] != cursorVersion {
		return Cursor{}, api.ErrInvalid
	}
	if parts[1] != tenantID {
		return Cursor{}, fmt.Errorf("%w: page token does not belong to this tenant", api.ErrInvalid)
	}
	at, err := time.Parse(time.RFC3339Nano, parts[2])
	if err != nil {
		return Cursor{}, api.ErrInvalid
	}
	return Cursor{PublishedAt: at, Tag: parts[3]}, nil
}

var _ api.Releases = (*Service)(nil)
