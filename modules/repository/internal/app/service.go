// Package app orchestrates the Repository context's use cases. It depends on domain and on ports;
// adapters are injected at the edges by cmd/ (ADR-0025). It may be reached only through the
// module's api/.
package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/gitfrok/backend/modules/repository/api"
	"github.com/gitfrok/backend/modules/repository/internal/domain"
	"github.com/gitfrok/backend/platform/bus"
	"github.com/gitfrok/backend/platform/ids"
)

// Store is the persistence port implemented by adapters. It speaks domain types: dependencies
// point inward, so an adapter knows the domain and never the reverse (invariant 16).
type Store interface {
	Save(ctx context.Context, r domain.Repository) error
	Load(ctx context.Context, tenant domain.TenantID, id domain.RepoID) (domain.Repository, error)
}

// Service implements api.Reader over a Store and publishes the context's domain events.
type Service struct {
	store Store
	bus   bus.Bus
	newID func() string
	now   func() time.Time
}

// Option adjusts a Service at construction. Only cmd/ and tests pass these.
type Option func(*Service)

// WithClock replaces the time source so a test can assert on occurred_at.
func WithClock(now func() time.Time) Option { return func(s *Service) { s.now = now } }

// WithIDs replaces the event-id source so a test can assert on event_id.
func WithIDs(newID func() string) Option { return func(s *Service) { s.newID = newID } }

// New builds the Repository application service over the ports it was given.
func New(s Store, b bus.Bus, opts ...Option) *Service {
	svc := &Service{store: s, bus: b, newID: ids.NewULID, now: time.Now}
	for _, o := range opts {
		o(svc)
	}
	return svc
}

// Create stores a new repository and announces it. The event is published only once the write
// succeeded: it asserts a fact, so it must not precede the fact.
func (s *Service) Create(ctx context.Context, tenantID, repoID, name, actorID string) (api.RepositoryView, error) {
	repo, err := domain.NewRepository(domain.TenantID(tenantID), domain.RepoID(repoID), name)
	if err != nil {
		return api.RepositoryView{}, err
	}
	if err := s.store.Save(ctx, repo); err != nil {
		return api.RepositoryView{}, fmt.Errorf("app: saving repository: %w", err)
	}

	evt := api.RepositoryCreated{
		EventID:    s.newID(),
		TenantID:   string(repo.Tenant),
		RepoID:     string(repo.ID),
		CreatedBy:  actorID,
		OccurredAt: s.now().UTC(),
	}
	// Publishing in-line keeps the reaction inside this request while the bus is in-process. When
	// this event moves onto Redpanda (ADR-0026) the publish becomes an outbox write in the same
	// transaction as the Save; what the caller observes — the write happened, consumers were
	// told — does not change, which is the point of the seam.
	if err := s.bus.Publish(ctx, evt); err != nil {
		return api.RepositoryView{}, fmt.Errorf("app: announcing repository %s: %w", repo.ID, err)
	}
	return viewOf(repo), nil
}

// Get loads a repository, enforcing tenant scope before shaping the view.
func (s *Service) Get(ctx context.Context, tenantID, repoID string) (api.RepositoryView, error) {
	if tenantID == "" {
		return api.RepositoryView{}, errors.New("app: tenant required")
	}
	t := domain.TenantID(tenantID)
	repo, err := s.store.Load(ctx, t, domain.RepoID(repoID))
	if err != nil {
		return api.RepositoryView{}, err
	}
	if !repo.BelongsTo(t) {
		return api.RepositoryView{}, domain.ErrCrossTenant
	}
	return viewOf(repo), nil
}

// viewOf shapes the aggregate into the module's public read model.
func viewOf(r domain.Repository) api.RepositoryView {
	return api.RepositoryView{TenantID: string(r.Tenant), RepoID: string(r.ID), Name: r.Name}
}

var _ api.Reader = (*Service)(nil)
