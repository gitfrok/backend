// Package app orchestrates the Code Search context's use cases. It reaches the Repository context
// the only two ways a module may: subscribing to its events on the in-process bus, and calling its
// api/ package. It never imports modules/repository/internal (invariant 14).
package app

import (
	"context"
	"errors"
	"fmt"
	"sync"

	csapi "github.com/gitfrok/backend/modules/codesearch/api"
	"github.com/gitfrok/backend/modules/codesearch/internal/domain"
	repoapi "github.com/gitfrok/backend/modules/repository/api"
	"github.com/gitfrok/backend/platform/bus"
)

// Projection maintains the Code Search index from Repository events.
type Projection struct {
	mu    sync.RWMutex
	index *domain.Index
	repos repoapi.Reader
}

// NewProjection builds the projection over the Repository context's read port. Taking the port
// (not a concrete service) is what lets that context become a gRPC client later without this
// module changing (ADR-0026).
func NewProjection(repos repoapi.Reader) *Projection {
	return &Projection{index: domain.NewIndex(), repos: repos}
}

// Register subscribes the projection to the Repository events it reacts to. Wiring happens in
// cmd/, which is the only place that knows both modules exist.
func (p *Projection) Register(b bus.Bus) {
	bus.SubscribeTyped(b, p.onRepositoryCreated)
	bus.SubscribeTyped(b, p.onRefUpdated)
}

// onRepositoryCreated indexes a new repository. RepositoryCreated deliberately does not carry the
// repository's name — the event states what happened, not the whole aggregate — so the projection
// asks the Repository context for it through its api/.
func (p *Projection) onRepositoryCreated(ctx context.Context, e repoapi.RepositoryCreated) error {
	view, err := p.repos.Get(ctx, e.TenantID, e.RepoID)
	if err != nil {
		return fmt.Errorf("codesearch: resolving repository %s: %w", e.RepoID, err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.index.Put(domain.Entry{
		Tenant: domain.TenantID(view.TenantID),
		ID:     domain.RepoID(view.RepoID),
		Name:   view.Name,
	})
	return nil
}

// onRefUpdated records a ref move against an already-indexed repository. An event for something
// unknown is dropped rather than failed: the producer is not responsible for this consumer's
// ordering, and failing here would fail their write.
func (p *Projection) onRefUpdated(_ context.Context, e repoapi.RefUpdated) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	err := p.index.SetRef(domain.TenantID(e.TenantID), domain.RepoID(e.RepoID), e.Ref, e.NewSha)
	if errors.Is(err, domain.ErrNotIndexed) {
		return nil
	}
	return err
}

// Lookup returns a tenant-scoped index entry.
func (p *Projection) Lookup(_ context.Context, tenantID, repoID string) (csapi.IndexedRepository, error) {
	if tenantID == "" {
		return csapi.IndexedRepository{}, errors.New("codesearch: tenant required")
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	e, err := p.index.Get(domain.TenantID(tenantID), domain.RepoID(repoID))
	if err != nil {
		return csapi.IndexedRepository{}, err
	}
	refs := make(map[string]string, len(e.Refs))
	for k, v := range e.Refs {
		refs[k] = v
	}
	return csapi.IndexedRepository{
		TenantID: string(e.Tenant), RepoID: string(e.ID), Name: e.Name, Refs: refs,
	}, nil
}

var _ csapi.Index = (*Projection)(nil)
