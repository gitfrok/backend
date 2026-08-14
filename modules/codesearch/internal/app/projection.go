// Package app orchestrates the Code Search context's use cases. It reaches the Repository context
// the only two ways a module may: subscribing to its events on the in-process bus, and calling its
// api/ package. It never imports modules/repository/internal (invariant 14).
package app

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	csapi "github.com/gitfrok/backend/modules/codesearch/api"
	"github.com/gitfrok/backend/modules/codesearch/internal/domain"
	repoapi "github.com/gitfrok/backend/modules/repository/api"
	"github.com/gitfrok/backend/platform/bus"
)

// Projection maintains the Code Search view of the repository fleet from Repository events:
// which repositories exist per tenant, what refs they advertise, and which revision was last
// admitted per repository. It is the query path's enumeration source: the searchable repository
// set is derived from this projection and the PDP at query time, never from a permission cache
// (SPEC-0034 AC2/AC6).
type Projection struct {
	mu    sync.RWMutex
	index *domain.Index
	repos repoapi.Reader
	// admitted records, per repository, the newest revision a ref-update admitted and when.
	// Freshness is measured against it (SPEC-0034 AC4).
	admitted map[domain.TenantID]map[domain.RepoID]admittedHead
}

type admittedHead struct {
	sha string
	at  time.Time
}

// NewProjection builds the projection over the Repository context's read port. Taking the port
// (not a concrete service) is what lets that context become a gRPC client later without this
// module changing (ADR-0026).
func NewProjection(repos repoapi.Reader) *Projection {
	return &Projection{
		index:    domain.NewIndex(),
		repos:    repos,
		admitted: make(map[domain.TenantID]map[domain.RepoID]admittedHead),
	}
}

// Register subscribes the projection to the Repository events it reacts to. Wiring happens in
// cmd/, which is the only place that knows both modules exist.
func (p *Projection) Register(b bus.Bus) {
	bus.SubscribeTyped(b, p.HandleRepositoryCreated)
	bus.SubscribeTyped(b, p.HandleRefUpdated)
}

// HandleRepositoryCreated indexes a new repository. RepositoryCreated deliberately does not carry the
// repository's name — the event states what happened, not the whole aggregate — so the projection
// asks the Repository context for it through its api/.
func (p *Projection) HandleRepositoryCreated(ctx context.Context, e repoapi.RepositoryCreated) error {
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

// HandleRefUpdated records a ref move against an already-indexed repository, and the admitted
// head regardless: freshness is measured from admission even for a repository whose entry has
// not landed yet. An event for something unknown to the entry table is dropped rather than
// failed: the producer is not responsible for this consumer's ordering, and failing here would
// fail their write.
func (p *Projection) HandleRefUpdated(_ context.Context, e repoapi.RefUpdated) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if e.NewSha != "" {
		at := e.OccurredAt
		if at.IsZero() {
			at = time.Now().UTC()
		}
		byRepo, ok := p.admitted[domain.TenantID(e.TenantID)]
		if !ok {
			byRepo = make(map[domain.RepoID]admittedHead)
			p.admitted[domain.TenantID(e.TenantID)] = byRepo
		}
		byRepo[domain.RepoID(e.RepoID)] = admittedHead{sha: e.NewSha, at: at}
	}
	err := p.index.SetRef(domain.TenantID(e.TenantID), domain.RepoID(e.RepoID), e.Ref, e.NewSha)
	if errors.Is(err, domain.ErrNotIndexed) {
		return nil
	}
	return err
}

// ReposOfTenant enumerates the repositories this projection knows for one tenant, sorted for
// deterministic query ordering. The query path asks the PDP about each one at query time; this
// list carries no permission outcome (SPEC-0035 AC2).
func (p *Projection) ReposOfTenant(tenantID string) []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	byRepo := p.index.EntriesOfTenant(domain.TenantID(tenantID))
	out := make([]string, 0, len(byRepo))
	for id := range byRepo {
		out = append(out, string(id))
	}
	slices.Sort(out)
	return out
}

// AdmittedHead returns the newest revision admitted for one repository and when it was admitted.
func (p *Projection) AdmittedHead(tenantID, repoID string) (sha string, at time.Time, ok bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	head, found := p.admitted[domain.TenantID(tenantID)][domain.RepoID(repoID)]
	if !found {
		return "", time.Time{}, false
	}
	return head.sha, head.at, true
}

// AdmittedRepo is one repository with an admitted head, for backfill enumeration.
type AdmittedRepo struct {
	TenantID string
	RepoID   string
	Revision string
}

// AllAdmitted enumerates every repository with an admitted revision, sorted for deterministic
// backfill order.
func (p *Projection) AllAdmitted() []AdmittedRepo {
	p.mu.RLock()
	defer p.mu.RUnlock()
	var out []AdmittedRepo
	for tenant, byRepo := range p.admitted {
		for repo, head := range byRepo {
			out = append(out, AdmittedRepo{TenantID: string(tenant), RepoID: string(repo), Revision: head.sha})
		}
	}
	slices.SortFunc(out, func(a, b AdmittedRepo) int {
		if c := cmp.Compare(a.TenantID, b.TenantID); c != 0 {
			return c
		}
		return cmp.Compare(a.RepoID, b.RepoID)
	})
	return out
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
