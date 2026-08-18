// Package memstore is an in-memory Store adapter for the Repository context. It exists so the
// plane binary and the tests can be wired end-to-end before the Postgres adapter lands with the
// tenancy baseline (T-0004) and the Git-RPC service (T-0010).
//
// It is an adapter, so it may know the domain; the domain never knows it (invariant 16).
package memstore

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/gitfrok/backend/modules/repository/internal/domain"
)

// key scopes every entry by tenant, so a lookup cannot cross tenants even by accident — the same
// shape RLS enforces in Postgres (invariant 1, ADR-0003).
type key struct {
	tenant domain.TenantID
	id     domain.RepoID
}

// Store keeps repositories in memory.
type Store struct {
	mu    sync.RWMutex
	repos map[key]domain.Repository
}

// New builds an empty store.
func New() *Store { return &Store{repos: make(map[key]domain.Repository)} }

// Save writes the repository under its tenant-scoped key.
func (s *Store) Save(_ context.Context, r domain.Repository) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.repos[key{r.Tenant, r.ID}] = r
	return nil
}

// Load reads a repository within one tenant. A repository belonging to another tenant is reported
// as absent, not as forbidden: the caller must not learn that it exists.
func (s *Store) Load(_ context.Context, tenant domain.TenantID, id domain.RepoID) (domain.Repository, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.repos[key{tenant, id}]
	if !ok {
		return domain.Repository{}, fmt.Errorf("memstore: repository %s not found", id)
	}
	return r, nil
}

// Candidates returns up to limit of one tenant's repositories whose ID sorts after afterID, in
// ascending ID order. Another tenant's repositories are not candidates — they are not filtered
// out, they are never gathered, which is the same shape RLS gives the Postgres adapter.
//
// It answers nothing about authorization: which candidates the caller may see is asked above this
// port, so an adapter cannot become a decision point by accident (invariant 2).
func (s *Store) Candidates(_ context.Context, tenant domain.TenantID, afterID domain.RepoID, limit int) ([]domain.Repository, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var out []domain.Repository
	for k, r := range s.repos {
		if k.tenant != tenant || k.id <= afterID {
			continue
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
