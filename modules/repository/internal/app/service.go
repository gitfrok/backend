// Package app orchestrates the Repository context's use cases. It depends on domain and on
// ports; it wires adapters at the edges. It may be reached only through the module's api/.
package app

import (
	"context"
	"errors"

	"github.com/gitfrok/backend/modules/repository/api"
	"github.com/gitfrok/backend/modules/repository/internal/domain"
)

// Store is the persistence port implemented by adapters (never referenced by domain).
type Store interface {
	Load(ctx context.Context, tenant domain.TenantID, id domain.RepoID) (domain.Repository, error)
}

// Service implements api.Reader over a Store.
type Service struct{ store Store }

// New builds the Repository application service.
func New(s Store) *Service { return &Service{store: s} }

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
	return api.RepositoryView{TenantID: string(repo.Tenant), RepoID: string(repo.ID), Name: repo.Name}, nil
}

var _ api.Reader = (*Service)(nil)
