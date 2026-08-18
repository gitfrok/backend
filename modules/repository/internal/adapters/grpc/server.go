// Package grpc adapts the Repository context's listing surface to its gRPC contract
// (T-0054, SPEC-0052).
//
// It carries verified identity and shapes only. A caller cannot assert a repository set, a scope
// or an authorization outcome, because ListRepositoriesRequest has no field for any of them — the
// listable set is derived server-side at request time (ADR-0071 decision 4).
package grpc

import (
	"context"

	repositoryv1 "github.com/gitfrok/backend/gen/proto/repository/v1"
	"github.com/gitfrok/backend/modules/repository/api"
	"github.com/gitfrok/backend/platform/tenancy"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Server is the gRPC adapter for the Lister port.
type Server struct {
	repositoryv1.UnimplementedRepositoryRegistryServer
	lister api.Lister
}

// NewServer builds the adapter over the module's port.
func NewServer(l api.Lister) *Server { return &Server{lister: l} }

// denial is the one coarse refusal this surface returns. A caller learns nothing about what
// exists or what is allowed — and note that a caller who may see NOTHING does not get this: an
// empty list is a successful answer, because "you may see none" and "there are none" have to be
// indistinguishable (SPEC-0052 AC4, SPEC-0001).
func denial() error {
	return status.Error(codes.PermissionDenied, "repository: unavailable")
}

// ListRepositories answers which repositories the caller may see.
func (s *Server) ListRepositories(ctx context.Context, req *repositoryv1.ListRepositoriesRequest) (*repositoryv1.ListRepositoriesResponse, error) {
	rc := req.GetContext()
	if rc == nil || rc.GetTenantId() == "" || rc.GetActorId() == "" {
		return nil, denial()
	}
	// The transaction is scoped from the verified context, not from anything the request could
	// name: there is no repository field to name one with.
	ctx = tenancy.WithTenant(ctx, tenancy.ID(rc.GetTenantId()))

	page, err := s.lister.List(ctx, api.ListQuery{
		TenantID:   rc.GetTenantId(),
		ActorID:    rc.GetActorId(),
		ActorRoles: rc.GetActorRoles(),
		PageToken:  req.GetPageToken(),
		PageSize:   req.GetPageSize(),
	})
	if err != nil {
		return nil, denial()
	}

	out := &repositoryv1.ListRepositoriesResponse{
		Repositories:  make([]*repositoryv1.RepositorySummary, 0, len(page.Repositories)),
		NextPageToken: page.NextPageToken,
	}
	for _, r := range page.Repositories {
		out.Repositories = append(out.Repositories, &repositoryv1.RepositorySummary{
			RepositoryId: r.RepoID,
			Name:         r.Name,
		})
	}
	return out, nil
}
