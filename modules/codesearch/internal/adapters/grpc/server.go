// Package grpc adapts the Code Search in-process surface to its gRPC contract (SPEC-0035). It
// carries only verified identity context; a caller cannot assert a repository scope, a
// permission claim, or an authorization outcome — the scope is a server fact derived at query
// time, and the response shape has no field capable of expressing an unauthorized total
// (SPEC-0035 AC2/AC3).
package grpc

import (
	"context"
	"errors"

	searchv1 "github.com/gitfrok/backend/gen/proto/search/v1"
	"github.com/gitfrok/backend/modules/codesearch/api"
	"github.com/gitfrok/backend/platform/tenancy"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Server is the gRPC adapter for the Service port.
type Server struct {
	searchv1.UnimplementedSearchServiceServer
	svc api.Service
}

// NewServer builds the adapter over the module's port.
func NewServer(svc api.Service) *Server { return &Server{svc: svc} }

// denial is the coarse refusal (SPEC-0035 non-functional): nonexistent, cross-tenant and
// unauthorized are indistinguishable, and a query whose only matches are unauthorized is
// indistinguishable from a query with none — that case returns an empty response, never this.
func denial() error {
	return status.Error(codes.PermissionDenied, "search: unavailable")
}

var errMalformed = status.Error(codes.InvalidArgument, "search: malformed request")

// Search runs one tenant-scoped query. The empty SearchResponse is returned for both a genuine
// no-match and an unauthorized-only match: marshalled, the two are byte-identical (SPEC-0035
// AC4), because the adapter builds the zero message in both cases and the contract defines no
// field that could distinguish them.
func (s *Server) Search(ctx context.Context, req *searchv1.SearchRequest) (*searchv1.SearchResponse, error) {
	ctx, q, err := intoQuery(ctx, req.GetContext(), req.GetQuery(), req.GetMode(), req.GetResultLimit(), req.GetContextLineLimit(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	page, err := s.svc.Search(ctx, q)
	if err != nil {
		if errors.Is(err, api.ErrMalformed) {
			return nil, errMalformed
		}
		return nil, denial()
	}
	resp := &searchv1.SearchResponse{}
	for _, m := range page.Matches {
		resp.Results = append(resp.Results, &searchv1.SearchResult{
			RepositoryId:   m.RepositoryID,
			Revision:       m.Revision,
			Path:           m.Path,
			LineStart:      m.LineStart,
			LineEnd:        m.LineEnd,
			MatchedContent: m.MatchedContent,
		})
	}
	resp.NextPageToken = page.NextPageToken
	return resp, nil
}

// GetIndexStatus reports freshness for readable repositories only; a repository the caller may
// not read appears in no entry (SPEC-0035 AC6).
func (s *Server) GetIndexStatus(ctx context.Context, req *searchv1.GetIndexStatusRequest) (*searchv1.GetIndexStatusResponse, error) {
	ctx, q, err := intoQuery(ctx, req.GetContext(), "", searchv1.QueryMode_QUERY_MODE_SUBSTRING, 0, 0, "")
	if err != nil {
		return nil, err
	}
	entries, err := s.svc.GetIndexStatus(ctx, q)
	if err != nil {
		if errors.Is(err, api.ErrMalformed) {
			return nil, errMalformed
		}
		return nil, denial()
	}
	resp := &searchv1.GetIndexStatusResponse{}
	for _, e := range entries {
		resp.Entries = append(resp.Entries, &searchv1.IndexStatusEntry{
			RepositoryId:        e.RepositoryID,
			LastIndexedRevision: e.LastIndexedRevision,
			IndexedAt:           timestamppb.New(e.IndexedAt),
			FreshnessLag:        durationpb.New(e.FreshnessLag),
		})
	}
	return resp, nil
}

// intoQuery maps the verified wire context onto the in-process query. An empty tenant or actor
// is a coarse denial that does not distinguish nonexistent from unauthorized (SPEC-0001); the
// mode must be one the contract names.
func intoQuery(ctx context.Context, c *searchv1.SearchContext, text string, mode searchv1.QueryMode, resultLimit, contextLineLimit int32, pageToken string) (context.Context, api.Query, error) {
	if c == nil || c.GetTenantId() == "" || c.GetActorId() == "" {
		return ctx, api.Query{}, denial()
	}
	ctx = tenancy.WithTenant(ctx, tenancy.ID(c.GetTenantId()))
	q := api.Query{
		TenantID:         c.GetTenantId(),
		ActorID:          c.GetActorId(),
		ActorRoles:       append([]string(nil), c.GetActorRoles()...),
		RequestID:        c.GetRequestId(),
		Text:             text,
		ResultLimit:      resultLimit,
		ContextLineLimit: contextLineLimit,
		PageToken:        pageToken,
	}
	switch mode {
	case searchv1.QueryMode_QUERY_MODE_SUBSTRING:
		q.Mode = api.QueryModeSubstring
	case searchv1.QueryMode_QUERY_MODE_REGEX:
		q.Mode = api.QueryModeRegex
	case searchv1.QueryMode_QUERY_MODE_SYMBOL:
		q.Mode = api.QueryModeSymbol
	default:
		return ctx, api.Query{}, errMalformed
	}
	return ctx, q, nil
}
