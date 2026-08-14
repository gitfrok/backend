// The gRPC adapter's claims are about the wire shape (SPEC-0035): verified context only, coarse
// refusals that distinguish no cause, and the empty SearchResponse being the one marshalling a
// no-match query and an unauthorized-only query both produce — byte-identical, because the
// adapter builds the zero message in both cases and the contract defines no field that could
// separate them (AC4).
package grpc

import (
	"bytes"
	"context"
	"errors"
	"testing"

	searchv1 "github.com/gitfrok/backend/gen/proto/search/v1"
	"github.com/gitfrok/backend/modules/codesearch/api"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// fakeService is the module port the adapter sits on; each test dials its answers.
type fakeService struct {
	search func(context.Context, api.Query) (api.Page, error)
	status func(context.Context, api.Query) ([]api.IndexStatusEntry, error)
	lastQ  api.Query
}

func (f *fakeService) Search(ctx context.Context, q api.Query) (api.Page, error) {
	f.lastQ = q
	return f.search(ctx, q)
}

func (f *fakeService) GetIndexStatus(ctx context.Context, q api.Query) ([]api.IndexStatusEntry, error) {
	return f.status(ctx, q)
}

func (f *fakeService) Lookup(context.Context, string, string) (api.IndexedRepository, error) {
	return api.IndexedRepository{}, nil
}

func (f *fakeService) AttachContentSource(api.ContentSource)          {}
func (f *fakeService) Backfill(context.Context) error                 { return nil }
func (f *fakeService) Drain(context.Context) error                    { return nil }
func (f *fakeService) TenantIndexSize(context.Context, string) (int64, error) { return 0, nil }

var _ api.Service = (*fakeService)(nil)

func validRequest(text string) *searchv1.SearchRequest {
	return &searchv1.SearchRequest{
		Context: &searchv1.SearchContext{
			TenantId: "t-1", ActorId: "user-9", ActorRoles: []string{"member"}, RequestId: "req-1",
		},
		Query: text,
		Mode:  searchv1.QueryMode_QUERY_MODE_SUBSTRING,
	}
}

// AC4: a no-match query and an unauthorized-only query marshal to the SAME bytes — the empty
// SearchResponse. The adapter cannot tell the two inputs apart once the port answers, and the
// wire cannot carry the difference.
func TestEmptyResponsesAreByteIdentical(t *testing.T) {
	srv := NewServer(&fakeService{
		search: func(context.Context, api.Query) (api.Page, error) { return api.Page{}, nil },
		status: func(context.Context, api.Query) ([]api.IndexStatusEntry, error) { return nil, nil },
	})
	ctx := context.Background()

	noMatch, err := srv.Search(ctx, validRequest("nothingmatches"))
	if err != nil {
		t.Fatalf("no-match search: %v", err)
	}
	unauthorizedOnly, err := srv.Search(ctx, validRequest("onlyunauthorized"))
	if err != nil {
		t.Fatalf("unauthorized-only search: %v", err)
	}
	a, err := proto.Marshal(noMatch)
	if err != nil {
		t.Fatalf("marshal no-match: %v", err)
	}
	b, err := proto.Marshal(unauthorizedOnly)
	if err != nil {
		t.Fatalf("marshal unauthorized-only: %v", err)
	}
	empty, err := proto.Marshal(&searchv1.SearchResponse{})
	if err != nil {
		t.Fatalf("marshal empty: %v", err)
	}
	if !bytes.Equal(a, b) || !bytes.Equal(a, empty) {
		t.Fatalf("no-match, unauthorized-only and the empty response must marshal identically: %x vs %x vs %x", a, b, empty)
	}
}

// Matches and the continuation token travel field for field.
func TestSearchMapsMatches(t *testing.T) {
	srv := NewServer(&fakeService{
		search: func(context.Context, api.Query) (api.Page, error) {
			return api.Page{
				Matches: []api.Match{{
					RepositoryID: "repo-a", Revision: "rev-1", Path: "a.go",
					LineStart: 3, LineEnd: 4, MatchedContent: "token",
				}},
				NextPageToken: "cursor-1",
			}, nil
		},
		status: func(context.Context, api.Query) ([]api.IndexStatusEntry, error) { return nil, nil },
	})
	resp, err := srv.Search(context.Background(), validRequest("token"))
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(resp.Results) != 1 || resp.NextPageToken != "cursor-1" {
		t.Fatalf("unexpected response: %+v", resp)
	}
	r := resp.Results[0]
	if r.RepositoryId != "repo-a" || r.Revision != "rev-1" || r.Path != "a.go" ||
		r.LineStart != 3 || r.LineEnd != 4 || r.MatchedContent != "token" {
		t.Fatalf("match fields must travel verbatim: %+v", r)
	}
}

// The coarse refusal: a port denial is PermissionDenied with one message, a malformed request is
// InvalidArgument, and neither distinguishes its cause (SPEC-0035 non-functional).
func TestSearchRefusalShapes(t *testing.T) {
	denying := NewServer(&fakeService{
		search: func(context.Context, api.Query) (api.Page, error) { return api.Page{}, api.ErrDenied },
		status: func(context.Context, api.Query) ([]api.IndexStatusEntry, error) { return nil, nil },
	})
	if _, err := denying.Search(context.Background(), validRequest("token")); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("port denial must map to PermissionDenied, got %v", err)
	}

	malformed := NewServer(&fakeService{
		search: func(context.Context, api.Query) (api.Page, error) { return api.Page{}, api.ErrMalformed },
		status: func(context.Context, api.Query) ([]api.IndexStatusEntry, error) { return nil, nil },
	})
	if _, err := malformed.Search(context.Background(), validRequest("token")); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("malformed must map to InvalidArgument, got %v", err)
	}

	// An unknown port error is still the coarse denial — never a transport of the cause.
	other := NewServer(&fakeService{
		search: func(context.Context, api.Query) (api.Page, error) { return api.Page{}, errors.New("boom") },
		status: func(context.Context, api.Query) ([]api.IndexStatusEntry, error) { return nil, nil },
	})
	if _, err := other.Search(context.Background(), validRequest("token")); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("unknown errors must map to the coarse denial, got %v", err)
	}
}

// Verified context only: no tenant or no actor is a coarse denial; no mode the contract names
// is a malformed refusal. The adapter accepts no caller-asserted scope (SPEC-0035 AC2).
func TestIntoQueryBoundaries(t *testing.T) {
	srv := NewServer(&fakeService{
		search: func(context.Context, api.Query) (api.Page, error) { return api.Page{}, nil },
		status: func(context.Context, api.Query) ([]api.IndexStatusEntry, error) { return nil, nil },
	})
	ctx := context.Background()

	if _, err := srv.Search(ctx, &searchv1.SearchRequest{
		Query: "token", Mode: searchv1.QueryMode_QUERY_MODE_SUBSTRING,
	}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("missing context must be the coarse denial, got %v", err)
	}

	if _, err := srv.Search(ctx, &searchv1.SearchRequest{
		Context: &searchv1.SearchContext{TenantId: "t-1", ActorId: "user-9", RequestId: "r"},
		Query:   "token",
	}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("unspecified mode must be malformed, got %v", err)
	}
}

// The verified context lands on the port untouched: tenant, actor, roles and request ID are
// carried over; the tenancy context rides along.
func TestQueryContextCarriedToPort(t *testing.T) {
	fake := &fakeService{
		search: func(context.Context, api.Query) (api.Page, error) { return api.Page{}, nil },
		status: func(context.Context, api.Query) ([]api.IndexStatusEntry, error) { return nil, nil },
	}
	srv := NewServer(fake)
	req := validRequest("token")
	req.Context.ActorRoles = []string{"owner", "member"}
	req.ResultLimit, req.ContextLineLimit, req.PageToken = 25, 3, "cursor-0"
	if _, err := srv.Search(context.Background(), req); err != nil {
		t.Fatalf("search: %v", err)
	}
	q := fake.lastQ
	if q.TenantID != "t-1" || q.ActorID != "user-9" || q.RequestID != "req-1" ||
		q.Text != "token" || q.Mode != api.QueryModeSubstring ||
		q.ResultLimit != 25 || q.ContextLineLimit != 3 || q.PageToken != "cursor-0" ||
		len(q.ActorRoles) != 2 {
		t.Fatalf("verified context must reach the port verbatim: %+v", q)
	}
}

// AC6 (status): entries map field for field; a port denial is the same coarse refusal.
func TestGetIndexStatusMapsEntries(t *testing.T) {
	srv := NewServer(&fakeService{
		search: func(context.Context, api.Query) (api.Page, error) { return api.Page{}, nil },
		status: func(context.Context, api.Query) ([]api.IndexStatusEntry, error) {
			return []api.IndexStatusEntry{{
				RepositoryID: "repo-a", LastIndexedRevision: "rev-9",
			}}, nil
		},
	})
	resp, err := srv.GetIndexStatus(context.Background(), &searchv1.GetIndexStatusRequest{
		Context: &searchv1.SearchContext{TenantId: "t-1", ActorId: "user-9", RequestId: "req-1"},
	})
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if len(resp.Entries) != 1 || resp.Entries[0].RepositoryId != "repo-a" ||
		resp.Entries[0].LastIndexedRevision != "rev-9" {
		t.Fatalf("unexpected entries: %+v", resp.Entries)
	}

	denying := NewServer(&fakeService{
		search: func(context.Context, api.Query) (api.Page, error) { return api.Page{}, nil },
		status: func(context.Context, api.Query) ([]api.IndexStatusEntry, error) {
			return nil, api.ErrDenied
		},
	})
	if _, err := denying.GetIndexStatus(context.Background(), &searchv1.GetIndexStatusRequest{
		Context: &searchv1.SearchContext{TenantId: "t-1", ActorId: "user-9", RequestId: "req-1"},
	}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("status denial must map to PermissionDenied, got %v", err)
	}
}
