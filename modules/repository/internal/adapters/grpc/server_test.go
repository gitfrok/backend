package grpc_test

import (
	"context"
	"errors"
	"testing"

	repositoryv1 "github.com/gitfrok/backend/gen/proto/repository/v1"
	"github.com/gitfrok/backend/modules/repository/api"
	repogrpc "github.com/gitfrok/backend/modules/repository/internal/adapters/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// SPEC-0052 AC8/AC9: the adapter shapes and forwards, and its refusal
// distinguishes nothing.

type fakeLister struct {
	page api.ListPage
	err  error
	got  api.ListQuery
}

func (f *fakeLister) List(_ context.Context, q api.ListQuery) (api.ListPage, error) {
	f.got = q
	return f.page, f.err
}

func req(tenant, actor string) *repositoryv1.ListRepositoriesRequest {
	return &repositoryv1.ListRepositoriesRequest{
		Context: &repositoryv1.ListContext{
			TenantId: tenant, ActorId: actor, RequestId: "req-1", ActorRoles: []string{"member"},
		},
		PageSize: 10,
	}
}

func TestListForwardsTheVerifiedContextAndNothingElse(t *testing.T) {
	lister := &fakeLister{page: api.ListPage{
		Repositories: []api.RepositoryView{{TenantID: "t-1", RepoID: "alpha", Name: "Alpha"}},
	}}
	srv := repogrpc.NewServer(lister)

	got, err := srv.ListRepositories(context.Background(), req("t-1", "actor-1"))
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got.GetRepositories()) != 1 || got.GetRepositories()[0].GetRepositoryId() != "alpha" {
		t.Fatalf("shaped %v", got.GetRepositories())
	}
	if lister.got.TenantID != "t-1" || lister.got.ActorID != "actor-1" {
		t.Fatalf("forwarded %+v", lister.got)
	}
	//arch:allow-inline-authz asserts the roles were FORWARDED unchanged; it decides no access — the PDP does, above this adapter
	if len(lister.got.ActorRoles) != 1 || lister.got.ActorRoles[0] != "member" {
		t.Fatalf("roles %v", lister.got.ActorRoles)
	}
}

func TestARequestWithoutAVerifiedCallerIsRefused(t *testing.T) {
	srv := repogrpc.NewServer(&fakeLister{})
	for name, r := range map[string]*repositoryv1.ListRepositoriesRequest{
		"no context": {},
		"no tenant":  req("", "actor-1"),
		"no actor":   req("t-1", ""),
	} {
		if _, err := srv.ListRepositories(context.Background(), r); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("%s: want PermissionDenied, got %v", name, err)
		}
	}
}

// An empty list is a SUCCESS, not the refusal. A caller who may see nothing
// and a tenant with nothing must be indistinguishable, and a refusal here
// would tell the first one that something exists to be refused.
func TestACallerWhoMaySeeNothingGetsAnEmptySuccess(t *testing.T) {
	srv := repogrpc.NewServer(&fakeLister{page: api.ListPage{}})
	got, err := srv.ListRepositories(context.Background(), req("t-1", "actor-1"))
	if err != nil {
		t.Fatalf("an empty list must not be a refusal: %v", err)
	}
	if len(got.GetRepositories()) != 0 || got.GetNextPageToken() != "" {
		t.Fatalf("want the zero response, got %v", got)
	}
	// Marshalled, it is byte-identical to the response for a tenant with no
	// repositories at all — which is what makes the two indistinguishable.
	empty, err := proto.Marshal(&repositoryv1.ListRepositoriesResponse{})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	mine, err := proto.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(empty) != string(mine) {
		t.Fatal("an empty answer is distinguishable from the zero response")
	}
}

func TestAServiceErrorIsTheOneCoarseRefusal(t *testing.T) {
	srv := repogrpc.NewServer(&fakeLister{err: errors.New("store unavailable")})
	_, err := srv.ListRepositories(context.Background(), req("t-1", "actor-1"))
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("want the coarse refusal, got %v", err)
	}
	if msg := status.Convert(err).Message(); msg != "repository: unavailable" {
		t.Fatalf("the refusal names a cause: %q", msg)
	}
}

func TestThePageTokenTravelsVerbatim(t *testing.T) {
	lister := &fakeLister{}
	srv := repogrpc.NewServer(lister)
	r := req("t-1", "actor-1")
	r.PageToken = "opaque::cursor"
	if _, err := srv.ListRepositories(context.Background(), r); err != nil {
		t.Fatalf("list: %v", err)
	}
	if lister.got.PageToken != "opaque::cursor" {
		t.Fatalf("token %q", lister.got.PageToken)
	}
}

// The contract must carry no field a caller could use to widen its own scope.
func TestTheRequestCarriesNoScopeField(t *testing.T) {
	fields := (&repositoryv1.ListRepositoriesRequest{}).ProtoReflect().Descriptor().Fields()
	for i := 0; i < fields.Len(); i++ {
		switch name := string(fields.Get(i).Name()); name {
		case "context", "page_token", "page_size":
		default:
			t.Fatalf("ListRepositoriesRequest carries an unexpected field %q — a scope a caller could assert", name)
		}
	}
}

// And the response must carry no field capable of expressing what was withheld.
func TestTheResponseCarriesNoTotal(t *testing.T) {
	fields := (&repositoryv1.ListRepositoriesResponse{}).ProtoReflect().Descriptor().Fields()
	for i := 0; i < fields.Len(); i++ {
		switch name := string(fields.Get(i).Name()); name {
		case "repositories", "next_page_token":
		default:
			t.Fatalf("ListRepositoriesResponse carries %q — non-enumeration is a property of this type", name)
		}
	}
}
