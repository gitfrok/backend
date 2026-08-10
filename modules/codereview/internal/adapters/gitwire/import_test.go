package gitwire

import (
	"context"
	"testing"

	"google.golang.org/grpc"

	gitv1 "github.com/gitfrok/backend/gen/proto/git/v1"
	"github.com/gitfrok/backend/modules/codereview/internal/app"
)

// stubStorage is GitStorage as far as the import adapter is concerned.
type stubStorage struct {
	gitv1.GitStorageClient
	response *gitv1.ImportRefsResponse
	request  *gitv1.ImportRefsRequest
}

func (s *stubStorage) ImportRefs(_ context.Context, in *gitv1.ImportRefsRequest, _ ...grpc.CallOption) (*gitv1.ImportRefsResponse, error) {
	s.request = in
	return s.response, nil
}

// The adapter forwards storage's own byte count without adjusting it: the tier
// that wrote the objects is the only one that can measure them (SPEC-0011
// AC9/AC21).
func TestImportRefsForwardsStorageMeasuredBytes(t *testing.T) {
	storage := &stubStorage{response: &gitv1.ImportRefsResponse{
		Refs:          []*gitv1.RefUpdate{{Ref: "refs/heads/main", Revision: "abc123"}},
		ImportedBytes: 5 * 1024 * 1024,
	}}
	result, err := NewGitImporter(storage).ImportRefs(t.Context(), app.ImportRefsCommand{
		TenantID: "tenant-a", RepositoryID: "repo-a", ActorID: "actor-a", RequestID: "req-1",
		SourceURL: "https://github.com/acme/widgets.git", SourceToken: "secret-token",
	})
	if err != nil {
		t.Fatalf("ImportRefs: %v", err)
	}
	if result.ImportedBytes != 5*1024*1024 {
		t.Fatalf("imported bytes = %d, want what storage reported", result.ImportedBytes)
	}
	if len(result.Refs) != 1 || result.Refs[0].Ref != "refs/heads/main" {
		t.Fatalf("refs = %+v", result.Refs)
	}
}

// A response with no byte count charges nothing rather than a guess.
func TestImportRefsWithoutBytesChargesNothing(t *testing.T) {
	storage := &stubStorage{response: &gitv1.ImportRefsResponse{
		Refs: []*gitv1.RefUpdate{{Ref: "refs/heads/main", Revision: "abc123"}},
	}}
	result, err := NewGitImporter(storage).ImportRefs(t.Context(), app.ImportRefsCommand{
		TenantID: "tenant-a", RepositoryID: "repo-a", ActorID: "actor-a", RequestID: "req-1",
		SourceURL: "https://github.com/acme/widgets.git",
	})
	if err != nil {
		t.Fatalf("ImportRefs: %v", err)
	}
	if result.ImportedBytes != 0 {
		t.Fatalf("imported bytes = %d, want 0", result.ImportedBytes)
	}
}

// The source token travels in the request only; it is never copied into the
// verified context the decision is made on (SPEC-0011 AC22).
func TestImportRefsKeepsTheTokenOutOfTheContext(t *testing.T) {
	storage := &stubStorage{response: &gitv1.ImportRefsResponse{}}
	if _, err := NewGitImporter(storage).ImportRefs(t.Context(), app.ImportRefsCommand{
		TenantID: "tenant-a", RepositoryID: "repo-a", ActorID: "actor-a", RequestID: "req-1",
		ActorRoles: []string{"maintainer"},
		SourceURL:  "https://github.com/acme/widgets.git", SourceToken: "secret-token",
	}); err != nil {
		t.Fatalf("ImportRefs: %v", err)
	}
	op := storage.request.GetContext()
	if op.GetTenantId() != "tenant-a" || op.GetActorId() != "actor-a" {
		t.Fatalf("context = %+v", op)
	}
	for _, role := range op.GetActorRoles() {
		if role == "secret-token" {
			t.Fatal("the source token reached the decision context")
		}
	}
	if storage.request.GetSourceToken() != "secret-token" {
		t.Fatal("the source token did not reach storage, so no private source can be imported")
	}
}
