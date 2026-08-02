package app_test

import (
	"context"
	"errors"
	"testing"
	"time"

	csapi "github.com/gitfrok/backend/modules/codesearch/api"
	"github.com/gitfrok/backend/modules/codesearch/internal/app"
	repoapi "github.com/gitfrok/backend/modules/repository/api"
	"github.com/gitfrok/backend/platform/bus"
)

// These tests are the T-0008 AC2 case: a second module reacts to the Repository context using only
// that context's api/ package and the bus. Nothing here imports modules/repository/internal — that
// is enforced by the arch gates, and readable in this file's imports.

// stubReader stands in for the Repository context's read port.
type stubReader struct {
	views map[string]repoapi.RepositoryView
	calls int
	err   error
}

func (r *stubReader) Get(_ context.Context, tenantID, repoID string) (repoapi.RepositoryView, error) {
	r.calls++
	if r.err != nil {
		return repoapi.RepositoryView{}, r.err
	}
	v, ok := r.views[tenantID+"/"+repoID]
	if !ok {
		return repoapi.RepositoryView{}, errors.New("not found")
	}
	return v, nil
}

func newReader(views ...repoapi.RepositoryView) *stubReader {
	m := make(map[string]repoapi.RepositoryView, len(views))
	for _, v := range views {
		m[v.TenantID+"/"+v.RepoID] = v
	}
	return &stubReader{views: m}
}

func created(tenant, repo string) repoapi.RepositoryCreated {
	return repoapi.RepositoryCreated{
		EventID: "01ARYZ6S41000000000000000A", TenantID: tenant, RepoID: repo,
		CreatedBy: "user-9", OccurredAt: time.Now().UTC(),
	}
}

// TestIndexesARepositoryOnCreation: the projection reacts to the event and fills in what the event
// does not carry by asking the producer's api/ — the two legitimate cross-module routes, together.
func TestIndexesARepositoryOnCreation(t *testing.T) {
	b := bus.NewInProcess()
	reader := newReader(repoapi.RepositoryView{TenantID: "t-1", RepoID: "repo-1", Name: "infra"})
	proj := app.NewProjection(reader)
	proj.Register(b)

	if err := b.Publish(context.Background(), created("t-1", "repo-1")); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	got, err := proj.Lookup(context.Background(), "t-1", "repo-1")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got.Name != "infra" {
		t.Errorf("want the name resolved through repository/api, got %+v", got)
	}
	if reader.calls != 1 {
		t.Errorf("want exactly one api call, got %d", reader.calls)
	}
}

// TestTracksRefUpdates: the second event type lands on the same projection.
func TestTracksRefUpdates(t *testing.T) {
	b := bus.NewInProcess()
	proj := app.NewProjection(newReader(repoapi.RepositoryView{TenantID: "t-1", RepoID: "repo-1", Name: "infra"}))
	proj.Register(b)

	ctx := context.Background()
	if err := b.Publish(ctx, created("t-1", "repo-1")); err != nil {
		t.Fatalf("Publish created: %v", err)
	}
	err := b.Publish(ctx, repoapi.RefUpdated{
		EventID: "01ARYZ6S41000000000000000B", TenantID: "t-1", RepoID: "repo-1",
		Ref: "refs/heads/main", OldSha: "", NewSha: "abc123", ActorID: "user-9",
		OccurredAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("Publish ref: %v", err)
	}

	got, err := proj.Lookup(ctx, "t-1", "repo-1")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got.Refs["refs/heads/main"] != "abc123" {
		t.Errorf("want the ref recorded, got %+v", got.Refs)
	}
}

// TestLookupIsTenantScoped: a projection is a copy of another context's data and carries the same
// tenancy obligation (invariant 1). It is also what PR-19 will filter on, so it cannot be an
// afterthought.
func TestLookupIsTenantScoped(t *testing.T) {
	b := bus.NewInProcess()
	proj := app.NewProjection(newReader(repoapi.RepositoryView{TenantID: "t-1", RepoID: "repo-1", Name: "infra"}))
	proj.Register(b)

	if err := b.Publish(context.Background(), created("t-1", "repo-1")); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	if _, err := proj.Lookup(context.Background(), "t-2", "repo-1"); err == nil {
		t.Error("want another tenant's repository to be invisible")
	}
}

// TestRefUpdateForAnUnknownRepositoryIsIgnored: events can arrive in any order once this moves to
// Redpanda, so an update for something not yet indexed must not create a half-populated entry.
func TestRefUpdateForAnUnknownRepositoryIsIgnored(t *testing.T) {
	b := bus.NewInProcess()
	proj := app.NewProjection(newReader())
	proj.Register(b)

	err := b.Publish(context.Background(), repoapi.RefUpdated{
		EventID: "01ARYZ6S41000000000000000C", TenantID: "t-1", RepoID: "ghost",
		Ref: "refs/heads/main", NewSha: "abc123", OccurredAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("an out-of-order event must not fail the publisher: %v", err)
	}
	if _, err := proj.Lookup(context.Background(), "t-1", "ghost"); err == nil {
		t.Error("want no entry created for an unknown repository")
	}
}

// TestIndexingFailureSurfaces: if the producer's api/ cannot answer, the consumer reports it
// rather than indexing a blank entry.
func TestIndexingFailureSurfaces(t *testing.T) {
	b := bus.NewInProcess()
	reader := newReader()
	reader.err = errors.New("repository unavailable")
	app.NewProjection(reader).Register(b)

	if err := b.Publish(context.Background(), created("t-1", "repo-1")); err == nil {
		t.Error("want the api failure surfaced to the publisher")
	}
}

// The projection satisfies the module's own public surface (invariant 14).
var _ csapi.Index = (*app.Projection)(nil)
