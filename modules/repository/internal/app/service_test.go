package app_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/gitfrok/backend/modules/repository/api"
	"github.com/gitfrok/backend/modules/repository/internal/adapters/memstore"
	"github.com/gitfrok/backend/modules/repository/internal/app"
	"github.com/gitfrok/backend/modules/repository/internal/domain"
	"github.com/gitfrok/backend/platform/bus"
)

// recorder captures what the app layer published, so these tests assert on the seam other modules
// actually see rather than on internal state.
type recorder struct{ events []bus.Event }

func (r *recorder) Publish(_ context.Context, e bus.Event) error {
	r.events = append(r.events, e)
	return nil
}
func (r *recorder) Subscribe(string, bus.Handler) {}

func newService(t *testing.T, b bus.Bus) *app.Service {
	t.Helper()
	return app.New(memstore.New(), b, app.WithClock(func() time.Time {
		return time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	}))
}

// TestCreatePublishesRepositoryCreated is the AC1 producer half: an app layer publishes a typed
// event through the port it was injected with.
func TestCreatePublishesRepositoryCreated(t *testing.T) {
	rec := &recorder{}
	svc := newService(t, rec)

	view, err := svc.Create(context.Background(), "t-1", "repo-1", "infra", "user-9")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if view.Name != "infra" || view.TenantID != "t-1" {
		t.Errorf("unexpected view %+v", view)
	}

	if len(rec.events) != 1 {
		t.Fatalf("want 1 event published, got %d", len(rec.events))
	}
	got, ok := rec.events[0].(api.RepositoryCreated)
	if !ok {
		t.Fatalf("want api.RepositoryCreated, got %T", rec.events[0])
	}
	if got.TenantID != "t-1" || got.RepoID != "repo-1" || got.CreatedBy != "user-9" {
		t.Errorf("event does not carry the creation facts: %+v", got)
	}
	if got.EventID == "" {
		t.Error("event_id is the consumer's idempotency key and must be set")
	}
	if got.OccurredAt.IsZero() {
		t.Error("occurred_at must be set")
	}
}

// TestCreateRejectsAMissingTenant: invariant 1 — there is no un-tenant-scoped write, and the
// rejection happens before anything is stored or published.
func TestCreateRejectsAMissingTenant(t *testing.T) {
	rec := &recorder{}
	svc := newService(t, rec)

	if _, err := svc.Create(context.Background(), "", "repo-1", "infra", "user-9"); err == nil {
		t.Fatal("want an error creating without a tenant")
	}
	if len(rec.events) != 0 {
		t.Errorf("nothing may be published for a rejected write, got %d events", len(rec.events))
	}
}

// TestCreateDoesNotPublishWhenTheWriteFails: the event asserts a fact. If the repository was not
// stored, no consumer may be told that it was.
func TestCreateDoesNotPublishWhenTheWriteFails(t *testing.T) {
	rec := &recorder{}
	svc := app.New(failingStore{}, rec)

	if _, err := svc.Create(context.Background(), "t-1", "repo-1", "infra", "user-9"); err == nil {
		t.Fatal("want the store error surfaced")
	}
	if len(rec.events) != 0 {
		t.Errorf("a failed write must publish nothing, got %d events", len(rec.events))
	}
}

// TestCreateIsReadableAfterwards ties the write path to the read port other modules use.
func TestCreateIsReadableAfterwards(t *testing.T) {
	svc := newService(t, bus.NewInProcess())
	if _, err := svc.Create(context.Background(), "t-1", "repo-1", "infra", "user-9"); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := svc.Get(context.Background(), "t-1", "repo-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Name != "infra" {
		t.Errorf("Get returned %+v", got)
	}
}

// TestGetIsTenantScoped: invariant 1 at the read port — another tenant's id must not resolve,
// and the error must not distinguish "wrong tenant" from "absent".
func TestGetIsTenantScoped(t *testing.T) {
	svc := newService(t, bus.NewInProcess())
	if _, err := svc.Create(context.Background(), "t-1", "repo-1", "infra", "user-9"); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if _, err := svc.Get(context.Background(), "t-2", "repo-1"); err == nil {
		t.Error("want a cross-tenant read denied")
	}
}

// TestPublishFailureFailsTheCall: a bus error is not swallowed, so a consumer that must react
// cannot be silently skipped.
func TestPublishFailureFailsTheCall(t *testing.T) {
	svc := app.New(memstore.New(), failingBus{})
	if _, err := svc.Create(context.Background(), "t-1", "repo-1", "infra", "user-9"); err == nil {
		t.Error("want the publish error surfaced")
	}
}

// Service is reachable only through the module's api/ surface (invariant 14).
var _ api.Reader = (*app.Service)(nil)

type failingStore struct{}

func (failingStore) Save(context.Context, domain.Repository) error {
	return errors.New("store unavailable")
}
func (failingStore) Load(context.Context, domain.TenantID, domain.RepoID) (domain.Repository, error) {
	return domain.Repository{}, errors.New("store unavailable")
}

type failingBus struct{}

func (failingBus) Publish(context.Context, bus.Event) error { return errors.New("bus down") }
func (failingBus) Subscribe(string, bus.Handler)            {}
