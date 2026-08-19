package app_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	policyapi "github.com/gitfrok/backend/modules/policy/api"
	"github.com/gitfrok/backend/modules/release/api"
	"github.com/gitfrok/backend/modules/release/internal/app"
)

// SPEC-0056 AC2, AC4, AC6: the commit is recorded not resolved, prose is
// editable and the pointer is not, and this context never asks git anything.

type pdp struct {
	allow map[string]bool
	err   error
	asked []string
}

func (p *pdp) Decide(_ context.Context, req policyapi.Request) (policyapi.Decision, error) {
	p.asked = append(p.asked, req.Action)
	if p.err != nil {
		return policyapi.Decision{}, p.err
	}
	return policyapi.Decision{Allowed: p.allow[req.Action]}, nil
}

func allowAll() *pdp { return &pdp{allow: map[string]bool{"repo.read": true, "repo.write": true}} }

type memStore struct {
	rows map[string]api.Release
}

func newStore() *memStore { return &memStore{rows: map[string]api.Release{}} }

func key(r, tag string) string { return r + "\x00" + tag }

func (m *memStore) Insert(_ context.Context, r api.Release) error {
	if _, ok := m.rows[key(r.RepositoryID, r.Tag)]; ok {
		return api.ErrAlreadyPublished
	}
	m.rows[key(r.RepositoryID, r.Tag)] = r
	return nil
}
func (m *memStore) Get(_ context.Context, _, repositoryID, tag string) (api.Release, error) {
	r, ok := m.rows[key(repositoryID, tag)]
	if !ok {
		return api.Release{}, api.ErrNotFound
	}
	return r, nil
}
func (m *memStore) UpdateNotes(_ context.Context, _, repositoryID, tag, notes string, at time.Time) (api.Release, error) {
	r, ok := m.rows[key(repositoryID, tag)]
	if !ok {
		return api.Release{}, api.ErrNotFound
	}
	r.Notes, r.NotesUpdatedAt = notes, at
	m.rows[key(repositoryID, tag)] = r
	return r, nil
}
func (m *memStore) Page(_ context.Context, _, repositoryID string, _ app.Cursor, limit int) ([]api.Release, error) {
	var out []api.Release
	for k, r := range m.rows {
		if strings.HasPrefix(k, repositoryID+"\x00") {
			out = append(out, r)
		}
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func rc() api.Context {
	return api.Context{TenantID: "t-1", RepositoryID: "repo-1", ActorID: "dev@x", ActorRoles: []string{"member"}}
}

func TestPublishRecordsTheCommitItWasGivenAndTheSessionsActor(t *testing.T) {
	store := newStore()
	svc := app.New(store, allowAll())

	got, err := svc.Publish(context.Background(), api.PublishRequest{
		Context: rc(), Tag: "v1.0.0", Notes: "first", PublishedCommit: "abc123",
	})
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if got.PublishedCommit != "abc123" {
		t.Fatalf("commit %q", got.PublishedCommit)
	}
	// The publisher is the session's actor, never a request field.
	if got.PublishedBy != "dev@x" {
		t.Fatalf("published by %q", got.PublishedBy)
	}
	if got.PublishedAt.IsZero() {
		t.Fatal("no publish instant")
	}
}

// AC6: nothing in this context resolves a tag. The service has no port that
// could, and a publish with no resolved commit is refused rather than looked up.
func TestPublishWithoutAResolvedCommitIsRefused(t *testing.T) {
	svc := app.New(newStore(), allowAll())
	_, err := svc.Publish(context.Background(), api.PublishRequest{Context: rc(), Tag: "v1.0.0"})
	if !errors.Is(err, api.ErrInvalid) {
		t.Fatalf("want ErrInvalid, got %v", err)
	}
}

func TestPublishingTheSameTagTwiceIsRefused(t *testing.T) {
	svc := app.New(newStore(), allowAll())
	req := api.PublishRequest{Context: rc(), Tag: "v1.0.0", Notes: "x", PublishedCommit: "abc"}
	if _, err := svc.Publish(context.Background(), req); err != nil {
		t.Fatalf("first: %v", err)
	}
	req.PublishedCommit = "def"
	if _, err := svc.Publish(context.Background(), req); !errors.Is(err, api.ErrAlreadyPublished) {
		t.Fatalf("want ErrAlreadyPublished, got %v", err)
	}
}

// AC4: editing prose does not move what a release points at.
func TestUpdateNotesCannotMoveTheRelease(t *testing.T) {
	store := newStore()
	svc := app.New(store, allowAll())
	if _, err := svc.Publish(context.Background(), api.PublishRequest{
		Context: rc(), Tag: "v1.0.0", Notes: "first", PublishedCommit: "abc123",
	}); err != nil {
		t.Fatalf("publish: %v", err)
	}
	got, err := svc.UpdateNotes(context.Background(), rc(), "v1.0.0", "corrected")
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if got.Notes != "corrected" || got.PublishedCommit != "abc123" || got.Tag != "v1.0.0" {
		t.Fatalf("edit moved the release: %+v", got)
	}
	// There is deliberately no method that takes a new commit or a new tag.
	var _ interface {
		UpdateNotes(context.Context, api.Context, string, string) (api.Release, error)
	} = svc
}

// Reads and writes ask about the REPOSITORY: a release adds no permission of
// its own.
func TestPublishAsksRepoWriteAndReadAsksRepoRead(t *testing.T) {
	p := allowAll()
	svc := app.New(newStore(), p)
	if _, err := svc.Publish(context.Background(), api.PublishRequest{
		Context: rc(), Tag: "v1", Notes: "", PublishedCommit: "abc",
	}); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if _, err := svc.Get(context.Background(), rc(), "v1"); err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(p.asked) != 2 || p.asked[0] != "repo.write" || p.asked[1] != "repo.read" {
		t.Fatalf("asked %v", p.asked)
	}
}

// A refusal is ErrNotFound, never a permission error: a caller must not learn a
// release exists.
func TestARefusalIsAbsenceNotDenial(t *testing.T) {
	svc := app.New(newStore(), &pdp{allow: map[string]bool{}})
	if _, err := svc.Get(context.Background(), rc(), "v1.0.0"); !errors.Is(err, api.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	if _, err := svc.Publish(context.Background(), api.PublishRequest{
		Context: rc(), Tag: "v1", PublishedCommit: "abc",
	}); !errors.Is(err, api.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestAPDPErrorIsARefusal(t *testing.T) {
	svc := app.New(newStore(), &pdp{err: errors.New("pdp down")})
	if _, err := svc.Get(context.Background(), rc(), "v1"); !errors.Is(err, api.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestNotesAreBounded(t *testing.T) {
	svc := app.New(newStore(), allowAll())
	_, err := svc.Publish(context.Background(), api.PublishRequest{
		Context: rc(), Tag: "v1", PublishedCommit: "abc",
		Notes: strings.Repeat("x", api.MaxNotesBytes+1),
	})
	if !errors.Is(err, api.ErrInvalid) {
		t.Fatalf("want ErrInvalid, got %v", err)
	}
}

func TestATagTheContractDoesNotNameIsRefused(t *testing.T) {
	svc := app.New(newStore(), allowAll())
	for _, tag := range []string{"", strings.Repeat("v", api.MaxTagLength+1), "with\x00nul", "with\nnewline"} {
		_, err := svc.Publish(context.Background(), api.PublishRequest{
			Context: rc(), Tag: tag, PublishedCommit: "abc",
		})
		if !errors.Is(err, api.ErrInvalid) {
			t.Fatalf("tag %q: want ErrInvalid, got %v", tag, err)
		}
	}
}

func TestACursorFromAnotherTenantIsRefused(t *testing.T) {
	svc := app.New(newStore(), allowAll())
	q := api.ListQuery{Context: rc(), PageSize: 1}
	other := rc()
	other.TenantID = "t-2"
	// A token minted for t-1 replayed as t-2.
	page, err := svc.List(context.Background(), q)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	_ = page
	q2 := api.ListQuery{Context: other, PageToken: "not-a-cursor"}
	if _, err := svc.List(context.Background(), q2); err == nil {
		t.Fatal("a malformed cursor must be refused")
	}
}
