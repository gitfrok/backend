// Indexing-path acceptance tests (SPEC-0034): the measured freshness bound and its IndexLagged
// report, the atomic shard swap on reindex, backfill after the content route is wired, and the
// cursor lifetime/tenant bindings. These live in the app package because the cursor minting and
// the freshness maps are the context's internals under test.
package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	csapi "github.com/gitfrok/backend/modules/codesearch/api"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
	repoapi "github.com/gitfrok/backend/modules/repository/api"
	"github.com/gitfrok/backend/platform/bus"
)

// idxRepos resolves the projection's RepositoryCreated lookups.
type idxRepos struct{}

func (idxRepos) Get(_ context.Context, tenantID, repoID string) (repoapi.RepositoryView, error) {
	return repoapi.RepositoryView{TenantID: tenantID, RepoID: repoID, Name: repoID + "-name"}, nil
}

// idxPDP allows everything.
type idxPDP struct{}

func (idxPDP) Decide(_ context.Context, _ policyapi.Request) (policyapi.Decision, error) {
	return policyapi.Decision{Allowed: true}, nil
}

// idxContent is an in-memory ContentSource keyed by (repo, revision).
type idxContent struct {
	mu   sync.Mutex
	revs map[string]map[string]map[string]string
}

func newIdxContent() *idxContent {
	return &idxContent{revs: map[string]map[string]map[string]string{}}
}

func (f *idxContent) put(repo, revision, path, content string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.revs[repo] == nil {
		f.revs[repo] = map[string]map[string]string{}
	}
	if f.revs[repo][revision] == nil {
		f.revs[repo][revision] = map[string]string{}
	}
	f.revs[repo][revision][path] = content
}

func (f *idxContent) ListFiles(_ context.Context, _, repo, revision string) ([]csapi.FileEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []csapi.FileEntry
	for path, content := range f.revs[repo][revision] {
		out = append(out, csapi.FileEntry{Path: path, SizeBytes: int64(len(content))})
	}
	return out, nil
}

func (f *idxContent) ReadFile(_ context.Context, _, repo, revision, path string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	content, ok := f.revs[repo][revision][path]
	if !ok {
		return nil, errors.New("content: no such file")
	}
	return []byte(content), nil
}

func newIdxService(t *testing.T, cfg Config, content csapi.ContentSource) (*Service, *bus.InProcess) {
	t.Helper()
	b := bus.NewInProcess()
	svc := NewService(idxRepos{}, idxPDP{}, b, content, cfg)
	svc.Register(b)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = svc.Drain(ctx)
	})
	return svc, b
}

func idxQuery(tenant, actor, text string) csapi.Query {
	return csapi.Query{
		TenantID: tenant, ActorID: actor, ActorRoles: []string{"owner"}, RequestID: "req-1",
		Text: text, Mode: csapi.QueryModeSubstring,
	}
}

// pushAdmission announces the repository and one ref move, then waits for the absorb.
func pushAdmission(t *testing.T, b *bus.InProcess, svc *Service, tenant, repo, revision string, admittedAt time.Time) {
	t.Helper()
	ctx := context.Background()
	if err := b.Publish(ctx, repoapi.RepositoryCreated{
		EventID: "evt-created-" + repo, TenantID: tenant, RepoID: repo, OccurredAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("publish created: %v", err)
	}
	if err := b.Publish(ctx, repoapi.RefUpdated{
		EventID: "evt-ref-" + repo + "-" + revision, TenantID: tenant, RepoID: repo,
		Ref: "refs/heads/main", NewSha: revision, OccurredAt: admittedAt,
	}); err != nil {
		t.Fatalf("publish ref: %v", err)
	}
	dctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := svc.Drain(dctx); err != nil {
		t.Fatalf("drain: %v", err)
	}
}

// AC4 (freshness): a measured lag above the stated bound publishes IndexLagged, exactly once per
// repository per admitted revision — exceeding the bound is a reported condition, not a silent
// delay, and not an event storm (SPEC-0034 non-functional).
func TestIndexLaggedPublishedOnceOnBoundBreach(t *testing.T) {
	content := newIdxContent()
	svc, b := newIdxService(t, Config{FreshnessBound: time.Millisecond}, content)

	var mu sync.Mutex
	var lagged []csapi.IndexLagged
	bus.SubscribeTyped[csapi.IndexLagged](b, func(_ context.Context, e csapi.IndexLagged) error {
		mu.Lock()
		lagged = append(lagged, e)
		mu.Unlock()
		return nil
	})

	// Admission an hour ago: whatever the absorb itself took, the measured lag exceeds the
	// millisecond bound.
	content.put("repo-a", "rev-1", "a.go", "package a\n")
	pushAdmission(t, b, svc, "t-1", "repo-a", "rev-1", time.Now().UTC().Add(-time.Hour))

	// A status read measures again; dedupe must keep the count at one.
	if _, err := svc.GetIndexStatus(context.Background(), idxQuery("t-1", "owner", "")); err != nil {
		t.Fatalf("status: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(lagged) != 1 {
		t.Fatalf("expected exactly one IndexLagged, got %d (%+v)", len(lagged), lagged)
	}
	e := lagged[0]
	if e.TenantID != "t-1" || e.RepositoryID != "repo-a" || e.LastIndexedRevision != "rev-1" ||
		e.Lag <= time.Millisecond {
		t.Fatalf("unexpected lag event: %+v", e)
	}
}

// AC5 (atomic swap): the old shard keeps serving until the new one is complete; after the swap
// the new revision answers and the old content is gone.
func TestReindexSwapsShardAtomically(t *testing.T) {
	content := newIdxContent()
	svc, b := newIdxService(t, Config{}, content)
	ctx := context.Background()

	content.put("repo-a", "rev-1", "a.go", "package a // oldtoken\n")
	pushAdmission(t, b, svc, "t-1", "repo-a", "rev-1", time.Now().UTC())
	if page, err := svc.Search(ctx, idxQuery("t-1", "owner", "oldtoken")); err != nil ||
		len(page.Matches) != 1 || page.Matches[0].Revision != "rev-1" {
		t.Fatalf("rev-1 must serve oldtoken: %+v err=%v", page, err)
	}

	content.put("repo-a", "rev-2", "a.go", "package a // newtoken\n")
	pushAdmission(t, b, svc, "t-1", "repo-a", "rev-2", time.Now().UTC())
	if page, err := svc.Search(ctx, idxQuery("t-1", "owner", "newtoken")); err != nil ||
		len(page.Matches) != 1 || page.Matches[0].Revision != "rev-2" {
		t.Fatalf("rev-2 must serve newtoken: %+v err=%v", page, err)
	}
	if page, err := svc.Search(ctx, idxQuery("t-1", "owner", "oldtoken")); err != nil ||
		!reflect.DeepEqual(page, csapi.Page{}) {
		t.Fatalf("old content must be gone after the swap: %+v err=%v", page, err)
	}
}

// Backfill absorbs every admitted revision the index missed once the content route is wired —
// the restart path (SPEC-0034 incremental + the plane's AttachContentSource sequence).
func TestBackfillAbsorbsMissedRevisions(t *testing.T) {
	content := newIdxContent()
	b := bus.NewInProcess()
	svc := NewService(idxRepos{}, idxPDP{}, b, nil, Config{}) // no content route yet
	svc.Register(b)
	ctx := context.Background()

	if err := b.Publish(ctx, repoapi.RepositoryCreated{
		EventID: "evt-created", TenantID: "t-1", RepoID: "repo-a", OccurredAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("publish created: %v", err)
	}
	if err := b.Publish(ctx, repoapi.RefUpdated{
		EventID: "evt-ref", TenantID: "t-1", RepoID: "repo-a", Ref: "refs/heads/main",
		NewSha: "rev-1", OccurredAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("publish ref: %v", err)
	}
	if err := svc.Drain(ctx); err != nil {
		t.Fatalf("drain: %v", err)
	}

	// No content route: nothing absorbed, queries yield the zero Page.
	if page, _ := svc.Search(ctx, idxQuery("t-1", "owner", "backfilltoken")); !reflect.DeepEqual(page, csapi.Page{}) {
		t.Fatalf("no content route means no matches: %+v", page)
	}

	content.put("repo-a", "rev-1", "a.go", "package a // backfilltoken\n")
	svc.AttachContentSource(content)
	if err := svc.Backfill(ctx); err != nil {
		t.Fatalf("backfill: %v", err)
	}
	if err := svc.Drain(ctx); err != nil {
		t.Fatalf("drain after backfill: %v", err)
	}
	page, err := svc.Search(ctx, idxQuery("t-1", "owner", "backfilltoken"))
	if err != nil || len(page.Matches) != 1 || page.Matches[0].Revision != "rev-1" {
		t.Fatalf("backfilled revision must be searchable: %+v err=%v", page, err)
	}
	// A second backfill is a no-op: the revision is already absorbed.
	if err := svc.Backfill(ctx); err != nil {
		t.Fatalf("second backfill: %v", err)
	}
}

// Cursor lifetime and tenant binding: an expired token and a token minted for another tenant
// both yield the zero Page — never an error that distinguishes causes (SPEC-0035 AC1/AC5).
func TestCursorExpiryAndCrossTenantRefused(t *testing.T) {
	content := newIdxContent()
	svc, b := newIdxService(t, Config{}, content)
	ctx := context.Background()

	content.put("repo-a", "rev-1", "a.go", strings.Repeat("lifetoken\n", 4))
	pushAdmission(t, b, svc, "t-1", "repo-a", "rev-1", time.Now().UTC())

	// An expired token (the minting shape, a past deadline).
	expired := idxQuery("t-1", "owner", "lifetoken")
	expired.PageToken = svc.encodeCursor("t-1", "owner", "lifetoken", int(csapi.QueryModeSubstring), 2,
		time.Now().UTC().Add(-time.Minute))
	if page, err := svc.Search(ctx, expired); err != nil || !reflect.DeepEqual(page, csapi.Page{}) {
		t.Fatalf("expired token must yield the zero Page, got %+v err=%v", page, err)
	}

	// A token minted for another tenant.
	cross := idxQuery("t-1", "owner", "lifetoken")
	cross.PageToken = svc.encodeCursor("other-tenant", "owner", "lifetoken", int(csapi.QueryModeSubstring), 0,
		time.Now().UTC().Add(time.Hour))
	if page, err := svc.Search(ctx, cross); err != nil || !reflect.DeepEqual(page, csapi.Page{}) {
		t.Fatalf("cross-tenant token must yield the zero Page, got %+v err=%v", page, err)
	}

	// A cursor minted inside the lifetime still advances.
	live := idxQuery("t-1", "owner", "lifetoken")
	live.ResultLimit = 2
	first, err := svc.Search(ctx, live)
	if err != nil || len(first.Matches) != 2 || first.NextPageToken == "" {
		t.Fatalf("first page: %+v err=%v", first, err)
	}
	live.PageToken = first.NextPageToken
	second, err := svc.Search(ctx, live)
	if err != nil || len(second.Matches) != 2 || second.NextPageToken != "" {
		t.Fatalf("second page: %+v err=%v", second, err)
	}
}

// Cursor principal binding (L17): a token is issued to one actor; a different actor in the same
// tenant replaying it yields the zero Page — the same coarse shape as every other refusal.
func TestCursorIsBoundToTheIssuingActor(t *testing.T) {
	content := newIdxContent()
	svc, b := newIdxService(t, Config{}, content)
	ctx := context.Background()

	content.put("repo-a", "rev-1", "a.go", strings.Repeat("actortoken\n", 4))
	pushAdmission(t, b, svc, "t-1", "repo-a", "rev-1", time.Now().UTC())

	first := idxQuery("t-1", "owner", "actortoken")
	first.ResultLimit = 2
	page, err := svc.Search(ctx, first)
	if err != nil || len(page.Matches) != 2 || page.NextPageToken == "" {
		t.Fatalf("first page: %+v err=%v", page, err)
	}

	// The issuing principal pages through.
	next := idxQuery("t-1", "owner", "actortoken")
	next.PageToken = page.NextPageToken
	second, err := svc.Search(ctx, next)
	if err != nil || len(second.Matches) != 2 {
		t.Fatalf("the issuing actor must keep paging: %+v err=%v", second, err)
	}

	// A different actor in the same tenant reusing the same token gets nothing.
	intruder := idxQuery("t-1", "intruder", "actortoken")
	intruder.PageToken = page.NextPageToken
	if page, err := svc.Search(ctx, intruder); err != nil || !reflect.DeepEqual(page, csapi.Page{}) {
		t.Fatalf("a replayed token under another actor must yield the zero Page, got %+v err=%v", page, err)
	}
}

// hungContent blocks ListFiles for one repository until the context is canceled: the shape of a
// hung content fetch the worker must survive.
type hungContent struct {
	inner    *idxContent
	hungRepo string
}

func (h *hungContent) ListFiles(ctx context.Context, tenant, repo, revision string) ([]csapi.FileEntry, error) {
	if repo == h.hungRepo {
		<-ctx.Done() // hang until the plane's per-job timeout cancels
		return nil, ctx.Err()
	}
	return h.inner.ListFiles(ctx, tenant, repo, revision)
}

func (h *hungContent) ReadFile(ctx context.Context, tenant, repo, revision, path string) ([]byte, error) {
	return h.inner.ReadFile(ctx, tenant, repo, revision, path)
}

// L15: one hung content fetch must not stall the single indexing worker. The hung job times out
// under the per-job bound, reports nothing new by itself, and the repository queued behind it
// still indexes.
func TestAHungIndexingJobTimesOutAndTheWorkerMovesOn(t *testing.T) {
	inner := newIdxContent()
	inner.put("repo-ok", "rev-1", "a.go", "package a // afterhang\n")
	content := &hungContent{inner: inner, hungRepo: "repo-hung"}
	svc, b := newIdxService(t, Config{JobTimeout: 50 * time.Millisecond}, content)
	ctx := context.Background()

	// Admit the hung repository first, then a healthy one: without the per-job timeout the
	// worker would sit on repo-hung forever and repo-ok would never index.
	for _, repo := range []string{"repo-hung", "repo-ok"} {
		if err := b.Publish(ctx, repoapi.RepositoryCreated{
			EventID: "evt-created-" + repo, TenantID: "t-1", RepoID: repo, OccurredAt: time.Now().UTC(),
		}); err != nil {
			t.Fatalf("publish created %s: %v", repo, err)
		}
		if err := b.Publish(ctx, repoapi.RefUpdated{
			EventID: "evt-ref-" + repo, TenantID: "t-1", RepoID: repo,
			Ref: "refs/heads/main", NewSha: "rev-1", OccurredAt: time.Now().UTC(),
		}); err != nil {
			t.Fatalf("publish ref %s: %v", repo, err)
		}
	}
	dctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := svc.Drain(dctx); err != nil {
		t.Fatalf("the worker stalled on the hung job: %v", err)
	}

	page, err := svc.Search(ctx, idxQuery("t-1", "owner", "afterhang"))
	if err != nil || len(page.Matches) != 1 || page.Matches[0].Revision != "rev-1" {
		t.Fatalf("the repository queued behind the hung job never indexed: %+v err=%v", page, err)
	}
}
