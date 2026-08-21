package postgres_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/gitfrok/backend/modules/codereview/api"
	crpg "github.com/gitfrok/backend/modules/codereview/internal/adapters/postgres"
	"github.com/gitfrok/backend/modules/codereview/internal/app"
	"github.com/gitfrok/backend/platform/db"
	"github.com/gitfrok/backend/platform/tenancy"
)

// SPEC-0061 against a real Postgres.
//
// The claims are about what survives a process and what the DATABASE permits: durability is a
// statement about committed rows, isolation is a statement about RLS policies, and the version guard
// is a statement about what two concurrent writers can both be told. None of that exists in process
// memory, so an in-memory fake would prove that a fake behaves.
//
//	kubectl port-forward svc/postgres 15432:5432   (minikube profile gitfrok)
//	TEST_DATABASE_URL='postgres://gitfrok_app:gitfrok_app@127.0.0.1:15432/gitfrok' \
//	TEST_SUPERUSER_DATABASE_URL='postgres://postgres:postgres@127.0.0.1:15432/gitfrok' \
//	  go test -race ./modules/codereview/internal/adapters/postgres/...
//
// **Carried limit 5 applies.** Without TEST_DATABASE_URL these SKIP, and what skips is the isolation
// proof. A green run that skipped it has proven nothing about isolation — count the skips before
// believing the exit record.

var runID = fmt.Sprintf("%d", time.Now().UnixNano()%1_000_000_000)

func TestMain(m *testing.M) {
	if dsn := os.Getenv("TEST_SUPERUSER_DATABASE_URL"); dsn != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		err := applyMigration(ctx, dsn, "migrations/0001_codereview.sql")
		cancel()
		if err != nil {
			fmt.Fprintf(os.Stderr, "codereview postgres tests: could not self-apply migration: %v\n", err)
		}
	}
	os.Exit(m.Run())
}

func applyMigration(ctx context.Context, superDSN, file string) error {
	sql, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	pool, err := pgxpool.New(ctx, superDSN)
	if err != nil {
		return err
	}
	defer pool.Close()
	_, err = pool.Exec(ctx, string(sql))
	return err
}

func openPool(t *testing.T) *db.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — integration test needs a Postgres with the SPEC-0001 RLS baseline")
	}
	pool, err := db.Open(t.Context(), dsn)
	if err != nil {
		t.Fatalf("opening pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// tenantFor gives each test its own tenant within the run: there is no delete path for the app role
// by design, so the fixture moves instead of cleaning up.
func tenantFor(t *testing.T) string {
	t.Helper()
	safe := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		default:
			return '-'
		}
	}, t.Name())
	if len(safe) > 32 {
		safe = safe[:32]
	}
	return fmt.Sprintf("t-%s-%s", safe, runID)
}

var at = time.Date(2026, 8, 20, 9, 0, 0, 0, time.UTC)

func mergeRequest(tenant, id string) api.MergeRequest {
	return api.MergeRequest{
		ID: id, TenantID: tenant, RepositoryID: "repo-a",
		SourceRef: "refs/heads/feature", TargetRef: "refs/heads/main",
		Title: "Add the thing", Description: "it does the thing",
		CreatorID: "dev@x", State: api.StateOpen,
		HeadRevision: "sha-head", TargetRevision: "sha-target",
		CreatedAt: at, UpdatedAt: at, Version: 1,
	}
}

// scopedCtx is what the gRPC door produces: a context naming the verified tenant.
func scopedCtx(t *testing.T, tenant string) context.Context {
	t.Helper()
	return tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
}

// AC1: the merge request survives the store that wrote it — the restart, expressed as the only thing
// a test can express it as.
func TestMergeRequestSurvivesTheStoreThatWroteIt(t *testing.T) {
	pool := openPool(t)
	tenant := tenantFor(t)
	ctx := scopedCtx(t, tenant)

	if _, _, err := crpg.New(pool).CreateOrGet(ctx, "key-1", mergeRequest(tenant, "mr-1")); err != nil {
		t.Fatalf("create: %v", err)
	}

	got, err := crpg.New(pool).Get(ctx, "mr-1")
	if err != nil {
		t.Fatalf("get after rebuild: %v", err)
	}
	if got.Title != "Add the thing" || got.State != api.StateOpen || got.Version != 1 {
		t.Fatalf("loaded %+v", got)
	}
	if got.TargetRevision != "sha-target" || got.CreatorID != "dev@x" {
		t.Errorf("the record lost fields: %+v", got)
	}
}

// AC2: reviews, protections, ref revisions and external issue references survive the same way.
func TestTheRestOfTheAggregateSurvivesToo(t *testing.T) {
	pool := openPool(t)
	tenant := tenantFor(t)
	ctx := scopedCtx(t, tenant)
	store := crpg.New(pool)

	mr := mergeRequest(tenant, "mr-1")
	mr.ExternalIssues = []api.ExternalIssue{
		{Tracker: "JIRA", IssueKey: "PLAT-1", URL: "https://tracker.test/PLAT-1", LinkedBy: "dev@x", LinkedAt: at},
		{Tracker: "Linear", IssueKey: "ENG-9", URL: "https://linear.test/ENG-9", LinkedBy: "dev@x", LinkedAt: at},
	}
	if _, _, err := store.CreateOrGet(ctx, "key-1", mr); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := store.PutReview(ctx, "mr-1", app.Review{
		ActorID: "reviewer@x", Disposition: api.DispositionApprove, HeadRevision: "sha-head", SubmittedAt: at,
	}); err != nil {
		t.Fatalf("put review: %v", err)
	}
	if err := store.SaveProtection(ctx, api.BranchProtection{
		TenantID: tenant, RepositoryID: "repo-a", TargetRef: "refs/heads/main", RequiredApprovals: 1, Version: 1,
	}); err != nil {
		t.Fatalf("save protection: %v", err)
	}
	if err := store.SaveRefRevision(ctx, tenant, "repo-a", "refs/heads/main", "sha-target"); err != nil {
		t.Fatalf("save ref revision: %v", err)
	}

	rebuilt := crpg.New(pool)

	loaded, err := rebuilt.Get(ctx, "mr-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(loaded.ExternalIssues) != 2 {
		t.Fatalf("references did not survive: %+v", loaded.ExternalIssues)
	}
	// Order is the order they were linked: a reader saw them in that order, and a set that
	// reshuffles on read is a different page every time.
	if loaded.ExternalIssues[0].IssueKey != "PLAT-1" || loaded.ExternalIssues[1].IssueKey != "ENG-9" {
		t.Errorf("references came back reordered: %+v", loaded.ExternalIssues)
	}
	if loaded.ExternalIssues[0].URL != "https://tracker.test/PLAT-1" || loaded.ExternalIssues[0].LinkedBy != "dev@x" {
		t.Errorf("a reference lost fields: %+v", loaded.ExternalIssues[0])
	}
	if !loaded.ExternalIssues[0].LinkedAt.Equal(at) {
		t.Errorf("a reference lost its instant: %v", loaded.ExternalIssues[0].LinkedAt)
	}

	reviews, err := rebuilt.Reviews(ctx, "mr-1")
	if err != nil || len(reviews) != 1 || reviews[0].Disposition != api.DispositionApprove {
		t.Fatalf("reviews did not survive: %+v (%v)", reviews, err)
	}
	protection, found, err := rebuilt.Protection(ctx, tenant, "repo-a", "refs/heads/main")
	if err != nil || !found || protection.RequiredApprovals != 1 {
		t.Fatalf("protection did not survive: %+v found=%v (%v)", protection, found, err)
	}
	revision, err := rebuilt.RefRevision(ctx, tenant, "repo-a", "refs/heads/main")
	if err != nil || revision != "sha-target" {
		t.Fatalf("ref revision did not survive: %q (%v)", revision, err)
	}
}

// AC2: a merge request with no references reads back with none — not a null the caller must handle.
func TestAMergeRequestWithNoReferencesReadsBackClean(t *testing.T) {
	pool := openPool(t)
	tenant := tenantFor(t)
	ctx := scopedCtx(t, tenant)
	store := crpg.New(pool)

	if _, _, err := store.CreateOrGet(ctx, "key-1", mergeRequest(tenant, "mr-1")); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := store.Get(ctx, "mr-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(got.ExternalIssues) != 0 {
		t.Errorf("want no references, got %+v", got.ExternalIssues)
	}
}

// AC3: the idempotency key survives, so a retry after a restart returns the first merge request
// rather than creating a second.
func TestCreateOrGetIsIdempotentAcrossStores(t *testing.T) {
	pool := openPool(t)
	tenant := tenantFor(t)
	ctx := scopedCtx(t, tenant)

	first, created, err := crpg.New(pool).CreateOrGet(ctx, "key-1", mergeRequest(tenant, "mr-1"))
	if err != nil || !created {
		t.Fatalf("first create: created=%v err=%v", created, err)
	}
	second, created, err := crpg.New(pool).CreateOrGet(ctx, "key-1", mergeRequest(tenant, "mr-2"))
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if created {
		t.Error("a replayed key reported that it created something")
	}
	if second.ID != first.ID {
		t.Errorf("the replay returned a different merge request: %q then %q", first.ID, second.ID)
	}
}

// AC3, second half: a concurrent double-submit converges instead of denying.
// Both callers miss any lookup, both insert the same key; ON CONFLICT DO NOTHING
// lets exactly one win and the loser reads back the winner's merge request —
// what the mutex-serialised memory store returned, without the mutex
// (ADR-0084 decision 4).
func TestConcurrentDoubleSubmitConvergesOnOneMergeRequest(t *testing.T) {
	pool := openPool(t)
	tenant := tenantFor(t)
	ctx := scopedCtx(t, tenant)
	store := crpg.New(pool)

	const key = "key-race"
	type outcome struct {
		mr      api.MergeRequest
		created bool
		err     error
	}
	results := make(chan outcome, 2)
	start := make(chan struct{})
	for i := range 2 {
		go func(i int) {
			<-start
			candidate := mergeRequest(tenant, fmt.Sprintf("mr-racer-%d", i))
			mr, created, err := store.CreateOrGet(ctx, key, candidate)
			results <- outcome{mr: mr, created: created, err: err}
		}(i)
	}
	close(start)

	var winners int
	firstID := ""
	for range 2 {
		got := <-results
		if got.err != nil {
			t.Fatalf("a concurrent same-key submit was denied instead of converged: %v", got.err)
		}
		if got.created {
			winners++
			if firstID == "" {
				firstID = got.mr.ID
			}
			continue
		}
		if got.mr.ID == "" {
			t.Error("the losing submit returned no merge request")
		}
	}
	if winners != 1 {
		t.Errorf("want exactly one creator, got %d", winners)
	}
	survivor, err := store.Get(ctx, firstID)
	if err != nil {
		t.Fatalf("get the winner: %v", err)
	}
	if survivor.ID != firstID {
		t.Errorf("the stored merge request is not the winner's: %q vs %q", survivor.ID, firstID)
	}
}

// AC4: Seen reports a request ID as unseen exactly once, and remembers across stores.
//
// Without this, every write a client retried across a restart would apply twice.
func TestSeenIsOnceAndSurvives(t *testing.T) {
	pool := openPool(t)
	ctx := scopedCtx(t, tenantFor(t))

	seen, err := crpg.New(pool).Seen(ctx, "request-1")
	if err != nil || seen {
		t.Fatalf("first sighting: seen=%v err=%v", seen, err)
	}
	seen, err = crpg.New(pool).Seen(ctx, "request-1")
	if err != nil || !seen {
		t.Fatalf("second sighting after rebuild: seen=%v err=%v", seen, err)
	}
}

// AC5: a call for one tenant under a context scoped to another is refused before any database work.
// RLS cannot make this refusal — the transaction would be scoped to the tenant that was asked for.
func TestACallForAnotherTenantUnderAScopedContextIsRefused(t *testing.T) {
	pool := openPool(t)
	mine := tenantFor(t)
	theirs := mine + "-other"
	store := crpg.New(pool)
	ctx := scopedCtx(t, mine)

	if _, _, err := store.CreateOrGet(ctx, "key-x", mergeRequest(theirs, "mr-theirs")); err == nil {
		t.Error("a create for another tenant was accepted")
	} else if !strings.Contains(err.Error(), "refusing a call for tenant") {
		t.Errorf("want the scoping refusal, got %v", err)
	}
	if err := store.SaveRefRevision(ctx, theirs, "repo-a", "refs/heads/main", "sha"); err == nil {
		t.Error("a ref revision for another tenant was accepted")
	}
	if _, _, err := store.Protection(ctx, theirs, "repo-a", "refs/heads/main"); err == nil {
		t.Error("a protection read for another tenant was accepted")
	}
}

// AC6: a tenant-less method with no tenant in the context is refused, not run unscoped.
func TestATenantlessCallWithNoContextTenantIsRefused(t *testing.T) {
	pool := openPool(t)
	store := crpg.New(pool)
	bare := t.Context()

	if _, err := store.Get(bare, "mr-1"); err == nil {
		t.Error("an unscoped Get was accepted")
	}
	if _, err := store.Seen(bare, "request-1"); err == nil {
		t.Error("an unscoped Seen was accepted")
	}
	if _, err := store.Reviews(bare, "mr-1"); err == nil {
		t.Error("an unscoped Reviews was accepted")
	}
	if err := store.PutReview(bare, "mr-1", app.Review{ActorID: "a", SubmittedAt: at}); err == nil {
		t.Error("an unscoped PutReview was accepted")
	}
}

// AC8: another tenant's merge request is ABSENT — not loadable, not listed, not reported to exist.
func TestAnotherTenantsMergeRequestIsAbsent(t *testing.T) {
	pool := openPool(t)
	mine := tenantFor(t)
	theirs := mine + "-other"
	store := crpg.New(pool)

	if _, _, err := store.CreateOrGet(scopedCtx(t, theirs), "key-theirs", mergeRequest(theirs, "mr-theirs")); err != nil {
		t.Fatalf("seeding the other tenant: %v", err)
	}

	mineCtx := scopedCtx(t, mine)
	if _, err := store.Get(mineCtx, "mr-theirs"); err == nil {
		t.Error("another tenant's merge request was loadable")
	}
	open, err := store.OpenForTarget(mineCtx, mine, "repo-a", "refs/heads/main")
	if err != nil {
		t.Fatalf("open for target: %v", err)
	}
	if len(open) != 0 {
		t.Errorf("another tenant's merge request was listed: %+v", open)
	}
	reviews, err := store.Reviews(mineCtx, "mr-theirs")
	if err != nil {
		t.Fatalf("reviews: %v", err)
	}
	if len(reviews) != 0 {
		t.Errorf("another tenant's reviews were readable: %+v", reviews)
	}
}

// AC9: two writers who read the same version cannot both win.
func TestTheVersionGuardIsInTheWrite(t *testing.T) {
	pool := openPool(t)
	tenant := tenantFor(t)
	ctx := scopedCtx(t, tenant)
	store := crpg.New(pool)

	if _, _, err := store.CreateOrGet(ctx, "key-1", mergeRequest(tenant, "mr-1")); err != nil {
		t.Fatalf("create: %v", err)
	}

	// Both readers hold version 1 and both write version 2. The first wins.
	first := mergeRequest(tenant, "mr-1")
	first.Title, first.Version = "renamed by the first writer", 2
	if err := store.Save(ctx, first); err != nil {
		t.Fatalf("first save: %v", err)
	}

	second := mergeRequest(tenant, "mr-1")
	second.Title, second.Version = "renamed by the second writer", 2
	err := store.Save(ctx, second)
	if !errors.Is(err, crpg.ErrVersionConflict) {
		t.Fatalf("want a version conflict, got %v", err)
	}

	got, err := store.Get(ctx, "mr-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Title != "renamed by the first writer" {
		t.Errorf("the loser's write landed: %q", got.Title)
	}
}

// AC9: a save against a merge request that is not there is a conflict too, and it does not create one.
func TestSavingAMergeRequestThatIsNotThereIsRefused(t *testing.T) {
	pool := openPool(t)
	tenant := tenantFor(t)
	ctx := scopedCtx(t, tenant)
	store := crpg.New(pool)

	missing := mergeRequest(tenant, "mr-missing")
	missing.Version = 2
	if err := store.Save(ctx, missing); !errors.Is(err, crpg.ErrVersionConflict) {
		t.Fatalf("want a version conflict, got %v", err)
	}
	if _, err := store.Get(ctx, "mr-missing"); err == nil {
		t.Error("the refused save created the merge request")
	}
}

// AC15: the column's bound refuses a reference list past the domain's limit, so the last line of
// defence is the database rather than the caller.
func TestTheReferenceBoundIsEnforcedAtTheColumn(t *testing.T) {
	pool := openPool(t)
	tenant := tenantFor(t)
	ctx := scopedCtx(t, tenant)

	mr := mergeRequest(tenant, "mr-1")
	for i := range 26 {
		mr.ExternalIssues = append(mr.ExternalIssues, api.ExternalIssue{
			Tracker: "JIRA", IssueKey: fmt.Sprintf("PLAT-%d", i),
			URL: "https://tracker.test/x", LinkedBy: "dev@x", LinkedAt: at,
		})
	}
	_, _, err := crpg.New(pool).CreateOrGet(ctx, "key-1", mr)
	if err == nil {
		t.Fatal("26 references were accepted; the domain bounds them at 25 and so must the column")
	}
	if !strings.Contains(err.Error(), "external_issues") {
		t.Errorf("want the column's own constraint to refuse it, got %v", err)
	}
}

// AC10: the projection write lands the projected fields and advances nothing —
// a ref moving under a merge request is not a caller edit, and bumping the
// version here would invalidate a review mid-submission (ADR-0084 decision 1).
func TestAProjectionLandsWithoutAdvancingTheVersion(t *testing.T) {
	pool := openPool(t)
	tenant := tenantFor(t)
	ctx := scopedCtx(t, tenant)
	store := crpg.New(pool)

	if _, _, err := store.CreateOrGet(ctx, "key-1", mergeRequest(tenant, "mr-1")); err != nil {
		t.Fatalf("create: %v", err)
	}

	projected := mergeRequest(tenant, "mr-1")
	projected.HeadRevision, projected.TargetRevision = "sha-head-2", "sha-target-2"
	if err := store.SaveProjection(ctx, projected); err != nil {
		t.Fatalf("project: %v", err)
	}

	got, err := store.Get(ctx, "mr-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.HeadRevision != "sha-head-2" || got.TargetRevision != "sha-target-2" {
		t.Errorf("the projection did not land: head=%q target=%q", got.HeadRevision, got.TargetRevision)
	}
	if got.Version != 1 {
		t.Errorf("the projection advanced the version to %d — a push must not invalidate a review mid-submission", got.Version)
	}
	if got.Title != "Add the thing" {
		t.Errorf("the projection rewrote more than the projected fields: %+v", got)
	}
}

// AC10: a caller edit landing between the event path's read and its projection
// does NOT surface a conflict — the projection is a fact about the ref and the
// fact still holds, so the write re-reads and re-applies at the row's current
// version, leaving the caller's own edit intact.
func TestAProjectionWhoseRowMovedReReadsAndReApplies(t *testing.T) {
	pool := openPool(t)
	tenant := tenantFor(t)
	ctx := scopedCtx(t, tenant)
	store := crpg.New(pool)

	if _, _, err := store.CreateOrGet(ctx, "key-1", mergeRequest(tenant, "mr-1")); err != nil {
		t.Fatalf("create: %v", err)
	}

	// The stale read the event path holds: version 1. A caller edit then lands,
	// bumping the stored row to version 2 under a new title.
	stale := mergeRequest(tenant, "mr-1")
	editor := mergeRequest(tenant, "mr-1")
	editor.Title, editor.Version = "renamed by a caller edit", 2
	if err := store.Save(ctx, editor); err != nil {
		t.Fatalf("the caller edit: %v", err)
	}

	stale.HeadRevision, stale.TargetRevision = "sha-head-2", "sha-target-2"
	if err := store.SaveProjection(ctx, stale); err != nil {
		t.Fatalf("the projection surfaced a conflict instead of re-applying: %v", err)
	}

	got, err := store.Get(ctx, "mr-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.HeadRevision != "sha-head-2" || got.TargetRevision != "sha-target-2" {
		t.Errorf("the re-applied projection did not land: head=%q target=%q", got.HeadRevision, got.TargetRevision)
	}
	if got.Title != "renamed by a caller edit" {
		t.Errorf("the re-apply overwrote the caller's edit: %q", got.Title)
	}
	if got.Version != 2 {
		t.Errorf("the re-apply advanced the version to %d", got.Version)
	}
}

// AC10's guard still refuses what is not there: a projection for a merge request
// that does not exist is an error, not a silent success.
func TestAProjectionForAMergeRequestThatIsNotThereIsRefused(t *testing.T) {
	pool := openPool(t)
	tenant := tenantFor(t)
	ctx := scopedCtx(t, tenant)

	projected := mergeRequest(tenant, "mr-missing")
	if err := crpg.New(pool).SaveProjection(ctx, projected); err == nil {
		t.Error("a projection for a merge request that is not there was accepted")
	}
}

// SPEC-0064 AC6: the durable store round-trips DRAFT unchanged — the column is
// text, the state is data, and no migration was needed.
func TestADraftRoundTrips(t *testing.T) {
	pool := openPool(t)
	tenant := tenantFor(t)
	ctx := scopedCtx(t, tenant)
	store := crpg.New(pool)

	draft := mergeRequest(tenant, "mr-draft")
	draft.State = api.StateDraft
	if _, _, err := store.CreateOrGet(ctx, "key-draft", draft); err != nil {
		t.Fatalf("create draft: %v", err)
	}
	got, err := store.Get(ctx, "mr-draft")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.State != api.StateDraft {
		t.Fatalf("state = %s, want DRAFT to round-trip", got.State)
	}
	// The open lookups the ref-update path projects through never list a draft.
	open, err := store.OpenForTarget(ctx, tenant, "repo-a", "refs/heads/main")
	if err != nil || len(open) != 0 {
		t.Fatalf("a draft appeared in the open lookups: %+v (%v)", open, err)
	}
}

// AC1/AC2: the open-merge-request lookups the ref-update path depends on return what they should,
// and nothing that is closed.
func TestOpenLookupsSeeOnlyOpenMergeRequests(t *testing.T) {
	pool := openPool(t)
	tenant := tenantFor(t)
	ctx := scopedCtx(t, tenant)
	store := crpg.New(pool)

	if _, _, err := store.CreateOrGet(ctx, "key-open", mergeRequest(tenant, "mr-open")); err != nil {
		t.Fatalf("create open: %v", err)
	}
	merged := mergeRequest(tenant, "mr-merged")
	if _, _, err := store.CreateOrGet(ctx, "key-merged", merged); err != nil {
		t.Fatalf("create merged: %v", err)
	}
	merged.State, merged.Version = api.StateMerged, 2
	if err := store.Save(ctx, merged); err != nil {
		t.Fatalf("merge it: %v", err)
	}

	byTarget, err := store.OpenForTarget(ctx, tenant, "repo-a", "refs/heads/main")
	if err != nil {
		t.Fatalf("open for target: %v", err)
	}
	if len(byTarget) != 1 || byTarget[0].ID != "mr-open" {
		t.Fatalf("open-by-target returned %+v", byTarget)
	}
	bySource, err := store.OpenForSource(ctx, tenant, "repo-a", "refs/heads/feature")
	if err != nil {
		t.Fatalf("open for source: %v", err)
	}
	if len(bySource) != 1 || bySource[0].ID != "mr-open" {
		t.Fatalf("open-by-source returned %+v", bySource)
	}
}
