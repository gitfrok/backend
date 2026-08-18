package postgres_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/gitfrok/backend/modules/ci/api"
	cipg "github.com/gitfrok/backend/modules/ci/internal/adapters/postgres"
	"github.com/gitfrok/backend/modules/ci/internal/app"
	"github.com/gitfrok/backend/platform/db"
	"github.com/gitfrok/backend/platform/tenancy"
)

// SPEC-0054 AC1, AC2, AC3 against a real Postgres. Durability is a statement
// about committed rows and isolation about RLS policies; neither exists in
// process memory, so a fake would prove that a fake behaves.
//
//	kubectl port-forward svc/postgres 15432:5432
//	TEST_DATABASE_URL='postgres://gitfrok_app:gitfrok_app@127.0.0.1:15432/gitfrok' \
//	TEST_SUPERUSER_DATABASE_URL='postgres://postgres:postgres@127.0.0.1:15432/gitfrok' \
//	  go test -race ./modules/ci/internal/adapters/postgres/...
//
// Carried limit 5: without TEST_DATABASE_URL these SKIP, and the ones that skip
// are the isolation proofs. Count the skips before believing a green run.

var runID = fmt.Sprintf("%d", time.Now().UnixNano()%1_000_000_000)

func TestMain(m *testing.M) {
	if dsn := os.Getenv("TEST_SUPERUSER_DATABASE_URL"); dsn != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		sql, err := os.ReadFile("migrations/0001_ci_jobs.sql")
		if err == nil {
			if pool, poolErr := pgxpool.New(ctx, dsn); poolErr == nil {
				if _, execErr := pool.Exec(ctx, string(sql)); execErr != nil {
					fmt.Fprintf(os.Stderr, "ci postgres tests: could not self-apply migration: %v\n", execErr)
				}
				pool.Close()
			}
		}
		cancel()
	}
	os.Exit(m.Run())
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
	if len(safe) > 28 {
		safe = safe[:28]
	}
	return fmt.Sprintf("t-%s-%s", safe, runID)
}

func job(tenant, id, repo string, queued time.Time) api.Job {
	return api.Job{
		ID: id, TenantID: tenant, RepositoryID: repo, ActorID: "actor-1",
		Ref: "refs/heads/main", CommitSHA: "abc123", Trigger: api.TriggerRefUpdated,
		ActorRoles: []string{"member"}, State: api.JobState("QUEUED"),
		QueuedAt: queued.UTC().Truncate(time.Microsecond),
	}
}

// AC1: the history survives the process that wrote it.
func TestAJobSurvivesTheStoreThatWroteIt(t *testing.T) {
	pool := openPool(t)
	tenant := tenantFor(t)

	writer := cipg.New(pool)
	if _, _, err := writer.CreateOrGet(t.Context(), "key-1", job(tenant, "job-1", "repo-1", time.Now())); err != nil {
		t.Fatalf("create: %v", err)
	}

	reader := cipg.New(pool)
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	got, err := reader.Get(ctx, "job-1")
	if err != nil {
		t.Fatalf("get after rebuild: %v", err)
	}
	if got.RepositoryID != "repo-1" || got.State != api.JobState("QUEUED") {
		t.Fatalf("read back %+v", got)
	}
}

// The idempotency rule is the database's: a replayed key returns the existing
// job rather than creating a second one.
func TestAReplayedKeyReturnsTheExistingJob(t *testing.T) {
	pool := openPool(t)
	tenant := tenantFor(t)
	store := cipg.New(pool)

	first, created, err := store.CreateOrGet(t.Context(), "key-replay", job(tenant, "job-a", "repo-1", time.Now()))
	if err != nil || !created {
		t.Fatalf("first create: %v created=%v", err, created)
	}
	second, created, err := store.CreateOrGet(t.Context(), "key-replay", job(tenant, "job-b", "repo-1", time.Now()))
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if created {
		t.Fatal("a replay created a second job")
	}
	if second.ID != first.ID {
		t.Fatalf("replay returned %s, want %s", second.ID, first.ID)
	}
}

// AC3: another tenant's job is absent, not forbidden.
func TestAnotherTenantsJobIsAbsent(t *testing.T) {
	pool := openPool(t)
	mine, theirs := tenantFor(t), tenantFor(t)+"-other"
	store := cipg.New(pool)

	if _, _, err := store.CreateOrGet(t.Context(), "key-theirs", job(theirs, "job-theirs", "repo-x", time.Now())); err != nil {
		t.Fatalf("seeding: %v", err)
	}

	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(mine))
	if _, err := store.Get(ctx, "job-theirs"); err == nil {
		t.Fatal("another tenant's job was gettable")
	} else if lowered := strings.ToLower(err.Error()); strings.Contains(lowered, "forbidden") || strings.Contains(lowered, "denied") {
		t.Fatalf("the refusal names a reason and so admits existence: %v", err)
	}

	candidates, err := store.Candidates(t.Context(), mine, "", app.ListCursor{}, 100)
	if err != nil {
		t.Fatalf("candidates: %v", err)
	}
	for _, c := range candidates {
		if c.ID == "job-theirs" {
			t.Fatal("another tenant's job appeared as a candidate")
		}
	}
}

func TestACallForAnotherTenantUnderAScopedContextIsRefused(t *testing.T) {
	pool := openPool(t)
	tenant := tenantFor(t)
	store := cipg.New(pool)
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	if _, err := store.Candidates(ctx, tenant+"-other", "", app.ListCursor{}, 10); err == nil {
		t.Fatal("a call for another tenant under a scoped context must be refused")
	}
}

// Candidates walk newest first, and the cursor is a position in that total
// order rather than an offset into an answer.
func TestCandidatesWalkNewestFirstAndHonourTheCursor(t *testing.T) {
	pool := openPool(t)
	tenant := tenantFor(t)
	store := cipg.New(pool)

	base := time.Now().Add(-time.Hour)
	for i, id := range []string{"job-old", "job-mid", "job-new"} {
		if _, _, err := store.CreateOrGet(t.Context(), "key-"+id,
			job(tenant, id, "repo-1", base.Add(time.Duration(i)*time.Minute))); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}

	first, err := store.Candidates(t.Context(), tenant, "", app.ListCursor{}, 2)
	if err != nil {
		t.Fatalf("candidates: %v", err)
	}
	if len(first) != 2 || first[0].ID != "job-new" || first[1].ID != "job-mid" {
		t.Fatalf("first page %v, want newest first", ids(first))
	}

	next, err := store.Candidates(t.Context(), tenant, "",
		app.ListCursor{QueuedAt: first[1].QueuedAt, JobID: first[1].ID}, 2)
	if err != nil {
		t.Fatalf("second page: %v", err)
	}
	if len(next) != 1 || next[0].ID != "job-old" {
		t.Fatalf("second page %v", ids(next))
	}
}

func TestCandidatesNarrowToOneRepositoryWhenAsked(t *testing.T) {
	pool := openPool(t)
	tenant := tenantFor(t)
	store := cipg.New(pool)

	now := time.Now()
	for i, spec := range [][2]string{{"job-r1", "repo-1"}, {"job-r2", "repo-2"}} {
		if _, _, err := store.CreateOrGet(t.Context(), "key-"+spec[0],
			job(tenant, spec[0], spec[1], now.Add(time.Duration(i)*time.Second))); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	got, err := store.Candidates(t.Context(), tenant, "repo-2", app.ListCursor{}, 10)
	if err != nil {
		t.Fatalf("candidates: %v", err)
	}
	if len(got) != 1 || got[0].ID != "job-r2" {
		t.Fatalf("narrowed to %v", ids(got))
	}
}

func TestSaveAdvancesAJobAndRefusesAnUnknownOne(t *testing.T) {
	pool := openPool(t)
	tenant := tenantFor(t)
	store := cipg.New(pool)

	created := job(tenant, "job-save", "repo-1", time.Now())
	if _, _, err := store.CreateOrGet(t.Context(), "key-save", created); err != nil {
		t.Fatalf("create: %v", err)
	}
	finished := time.Now().UTC().Truncate(time.Microsecond)
	created.State, created.FinishedAt, created.OutcomeSummary = api.JobState("SUCCEEDED"), &finished, "all green"
	if err := store.Save(t.Context(), created); err != nil {
		t.Fatalf("save: %v", err)
	}

	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	got, err := store.Get(ctx, "job-save")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.State != api.JobState("SUCCEEDED") || got.OutcomeSummary != "all green" {
		t.Fatalf("advanced to %+v", got)
	}

	// A Save for a job that does not exist must not quietly create one.
	if err := store.Save(t.Context(), job(tenant, "job-missing", "repo-1", time.Now())); err == nil {
		t.Fatal("saving an unknown job silently created it")
	}
}

func ids(jobs []api.Job) []string {
	out := make([]string, 0, len(jobs))
	for _, j := range jobs {
		out = append(out, j.ID)
	}
	return out
}
