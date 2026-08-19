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

	"github.com/gitfrok/backend/modules/release/api"
	releasepg "github.com/gitfrok/backend/modules/release/internal/adapters/postgres"
	"github.com/gitfrok/backend/modules/release/internal/app"
	"github.com/gitfrok/backend/platform/db"
	"github.com/gitfrok/backend/platform/tenancy"
)

// SPEC-0056 AC3, AC4, AC5 against a real Postgres.
//
//	kubectl port-forward svc/postgres 15432:5432
//	TEST_DATABASE_URL='postgres://gitfrok_app:gitfrok_app@127.0.0.1:15432/gitfrok' \
//	TEST_SUPERUSER_DATABASE_URL='postgres://postgres:postgres@127.0.0.1:15432/gitfrok' \
//	  go test -race ./modules/release/internal/adapters/postgres/...
//
// Carried limit 5: without TEST_DATABASE_URL these SKIP, and the ones that skip
// are the isolation proofs. Count the skips before believing a green run.

var runID = fmt.Sprintf("%d", time.Now().UnixNano()%1_000_000_000)

func TestMain(m *testing.M) {
	if dsn := os.Getenv("TEST_SUPERUSER_DATABASE_URL"); dsn != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		if sql, err := os.ReadFile("migrations/0001_releases.sql"); err == nil {
			if pool, poolErr := pgxpool.New(ctx, dsn); poolErr == nil {
				if _, execErr := pool.Exec(ctx, string(sql)); execErr != nil {
					fmt.Fprintf(os.Stderr, "release postgres tests: could not self-apply migration: %v\n", execErr)
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
	if len(safe) > 26 {
		safe = safe[:26]
	}
	return fmt.Sprintf("t-%s-%s", safe, runID)
}

func release(tenant, tag, commit string, at time.Time) api.Release {
	return api.Release{
		TenantID: tenant, RepositoryID: "repo-1", Tag: tag, PublishedCommit: commit,
		Notes: "what changed", PublishedBy: "dev@gitsaas.test",
		PublishedAt: at.UTC().Truncate(time.Microsecond),
	}
}

// AC5: the record survives the process that wrote it.
func TestAReleaseSurvivesTheStoreThatWroteIt(t *testing.T) {
	pool := openPool(t)
	tenant := tenantFor(t)

	if err := releasepg.New(pool).Insert(t.Context(), release(tenant, "v1.0.0", "abc123", time.Now())); err != nil {
		t.Fatalf("insert: %v", err)
	}
	got, err := releasepg.New(pool).Get(t.Context(), tenant, "repo-1", "v1.0.0")
	if err != nil {
		t.Fatalf("get after rebuild: %v", err)
	}
	if got.PublishedCommit != "abc123" || got.Notes != "what changed" {
		t.Fatalf("read back %+v", got)
	}
}

// AC3: a tag has at most one release, and the database is what says so.
func TestPublishingTheSameTagTwiceIsRefused(t *testing.T) {
	pool := openPool(t)
	tenant := tenantFor(t)
	store := releasepg.New(pool)

	if err := store.Insert(t.Context(), release(tenant, "v1.0.0", "abc123", time.Now())); err != nil {
		t.Fatalf("first: %v", err)
	}
	err := store.Insert(t.Context(), release(tenant, "v1.0.0", "def456", time.Now()))
	if !errors.Is(err, api.ErrAlreadyPublished) {
		t.Fatalf("want ErrAlreadyPublished, got %v", err)
	}

	// And the first release is untouched — a refused second publish must not
	// have moved what the first one describes.
	got, err := store.Get(t.Context(), tenant, "repo-1", "v1.0.0")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.PublishedCommit != "abc123" {
		t.Fatalf("the refused publish changed the record: %+v", got)
	}
}

// AC4: notes are editable; the tag and the commit are not.
func TestUpdatingNotesLeavesTheTagAndCommitAlone(t *testing.T) {
	pool := openPool(t)
	tenant := tenantFor(t)
	store := releasepg.New(pool)

	if err := store.Insert(t.Context(), release(tenant, "v1.0.0", "abc123", time.Now())); err != nil {
		t.Fatalf("insert: %v", err)
	}
	edited := time.Now().UTC().Truncate(time.Microsecond)
	got, err := store.UpdateNotes(t.Context(), tenant, "repo-1", "v1.0.0", "corrected prose", edited)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if got.Notes != "corrected prose" {
		t.Fatalf("notes %q", got.Notes)
	}
	if got.PublishedCommit != "abc123" || got.Tag != "v1.0.0" {
		t.Fatalf("editing prose moved the release: %+v", got)
	}
	if got.NotesUpdatedAt.IsZero() {
		t.Fatal("an edit must record when it happened")
	}
}

func TestNotesUpdatedAtIsZeroUntilTheFirstEdit(t *testing.T) {
	pool := openPool(t)
	tenant := tenantFor(t)
	store := releasepg.New(pool)
	if err := store.Insert(t.Context(), release(tenant, "v1.0.0", "abc123", time.Now())); err != nil {
		t.Fatalf("insert: %v", err)
	}
	got, err := store.Get(t.Context(), tenant, "repo-1", "v1.0.0")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !got.NotesUpdatedAt.IsZero() {
		t.Fatalf("an unedited release reports an edit time: %v", got.NotesUpdatedAt)
	}
}

func TestUpdatingAnUnknownReleaseIsNotFound(t *testing.T) {
	pool := openPool(t)
	store := releasepg.New(pool)
	_, err := store.UpdateNotes(t.Context(), tenantFor(t), "repo-1", "v9.9.9", "x", time.Now())
	if !errors.Is(err, api.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

// AC5: a release of another tenant is absent, not forbidden.
func TestAnotherTenantsReleaseIsAbsent(t *testing.T) {
	pool := openPool(t)
	mine, theirs := tenantFor(t), tenantFor(t)+"-other"
	store := releasepg.New(pool)

	if err := store.Insert(t.Context(), release(theirs, "v1.0.0", "abc123", time.Now())); err != nil {
		t.Fatalf("seeding: %v", err)
	}
	_, err := store.Get(t.Context(), mine, "repo-1", "v1.0.0")
	if !errors.Is(err, api.ErrNotFound) {
		t.Fatalf("another tenant's release was readable or named a reason: %v", err)
	}

	page, err := store.Page(t.Context(), mine, "repo-1", app.Cursor{}, 100)
	if err != nil {
		t.Fatalf("page: %v", err)
	}
	if len(page) != 0 {
		t.Fatalf("another tenant's release was listed: %+v", page)
	}
}

func TestACallForAnotherTenantUnderAScopedContextIsRefused(t *testing.T) {
	pool := openPool(t)
	tenant := tenantFor(t)
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	if _, err := releasepg.New(pool).Page(ctx, tenant+"-other", "repo-1", app.Cursor{}, 10); err == nil {
		t.Fatal("a call for another tenant under a scoped context must be refused")
	}
}

// The page walks newest first and the cursor is a position in a total order.
func TestThePageWalksNewestFirstAndHonoursTheCursor(t *testing.T) {
	pool := openPool(t)
	tenant := tenantFor(t)
	store := releasepg.New(pool)

	base := time.Now().Add(-time.Hour)
	for i, tag := range []string{"v1.0.0", "v1.1.0", "v1.2.0"} {
		if err := store.Insert(t.Context(), release(tenant, tag, "c"+tag, base.Add(time.Duration(i)*time.Minute))); err != nil {
			t.Fatalf("seed %s: %v", tag, err)
		}
	}
	first, err := store.Page(t.Context(), tenant, "repo-1", app.Cursor{}, 2)
	if err != nil {
		t.Fatalf("page: %v", err)
	}
	if len(first) != 2 || first[0].Tag != "v1.2.0" || first[1].Tag != "v1.1.0" {
		t.Fatalf("first page %v", tags(first))
	}
	next, err := store.Page(t.Context(), tenant, "repo-1",
		app.Cursor{PublishedAt: first[1].PublishedAt, Tag: first[1].Tag}, 2)
	if err != nil {
		t.Fatalf("next: %v", err)
	}
	if len(next) != 1 || next[0].Tag != "v1.0.0" {
		t.Fatalf("second page %v", tags(next))
	}
}

func tags(rs []api.Release) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.Tag)
	}
	return out
}
