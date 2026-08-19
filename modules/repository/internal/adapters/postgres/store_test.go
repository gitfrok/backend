package postgres_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	repopg "github.com/gitfrok/backend/modules/repository/internal/adapters/postgres"
	"github.com/gitfrok/backend/modules/repository/internal/domain"
	"github.com/gitfrok/backend/platform/db"
	"github.com/gitfrok/backend/platform/tenancy"
)

// SPEC-0052 AC1, AC2, AC3 against a real Postgres.
//
// The claims are about what survives a restart and what the DATABASE permits.
// Durability is a statement about committed rows and isolation is a statement
// about RLS policies; neither exists in process memory, so an in-memory fake
// would prove that a fake behaves.
//
//	kubectl port-forward svc/postgres 15432:5432   (minikube profile gitfrok)
//	TEST_DATABASE_URL='postgres://gitfrok_app:gitfrok_app@127.0.0.1:15432/gitfrok' \
//	TEST_SUPERUSER_DATABASE_URL='postgres://postgres:postgres@127.0.0.1:15432/gitfrok' \
//	  go test -race ./modules/repository/internal/adapters/postgres/...
//
// **Carried limit 5 applies here and it matters more than usual.** Without
// TEST_DATABASE_URL these tests SKIP, and the tests that skip are exactly the
// cross-tenant isolation proofs. A green run that skipped them has proven
// nothing about isolation — count the skips before believing the exit record.

var runID = fmt.Sprintf("%d", time.Now().UnixNano()%1_000_000_000)

func TestMain(m *testing.M) {
	if dsn := os.Getenv("TEST_SUPERUSER_DATABASE_URL"); dsn != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		err := applyMigration(ctx, dsn, "migrations/0001_repository_registry.sql")
		if err == nil {
			// 0002 adds the settings columns (T-0068, SPEC-0057). Applied in order, because
			// it ALTERs the table 0001 creates.
			err = applyMigration(ctx, dsn, "migrations/0002_repository_settings.sql")
		}
		cancel()
		if err != nil {
			fmt.Fprintf(os.Stderr, "repository postgres tests: could not self-apply migration: %v\n", err)
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

// tenantFor gives each test its own tenant within the run: there is no delete
// path for the app role by design, so the fixture moves instead.
func tenantFor(t *testing.T) domain.TenantID {
	t.Helper()
	safe := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		default:
			return '-'
		}
	}, t.Name())
	// A tenant ID is capped at 64 characters (platform/tenancy), and some of
	// these test names are long enough to blow past it once the run ID and a
	// "-other" suffix are appended. Truncating here keeps the fixture legible
	// while staying inside the rule the platform actually enforces.
	if len(safe) > 32 {
		safe = safe[:32]
	}
	return domain.TenantID(fmt.Sprintf("t-%s-%s", safe, runID))
}

func repo(tenant domain.TenantID, id, name string) domain.Repository {
	return domain.Repository{Tenant: tenant, ID: domain.RepoID(id), Name: name}
}

// AC1: the registry survives the process that wrote it. The store is thrown
// away and rebuilt against the same database, which is what a restart is.
func TestRegistrySurvivesTheStoreThatWroteIt(t *testing.T) {
	pool := openPool(t)
	tenant := tenantFor(t)

	writer := repopg.New(pool)
	if err := writer.Save(t.Context(), repo(tenant, "alpha", "Alpha")); err != nil {
		t.Fatalf("save: %v", err)
	}

	// A new Store over the same pool is the reader a restarted plane would build.
	reader := repopg.New(pool)
	got, err := reader.Load(t.Context(), tenant, "alpha")
	if err != nil {
		t.Fatalf("load after rebuild: %v", err)
	}
	if got.Name != "Alpha" || got.Tenant != tenant {
		t.Fatalf("loaded %+v, want Alpha in %s", got, tenant)
	}
}

// AC3: a repository of another tenant is ABSENT, not forbidden — not
// loadable, not a candidate, not countable.
func TestAnotherTenantsRepositoryIsAbsentRatherThanForbidden(t *testing.T) {
	pool := openPool(t)
	mine := tenantFor(t)
	theirs := domain.TenantID(string(mine) + "-other")
	store := repopg.New(pool)

	if err := store.Save(t.Context(), repo(theirs, "theirs-1", "Theirs")); err != nil {
		t.Fatalf("seeding the other tenant: %v", err)
	}

	if _, err := store.Load(t.Context(), mine, "theirs-1"); err == nil {
		t.Fatal("another tenant's repository must not be loadable")
	} else if strings.Contains(strings.ToLower(err.Error()), "forbidden") ||
		strings.Contains(strings.ToLower(err.Error()), "denied") {
		t.Fatalf("the refusal names the reason and so admits existence: %v", err)
	}

	candidates, err := store.Candidates(t.Context(), mine, "", 100)
	if err != nil {
		t.Fatalf("candidates: %v", err)
	}
	for _, c := range candidates {
		if c.ID == "theirs-1" {
			t.Fatal("another tenant's repository appeared as a candidate")
		}
	}
}

// AC3, the other direction: a transaction scoped to one tenant may not be
// asked about another, and the refusal happens before any database work.
func TestACallForAnotherTenantUnderAScopedContextIsRefused(t *testing.T) {
	pool := openPool(t)
	tenant := tenantFor(t)
	store := repopg.New(pool)

	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(string(tenant)))
	if _, err := store.Candidates(ctx, domain.TenantID(string(tenant)+"-other"), "", 10); err == nil {
		t.Fatal("a call for another tenant under a scoped context must be refused")
	}
}

// Candidates walks in ascending ID order and honours the cursor, which is what
// makes the list's paging a position in the ordering rather than an offset
// into an answer.
func TestCandidatesWalkAscendingAndHonourTheCursor(t *testing.T) {
	pool := openPool(t)
	tenant := tenantFor(t)
	store := repopg.New(pool)

	for _, id := range []string{"c", "a", "b"} {
		if err := store.Save(t.Context(), repo(tenant, id, strings.ToUpper(id))); err != nil {
			t.Fatalf("save %s: %v", id, err)
		}
	}

	first, err := store.Candidates(t.Context(), tenant, "", 2)
	if err != nil {
		t.Fatalf("candidates: %v", err)
	}
	if len(first) != 2 || first[0].ID != "a" || first[1].ID != "b" {
		t.Fatalf("first page %v, want [a b]", idsOf(first))
	}

	next, err := store.Candidates(t.Context(), tenant, "b", 2)
	if err != nil {
		t.Fatalf("candidates after b: %v", err)
	}
	if len(next) != 1 || next[0].ID != "c" {
		t.Fatalf("second page %v, want [c]", idsOf(next))
	}
}

// Re-registering the same repository is the same fact stated twice, not a
// duplicate-key failure that leaves the caller unsure whether it exists.
func TestSavingTheSameRepositoryTwiceConverges(t *testing.T) {
	pool := openPool(t)
	tenant := tenantFor(t)
	store := repopg.New(pool)

	if err := store.Save(t.Context(), repo(tenant, "alpha", "Alpha")); err != nil {
		t.Fatalf("first save: %v", err)
	}
	if err := store.Save(t.Context(), repo(tenant, "alpha", "Alpha renamed")); err != nil {
		t.Fatalf("second save: %v", err)
	}
	got, err := store.Load(t.Context(), tenant, "alpha")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.Name != "Alpha renamed" {
		t.Fatalf("name %q, want the converged one", got.Name)
	}
}

func TestAnUnknownRepositoryIsNotFound(t *testing.T) {
	pool := openPool(t)
	store := repopg.New(pool)
	if _, err := store.Load(t.Context(), tenantFor(t), "nope"); err == nil {
		t.Fatal("an unknown repository must not load")
	}
}

func idsOf(rs []domain.Repository) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, string(r.ID))
	}
	return out
}
