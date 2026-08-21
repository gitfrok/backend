package postgres_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/gitfrok/backend/modules/notifications/api"
	notpg "github.com/gitfrok/backend/modules/notifications/internal/adapters/postgres"
	notificationsapp "github.com/gitfrok/backend/modules/notifications/internal/app"
	"github.com/gitfrok/backend/platform/db"
	"github.com/gitfrok/backend/platform/tenancy"
)

// SPEC-0063 against a real Postgres.
//
// The claims are about what survives a process and what the DATABASE permits:
// idempotency is a statement about committed rows under replay (AC4), tenant
// isolation is a statement about RLS policies (AC5), and exactness of count
// and mark-read is a statement about what one recipient's rows can do to
// another's (AC6). None of that exists in process memory.
//
//	kubectl port-forward svc/postgres 15432:5432   (minikube profile gitfrok)
//	TEST_DATABASE_URL='postgres://gitfrok_app:gitfrok_app@127.0.0.1:15432/gitfrok' \
//	TEST_SUPERUSER_DATABASE_URL='postgres://postgres:postgres@127.0.0.1:15432/gitfrok' \
//	  go test -race ./modules/notifications/internal/adapters/postgres/...
//
// **Carried limit 5 applies.** Without TEST_DATABASE_URL these SKIP.

var runID = fmt.Sprintf("%d", time.Now().UnixNano()%1_000_000_000)

func TestMain(m *testing.M) {
	if dsn := os.Getenv("TEST_SUPERUSER_DATABASE_URL"); dsn != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		err := applyMigration(ctx, dsn, "migrations/0001_notifications.sql")
		cancel()
		if err != nil {
			fmt.Fprintf(os.Stderr, "notifications postgres tests: could not self-apply migration: %v\n", err)
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
	return safe + "-" + runID
}

// AC4 — at-least-once delivery from the bus, exactly-once rows in Postgres.
func TestReplayedEventMakesOneRow(t *testing.T) {
	pool := openPool(t)
	store := notpg.New(pool)
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenantFor(t)))

	row := func(suffix string) notificationsapp.Row {
		return notificationsapp.Row{
			EventID: "evt-replay-" + runID + ":" + suffix, TenantID: tenantFor(t),
			RecipientID: suffix, Kind: api.KindMergeRequestMerged,
			RepositoryID: "repo-1", MergeRequestID: "mr-1", ActorID: "merger",
			OccurredAt: time.Now().UTC(),
		}
	}
	batch := []notificationsapp.Row{row("author"), row("rev-a"), row("rev-b")}
	for range 3 { // three deliveries of the same event
		if err := store.Append(ctx, batch); err != nil {
			t.Fatal(err)
		}
	}
	page, err := store.List(ctx, tenantFor(t), "author", 100, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Notifications) != 1 {
		t.Fatalf("rows after 3 deliveries = %d, want exactly 1", len(page.Notifications))
	}
	if page.Notifications[0].Read {
		t.Fatal("fresh row reports read")
	}
}

// AC5 — another tenant's notifications are absent, not forbidden; every query
// runs inside the tenant-scoped transaction so forced RLS holds.
func TestAnotherTenantsRowsAreAbsent(t *testing.T) {
	pool := openPool(t)
	store := notpg.New(pool)
	tenant := tenantFor(t)
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))

	if err := store.Append(ctx, []notificationsapp.Row{{
		EventID: "evt-iso-" + runID + ":author", TenantID: tenant, RecipientID: "author",
		Kind: api.KindReviewSubmitted, RepositoryID: "repo-1", MergeRequestID: "mr-1",
		ActorID: "reviewer", OccurredAt: time.Now().UTC(),
	}}); err != nil {
		t.Fatal(err)
	}

	otherCtx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant+"-other"))
	page, err := store.List(otherCtx, tenant, "author", 100, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Notifications) != 0 {
		t.Fatalf("cross-tenant list leaked %+v", page.Notifications)
	}
	if n, err := store.UnreadCount(otherCtx, tenant, "author"); err != nil || n != 0 {
		t.Fatalf("cross-tenant unread = %d, %v; want 0", n, err)
	}
	if _, err := store.MarkRead(otherCtx, tenant, "author", "evt-iso-"+runID+":author", time.Now().UTC()); err == nil {
		t.Fatal("cross-tenant mark-read succeeded")
	}
}

// AC6 — marking one marks one; the count never counts another recipient.
func TestMarkReadIsExactPerRecipient(t *testing.T) {
	pool := openPool(t)
	store := notpg.New(pool)
	tenant := tenantFor(t)
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))

	now := time.Now().UTC()
	rows := make([]notificationsapp.Row, 0, 3)
	for _, suffix := range []string{"a", "b"} {
		rows = append(rows, notificationsapp.Row{
			EventID:  fmt.Sprintf("evt-exact-%s-%s:%s", runID, "n", suffix),
			TenantID: tenant, RecipientID: "recipient-" + suffix,
			Kind: api.KindFindingsAttributed, RepositoryID: "repo-1",
			MergeRequestID: "mr-1", OccurredAt: now,
		})
	}
	// Two events for recipient-a, one for recipient-b.
	rows = append(rows, notificationsapp.Row{
		EventID: fmt.Sprintf("evt-exact-%s-m:b", runID), TenantID: tenant,
		RecipientID: "recipient-a", Kind: api.KindFindingsAttributed,
		RepositoryID: "repo-1", MergeRequestID: "mr-1", OccurredAt: now,
	})
	if err := store.Append(ctx, rows); err != nil {
		t.Fatal(err)
	}

	if n, err := store.UnreadCount(ctx, tenant, "recipient-a"); err != nil || n != 2 {
		t.Fatalf("unread a = %d, %v; want 2", n, err)
	}
	if n, err := store.UnreadCount(ctx, tenant, "recipient-b"); err != nil || n != 1 {
		t.Fatalf("unread b = %d, %v; want 1 (never counts another recipient)", n, err)
	}

	marked, err := store.MarkRead(ctx, tenant, "recipient-a", fmt.Sprintf("evt-exact-%s-n:a", runID), now)
	if err != nil {
		t.Fatal(err)
	}
	if !marked.Read {
		t.Fatal("marked row reports unread")
	}
	if n, _ := store.UnreadCount(ctx, tenant, "recipient-a"); n != 1 {
		t.Fatalf("unread a after mark = %d, want exactly 1 fewer", n)
	}
	if n, _ := store.UnreadCount(ctx, tenant, "recipient-b"); n != 1 {
		t.Fatal("marking a changed b")
	}
	// Re-marking is idempotent and returns the row.
	again, err := store.MarkRead(ctx, tenant, "recipient-a", marked.ID, now)
	if err != nil || !again.Read {
		t.Fatalf("re-mark = %+v, %v", again, err)
	}
}

// The creator projection round-trips within its tenant and stays absent
// across tenants (the findings notification depends on it).
func TestCreatorProjectionRoundTrips(t *testing.T) {
	pool := openPool(t)
	store := notpg.New(pool)
	tenant := tenantFor(t)
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))

	if creator, err := store.Creator(ctx, tenant, "repo-1", "mr-9"); err != nil || creator != "" {
		t.Fatalf("unknown creator = %q, %v; want empty", creator, err)
	}
	if err := store.PutCreator(ctx, tenant, "repo-1", "mr-9", "author"); err != nil {
		t.Fatal(err)
	}
	if creator, err := store.Creator(ctx, tenant, "repo-1", "mr-9"); err != nil || creator != "author" {
		t.Fatalf("creator = %q, %v; want author", creator, err)
	}
	other := tenancy.WithTenant(t.Context(), tenancy.ID(tenant+"-other"))
	if creator, err := store.Creator(other, tenant, "repo-1", "mr-9"); err != nil || creator != "" {
		t.Fatalf("cross-tenant creator = %q, %v; want absent", creator, err)
	}
}
