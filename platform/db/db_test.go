package db_test

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/gitfrok/backend/platform/audit"
	"github.com/gitfrok/backend/platform/bus"
	"github.com/gitfrok/backend/platform/db"
	"github.com/gitfrok/backend/platform/tenancy"
)

// SPEC-0001 acceptance criteria, as tests. AC1 and AC2 are covered here; AC3 (audit event on a
// cross-tenant write) and AC4 (migration lint) are tracked separately — see the task file.
//
// These need a real Postgres with the RLS baseline applied, because that is the whole claim: an
// in-memory fake would prove that a fake denies things. TEST_DATABASE_URL must name a role that is
// NOT superuser and NOT BYPASSRLS; db.Open refuses anything else, which is itself asserted below.
//
//	kubectl port-forward -n default deploy/postgres 15432:5432
//	TEST_DATABASE_URL='postgres://gitfrok_app:gitfrok_app@127.0.0.1:15432/gitfrok' go test ./platform/db/...

const (
	tenantA = tenancy.ID("tenant-a-t0004")
	tenantB = tenancy.ID("tenant-b-t0004")
)

func dsn(t *testing.T) string {
	t.Helper()
	v := os.Getenv("TEST_DATABASE_URL")
	if v == "" {
		t.Skip("TEST_DATABASE_URL not set — integration test needs a Postgres with the SPEC-0001 RLS baseline")
	}
	return v
}

func openPool(t *testing.T) (*db.Pool, context.Context) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	pool, err := db.Open(ctx, dsn(t))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool, ctx
}

// seed inserts one row per tenant and removes them afterwards. Each tenant's own row is written
// under its own scope, which is the only way the policy's WITH CHECK will accept it.
func seed(t *testing.T, pool *db.Pool, ctx context.Context) {
	t.Helper()
	for _, id := range []tenancy.ID{tenantA, tenantB} {
		tctx := tenancy.WithTenant(ctx, id)
		err := pool.InTx(tctx, func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx,
				`INSERT INTO tenant.tenants (id, name) VALUES ($1, $2)
				 ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name`,
				string(id), "T-0004 fixture")
			return err
		})
		if err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}
	t.Cleanup(func() {
		for _, id := range []tenancy.ID{tenantA, tenantB} {
			tctx := tenancy.WithTenant(context.Background(), id)
			_ = pool.InTx(tctx, func(ctx context.Context, tx pgx.Tx) error {
				_, err := tx.Exec(ctx, `DELETE FROM tenant.tenants WHERE id = $1`, string(id))
				return err
			})
		}
	})
}

// AC1 (read half): under tenant A, tenant B's row is not visible. Asserted by counting B's row
// specifically rather than comparing totals, so an unrelated row in the table cannot mask a leak.
func TestAC1_TenantCannotReadAnotherTenantsRow(t *testing.T) {
	pool, ctx := openPool(t)
	seed(t, pool, ctx)

	var visible int
	err := pool.InTx(tenancy.WithTenant(ctx, tenantA), func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM tenant.tenants WHERE id = $1`, string(tenantB)).Scan(&visible)
	})
	if err != nil {
		t.Fatalf("query as tenant A: %v", err)
	}
	if visible != 0 {
		t.Errorf("tenant A sees %d row(s) of tenant B — RLS is not isolating (SPEC-0001 AC1)", visible)
	}

	// The same query under B's own scope must find it, or the test above would pass simply because
	// the row was never written.
	var own int
	err = pool.InTx(tenancy.WithTenant(ctx, tenantB), func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM tenant.tenants WHERE id = $1`, string(tenantB)).Scan(&own)
	})
	if err != nil {
		t.Fatalf("query as tenant B: %v", err)
	}
	if own != 1 {
		t.Errorf("tenant B cannot see its own row (got %d) — the fixture or the policy is wrong, and AC1 above proved nothing", own)
	}
}

// AC1 (write half): a write aimed at another tenant's row is rejected. UPDATE is silently
// ineffective under RLS (the row is invisible, so zero rows match), while INSERT trips WITH CHECK
// and errors. Both are asserted, because "no error" and "no effect" are different failures.
func TestAC1_TenantCannotWriteAnotherTenantsRow(t *testing.T) {
	pool, ctx := openPool(t)
	seed(t, pool, ctx)

	var affected int64
	err := pool.InTx(tenancy.WithTenant(ctx, tenantA), func(ctx context.Context, tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE tenant.tenants SET name = 'hijacked' WHERE id = $1`, string(tenantB))
		affected = tag.RowsAffected()
		return err
	})
	if err != nil {
		t.Fatalf("update as tenant A: %v", err)
	}
	if affected != 0 {
		t.Errorf("tenant A updated %d of tenant B's row(s) — RLS is not isolating writes (SPEC-0001 AC1)", affected)
	}

	// Confirm B's data is untouched, so "0 rows affected" is not merely a misreported success.
	var name string
	err = pool.InTx(tenancy.WithTenant(ctx, tenantB), func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT name FROM tenant.tenants WHERE id = $1`, string(tenantB)).Scan(&name)
	})
	if err != nil {
		t.Fatalf("read back as tenant B: %v", err)
	}
	if name == "hijacked" {
		t.Error("tenant B's row was modified by tenant A (SPEC-0001 AC1)")
	}

	// Inserting a row belonging to another tenant must be refused by WITH CHECK.
	err = pool.InTx(tenancy.WithTenant(ctx, tenantA), func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO tenant.tenants (id, name) VALUES ($1, $2)`,
			string(tenantB)+"-forged", "forged by A")
		return err
	})
	if err == nil {
		t.Error("tenant A inserted a row outside its own scope — WITH CHECK is not binding (SPEC-0001 AC1)")
	}
}

// AC2 (application half): no tenant in context is a denial, and it happens before Postgres is
// touched at all.
func TestAC2_MissingTenantContextIsDeniedByTheApplication(t *testing.T) {
	pool, ctx := openPool(t)

	called := false
	err := pool.InTx(ctx, func(context.Context, pgx.Tx) error {
		called = true
		return nil
	})
	if !errors.Is(err, db.ErrNoTenant) {
		t.Errorf("unscoped InTx returned %v, want ErrNoTenant (SPEC-0001 AC2)", err)
	}
	if called {
		t.Error("the callback ran without a tenant scope — an unscoped query reached the database (SPEC-0001 AC2)")
	}

	// An empty or malformed ID must be refused too: it would otherwise reach SET LOCAL, and an
	// empty scope matches nothing, which looks like isolation while actually being a broken request.
	for _, bad := range []tenancy.ID{"", "no spaces allowed", "quote'injection", "tab\there"} {
		err := pool.InTx(tenancy.WithTenant(ctx, bad), func(context.Context, pgx.Tx) error { return nil })
		if err == nil {
			t.Errorf("tenant ID %q was accepted; want rejection", string(bad))
		}
	}
}

// AC2 (database half): the same request without SET LOCAL returns no rows rather than the whole
// table. This is what makes the guarantee survive application code that bypasses this package —
// exactly the scenario the app-layer check above cannot cover.
func TestAC2_DatabaseFailsClosedWithoutTheSessionSetting(t *testing.T) {
	pool, ctx := openPool(t)
	seed(t, pool, ctx)

	var rows int
	err := pool.InTxUnscoped(ctx, "SPEC-0001 AC2: prove RLS denies when app.tenant_id is unset",
		func(ctx context.Context, tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM tenant.tenants`).Scan(&rows)
		})
	if err != nil {
		t.Fatalf("unscoped count: %v", err)
	}
	if rows != 0 {
		t.Errorf("an unscoped transaction read %d row(s); RLS must fail closed to no rows (SPEC-0001 AC2)", rows)
	}
}

// The scoping must not survive the transaction. A pooled connection is reused, so a leaked SET
// would hand one request's tenant to the next borrower — a cross-tenant read that no test using a
// fresh connection per case would ever catch.
func TestScopeDoesNotLeakAcrossTransactionsOnTheSameConnection(t *testing.T) {
	pool, ctx := openPool(t)
	seed(t, pool, ctx)

	if err := pool.InTx(tenancy.WithTenant(ctx, tenantA), func(ctx context.Context, tx pgx.Tx) error {
		var n int
		return tx.QueryRow(ctx, `SELECT count(*) FROM tenant.tenants`).Scan(&n)
	}); err != nil {
		t.Fatalf("scoped tx as A: %v", err)
	}

	var setting *string
	err := pool.InTxUnscoped(ctx, "SPEC-0001: assert SET LOCAL was reverted with the transaction",
		func(ctx context.Context, tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT current_setting('app.tenant_id', true)`).Scan(&setting)
		})
	if err != nil {
		t.Fatalf("read setting: %v", err)
	}
	if setting != nil && *setting != "" {
		t.Errorf("app.tenant_id survived the transaction as %q — SET LOCAL leaked to the pooled connection", *setting)
	}
}

// db.Open must refuse a role that bypasses RLS. Without this, running the suite as `postgres` would
// make every isolation test above pass against a database enforcing nothing at all — the most
// dangerous possible false green.
func TestOpenRefusesARoleThatBypassesRLS(t *testing.T) {
	if os.Getenv("TEST_SUPERUSER_DATABASE_URL") == "" {
		t.Skip("TEST_SUPERUSER_DATABASE_URL not set — cannot verify the BYPASSRLS guard without a superuser DSN")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	pool, err := db.Open(ctx, os.Getenv("TEST_SUPERUSER_DATABASE_URL"))
	if err == nil {
		pool.Close()
		t.Fatal("db.Open accepted a superuser/BYPASSRLS role; the isolation tests would then prove nothing")
	}
}

// AC3: a rejected cross-tenant write emits an audit event.
//
// The assertion is on what reaches the bus, not on a log line: SPEC-0001 AC3 says "emits an audit
// event", and T-0006 will subscribe to exactly this. It also asserts the event carries no row data —
// an audit record of a leak attempt must not itself carry the data (ADR-0007).
func TestAC3_RejectedCrossTenantWriteEmitsAnAuditEvent(t *testing.T) {
	pool, ctx := openPool(t)
	seed(t, pool, ctx)

	b := bus.NewInProcess()
	var got []bus.Event
	b.Subscribe(audit.EventAudit, func(_ context.Context, e bus.Event) error {
		got = append(got, e)
		return nil
	})
	pool.WithAuditBus(b)

	// Tenant A tries to insert a row belonging to someone else; WITH CHECK refuses it.
	err := pool.InTx(tenancy.WithTenant(ctx, tenantA), func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO tenant.tenants (id, name) VALUES ($1, $2)`,
			string(tenantB)+"-forged-ac3", "forged")
		return err
	})
	if err == nil {
		t.Fatal("cross-tenant insert succeeded; AC1 is broken and AC3 is untestable")
	}

	if len(got) != 1 {
		t.Fatalf("got %d audit events, want exactly 1 (SPEC-0001 AC3)", len(got))
	}
	v, ok := got[0].(audit.TenantIsolationViolation)
	if !ok {
		t.Fatalf("audit event has type %T, want TenantIsolationViolation", got[0])
	}
	if v.Tenant() != string(tenantA) {
		t.Errorf("event attributed to %q, want the acting tenant %q", v.Tenant(), tenantA)
	}
	if v.SQLState != "42501" {
		t.Errorf("SQLState = %q, want 42501 (the RLS refusal)", v.SQLState)
	}
	if v.OccurredAt.IsZero() {
		t.Error("OccurredAt is zero")
	}
	// No row data, no SQL text, no target tenant guess.
	if strings.Contains(v.Detail, "forged") {
		t.Errorf("audit detail carries row data: %q — an audit event must not copy the payload (ADR-0007)", v.Detail)
	}
}

// A denial must stay a denial when nothing is listening. Without this, a future refactor that made
// auditing mandatory could turn an unavailable sink into a returned success.
func TestAC3_WriteIsStillRejectedWithNoAuditBus(t *testing.T) {
	pool, ctx := openPool(t)
	seed(t, pool, ctx)

	err := pool.InTx(tenancy.WithTenant(ctx, tenantA), func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO tenant.tenants (id, name) VALUES ($1, $2)`,
			string(tenantB)+"-forged-noaudit", "forged")
		return err
	})
	if err == nil {
		t.Error("cross-tenant insert succeeded when no audit bus was configured — auditing must observe enforcement, never gate it")
	}
}
