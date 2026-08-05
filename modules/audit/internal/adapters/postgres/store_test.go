package postgres_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	pgxpool "github.com/jackc/pgx/v5/pgxpool"

	"github.com/gitfrok/backend/modules/audit/api"
	auditpg "github.com/gitfrok/backend/modules/audit/internal/adapters/postgres"
	"github.com/gitfrok/backend/platform/db"
	"github.com/gitfrok/backend/platform/tenancy"
)

// SPEC-0003 AC1, AC2 and AC4 against a real Postgres. The claims are about what the *database*
// permits, so an in-memory store would prove nothing: "there is no update path" is a statement about
// grants and triggers, not about Go methods.
//
//	kubectl port-forward -n default deploy/postgres 15432:5432
//	TEST_DATABASE_URL='postgres://gitfrok_app:gitfrok_app@127.0.0.1:15432/gitfrok' \
//	TEST_SUPERUSER_DATABASE_URL='postgres://postgres:postgres@127.0.0.1:15432/gitfrok' \
//	  go test ./modules/audit/...

// runID makes each `go test` invocation use fresh tenants.
//
// Per-test tenants alone are not enough, and the reason is the feature under test: the trail is
// append-only, so a second run chains onto the first run's records and every count assertion drifts.
// There is no cleanup available — deleting is exactly what the store forbids — so the fixture has to
// move instead. A suite that cannot reset its own fixture is the honest consequence of an immutable
// log, not a smell.
var runID = fmt.Sprintf("%d", time.Now().UnixNano()%1_000_000_000)

// Each test gets its own tenant within the run, so cases cannot interfere and every case exercises
// the tenant scoping for free.
func tenantFor(t *testing.T) tenancy.ID {
	t.Helper()
	safe := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		default:
			return '-'
		}
	}, t.Name())
	if len(safe) > 40 {
		safe = safe[:40]
	}
	return tenancy.ID(safe + "-" + runID)
}

func store(t *testing.T) (*auditpg.Store, context.Context) {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — needs a Postgres with the T-0006 migration applied")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	pool, err := db.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(pool.Close)
	return auditpg.New(pool), tenancy.WithTenant(ctx, tenantFor(t))
}

// superuser returns a raw pool for the *attacker's* side of the tamper tests: mutating a row that
// the application role is not permitted to touch. Using the app role would prove only that the
// grants work, not that verification catches a change made around them.
func superuser(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_SUPERUSER_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_SUPERUSER_DATABASE_URL not set — cannot simulate tampering that bypasses the grants")
	}
	p, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("superuser pool: %v", err)
	}
	t.Cleanup(p.Close)
	return p
}

func appendN(t *testing.T, s *auditpg.Store, ctx context.Context, n int) []api.Record {
	t.Helper()
	var out []api.Record
	for i := 0; i < n; i++ {
		r, err := s.Append(ctx, api.Entry{
			TenantID:   string(tenantFor(t)),
			Action:     api.ActionTenantIsolationViolation,
			ActorID:    "user-1",
			Resource:   "repo/01H",
			Outcome:    api.OutcomeDenied,
			Detail:     map[string]string{"sqlstate": "42501"},
			OccurredAt: time.Unix(int64(1780000000+i), 0).UTC(),
		})
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
		out = append(out, r)
	}
	return out
}

// withTriggerDisabled runs fn with an append-only guard temporarily off, to simulate an attacker who
// has database access and drops the guard before editing.
//
// t.Cleanup rather than defer, and a re-enable at the start as well as the end. A killed test run —
// a timeout, a ^C — leaves the trigger disabled in a database that outlives the process, and the next
// run then "passes" its tamper test for the wrong reason while AC1's assertion silently stops
// holding. Learned the hard way: exactly that happened here.
func withTriggerDisabled(t *testing.T, su *pgxpool.Pool, trigger string, fn func()) {
	t.Helper()
	enable := func() {
		if _, err := su.Exec(context.Background(),
			fmt.Sprintf(`ALTER TABLE audit.entries ENABLE TRIGGER %s`, trigger)); err != nil {
			t.Fatalf("re-enable %s: %v", trigger, err)
		}
	}
	enable() // repair anything a previous run left behind
	if _, err := su.Exec(context.Background(),
		fmt.Sprintf(`ALTER TABLE audit.entries DISABLE TRIGGER %s`, trigger)); err != nil {
		t.Fatalf("disable %s: %v", trigger, err)
	}
	t.Cleanup(enable)
	fn()
}

// AC1: the application role has no update or delete path, in the database itself.
func TestAC1_NoUpdateOrDeletePathExists(t *testing.T) {
	s, ctx := store(t)
	recs := appendN(t, s, ctx, 1)

	dsn := os.Getenv("TEST_DATABASE_URL")
	app, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("app pool: %v", err)
	}
	defer app.Close()

	scoped := func(sql string, args ...any) error {
		tx, err := app.Begin(context.Background())
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		if _, err := tx.Exec(context.Background(),
			"SET LOCAL app.tenant_id = '"+string(tenantFor(t))+"'"); err != nil {
			return err
		}
		_, err = tx.Exec(context.Background(), sql, args...)
		return err
	}

	if err := scoped(`UPDATE audit.entries SET resource = 'rewritten'
	                    WHERE tenant_id = $1 AND tenant_seq = $2`, string(tenantFor(t)), recs[0].Seq); err == nil {
		t.Error("the application role updated an audit entry — AC1 requires no update path")
	}
	if err := scoped(`DELETE FROM audit.entries WHERE tenant_id = $1 AND tenant_seq = $2`,
		string(tenantFor(t)), recs[0].Seq); err == nil {
		t.Error("the application role deleted an audit entry — AC1 requires no delete path")
	}
	if err := scoped(`TRUNCATE audit.entries`); err == nil {
		t.Error("the application role truncated the audit trail — AC1 requires no delete path")
	}
}

// AC2: an intact chain verifies.
func TestAC2_IntactChainVerifies(t *testing.T) {
	s, ctx := store(t)
	appendN(t, s, ctx, 4)

	res, err := s.Verify(ctx)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.OK {
		t.Errorf("intact chain failed at seq %d: %s", res.BrokenAtSeq, res.Reason)
	}
	if res.Checked != 4 {
		t.Errorf("checked %d records, want 4 — verification is skipping entries", res.Checked)
	}
}

// AC2, the half that matters: a record altered behind the application's back is detected.
func TestAC2_TamperedRecordIsDetected(t *testing.T) {
	s, ctx := store(t)
	recs := appendN(t, s, ctx, 4)

	// Record.Seq is the per-tenant chain position, not the table's global `seq` — filtering on the
	// wrong one silently matches zero rows, and a row-level trigger that never fires looks exactly
	// like a trigger that does not work.
	su := superuser(t)
	if _, err := su.Exec(context.Background(),
		`UPDATE audit.entries SET resource = 'covered-up'
		  WHERE tenant_id = $1 AND tenant_seq = $2`, string(tenantFor(t)), recs[1].Seq); err == nil {
		t.Fatal("expected the append-only trigger to reject even a superuser UPDATE")
	}

	// The trigger blocks in-place edits, so tamper the way an attacker with database access actually
	// would: drop the guard first. That this takes DDL is itself part of the defence, and the chain
	// must still catch what happens afterwards.
	withTriggerDisabled(t, su, "no_update", func() {
		if _, err := su.Exec(context.Background(),
			`UPDATE audit.entries SET resource = 'covered-up'
			  WHERE tenant_id = $1 AND tenant_seq = $2`, string(tenantFor(t)), recs[1].Seq); err != nil {
			t.Fatalf("tamper: %v", err)
		}
	})

	res, err := s.Verify(ctx)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.OK {
		t.Fatal("verification passed on a tampered trail — the chain is not tamper-evident (SPEC-0003 AC2)")
	}
	if res.BrokenAtSeq != recs[1].Seq {
		t.Errorf("reported broken at %d, want %d (the altered record)", res.BrokenAtSeq, recs[1].Seq)
	}
	if !strings.Contains(res.Reason, "altered") {
		t.Errorf("reason = %q, want it to name content alteration", res.Reason)
	}
}

// A removed record is tampering that hashes alone cannot see: every surviving row is individually
// valid. The sequence check is what catches it.
func TestAC2_DeletedRecordIsDetected(t *testing.T) {
	s, ctx := store(t)
	recs := appendN(t, s, ctx, 4)

	su := superuser(t)
	withTriggerDisabled(t, su, "no_delete", func() {
		if _, err := su.Exec(context.Background(),
			`DELETE FROM audit.entries WHERE tenant_id = $1 AND tenant_seq = $2`,
			string(tenantFor(t)), recs[1].Seq); err != nil {
			t.Fatalf("delete: %v", err)
		}
	})

	res, err := s.Verify(ctx)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.OK {
		t.Fatal("verification passed after a record was deleted (SPEC-0003 AC1/AC2)")
	}
	if !strings.Contains(res.Reason, "sequence gap") {
		t.Errorf("reason = %q, want it to name a sequence gap", res.Reason)
	}
}

// The sealing helper must not be usable as a general update path: an already-hashed record cannot be
// re-sealed, so an attacker cannot mutate a row and then re-hash it through the same door.
func TestSealingHelperCannotRewriteAnExistingHash(t *testing.T) {
	s, ctx := store(t)
	recs := appendN(t, s, ctx, 1)

	dsn := os.Getenv("TEST_DATABASE_URL")
	app, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("app pool: %v", err)
	}
	defer app.Close()

	tx, err := app.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(context.Background(), "SET LOCAL app.tenant_id = '"+string(tenantFor(t))+"'"); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(context.Background(),
		`SELECT audit.set_entry_hash($1, $2)`, recs[0].Seq, "0000000000000000"); err != nil {
		t.Fatalf("call: %v", err)
	}
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}

	res, err := s.Verify(ctx)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.OK {
		t.Errorf("the sealing helper rewrote a sealed record's hash — it is an update path after all: %s", res.Reason)
	}
}

// AC4: the trail lives in its own schema, separate from anything operational. Asserted against the
// catalog rather than the migration text, so moving the table without moving the guarantee fails.
func TestAC4_AuditIsASeparateStore(t *testing.T) {
	su := superuser(t)
	var schema string
	err := su.QueryRow(context.Background(),
		`SELECT table_schema FROM information_schema.tables WHERE table_name = 'entries' AND table_schema = 'audit'`,
	).Scan(&schema)
	if err != nil {
		t.Fatalf("audit.entries is not in its own schema: %v", err)
	}
	if schema != "audit" {
		t.Errorf("audit table lives in schema %q, want a dedicated 'audit' schema (SPEC-0003 AC4)", schema)
	}

	// And nothing else shares it: a telemetry or application table appearing here would mean the
	// trail inherits that table's retention and access rules.
	rows, err := su.Query(context.Background(),
		`SELECT table_name FROM information_schema.tables WHERE table_schema = 'audit'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		names = append(names, n)
	}
	for _, n := range names {
		if n != "entries" {
			t.Errorf("unexpected table %q in the audit schema — the trail must not share a store (SPEC-0003 AC4)", n)
		}
	}
}

// Tenant isolation applies to the trail itself: one tenant's investigators must not read another's
// incidents (invariant 1, inherited from SPEC-0001).
func TestTrailIsTenantScoped(t *testing.T) {
	s, ctx := store(t)
	appendN(t, s, ctx, 2)

	other := tenancy.WithTenant(context.Background(), tenancy.ID("tenant-audit-other"))
	res, err := s.Verify(other)
	if err != nil {
		t.Fatalf("verify as another tenant: %v", err)
	}
	if res.Checked != 0 {
		t.Errorf("another tenant saw %d audit records; the trail is not tenant-scoped", res.Checked)
	}
}

var _ api.Log = (*auditpg.Store)(nil) // the adapter satisfies the api surface, and only that

var _ = pgx.ErrNoRows // keep the pgx import meaningful if the file is trimmed
