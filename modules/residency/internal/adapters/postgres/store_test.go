package postgres_test

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/gitfrok/backend/internal/chaos"
	"github.com/gitfrok/backend/modules/audit"
	auditapi "github.com/gitfrok/backend/modules/audit/api"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
	"github.com/gitfrok/backend/modules/residency/api"
	residencypg "github.com/gitfrok/backend/modules/residency/internal/adapters/postgres"
	"github.com/gitfrok/backend/modules/residency/internal/app"
	"github.com/gitfrok/backend/platform/bus"
	"github.com/gitfrok/backend/platform/db"
	"github.com/gitfrok/backend/platform/tenancy"
)

// SPEC-0042 AC3 and the residency half of AC5 against a real Postgres. The
// claims are about what survives a kill -9 and what the *database* permits:
// durability is a statement about committed rows and isolation about RLS
// policies — neither exists in process memory, so an in-memory fake proves
// nothing.
//
//	kubectl port-forward svc/postgres 15432:5432  (minikube profile gitfrok)
//	TEST_DATABASE_URL='postgres://gitfrok_app:gitfrok_app@127.0.0.1:15432/gitfrok' \
//	TEST_SUPERUSER_DATABASE_URL='postgres://postgres:postgres@127.0.0.1:15432/gitfrok' \
//	  go test -race ./modules/residency/internal/adapters/postgres/...
//
// TestMain applies the module's own migration via the superuser DSN when it
// is available, so the suite does not depend on the dev-provision list
// knowing about this wave's migration yet.

// runID makes each `go test` invocation use fresh tenants: there is no
// deletion path for the app role (by design — declarations are append-only),
// so the fixture moves instead.
var runID = fmt.Sprintf("%d", time.Now().UnixNano()%1_000_000_000)

func TestMain(m *testing.M) {
	if dsn := os.Getenv("TEST_SUPERUSER_DATABASE_URL"); dsn != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		err := applyMigration(ctx, dsn, "migrations/0001_residency_declarations.sql")
		cancel()
		if err != nil {
			fmt.Fprintf(os.Stderr, "residency postgres tests: could not self-apply migration: %v\n", err)
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

// tenantFor gives each test its own tenant within the run.
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

func dsnOrSkip(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — needs the dev Postgres (see file header for the port-forward)")
	}
	return dsn
}

func superDSNOrSkip(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("TEST_SUPERUSER_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_SUPERUSER_DATABASE_URL not set — migration application and attacker-side checks need it")
	}
	return dsn
}

// openPool is one app-role db.Pool, closed with the test.
func openPool(t *testing.T) *db.Pool {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	t.Cleanup(cancel)
	pool, err := db.Open(ctx, dsnOrSkip(t))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func store(t *testing.T) *residencypg.Store {
	t.Helper()
	return residencypg.New(openPool(t))
}

// rawAppPool is a bare pgxpool on the SAME app role, for assertions that must
// speak SQL directly (RLS visibility, pg_catalog enumeration) rather than go
// through the adapter whose behaviour they are checking.
func rawAppPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	p, err := pgxpool.New(t.Context(), dsnOrSkip(t))
	if err != nil {
		t.Fatalf("raw app pool: %v", err)
	}
	t.Cleanup(p.Close)
	return p
}

func superPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	p, err := pgxpool.New(t.Context(), superDSNOrSkip(t))
	if err != nil {
		t.Fatalf("superuser pool: %v", err)
	}
	t.Cleanup(p.Close)
	return p
}

func tenantCtx(tenant tenancy.ID) context.Context {
	return tenancy.WithTenant(context.Background(), tenant)
}

// declare inserts one declaration through the adapter with a caller-chosen
// effective time, so range semantics are testable without racing the clock.
func declare(t *testing.T, s *residencypg.Store, tenant tenancy.ID, cloud, region string, effectiveAt time.Time, seq int64) api.Declaration {
	t.Helper()
	d := api.Declaration{
		TenantID: string(tenant), Cloud: cloud, Region: region,
		EffectiveAt: effectiveAt, ActorID: "owner-" + runID,
		ChainSeq: seq, RecordHash: fmt.Sprintf("hash-%s-%d", runID, seq),
	}
	if err := s.PutDeclaration(tenantCtx(tenant), d); err != nil {
		t.Fatalf("put declaration: %v", err)
	}
	return d
}

// chaosStore builds the reusable kill-restart plane over the store: one
// db.Open per incarnation, discarded without ceremony on Kill.
func chaosStore(t *testing.T) *chaos.Plane[*residencypg.Store] {
	t.Helper()
	return chaos.New(dsnOrSkip(t), func(dsn string) (*residencypg.Store, *db.Pool, error) {
		pool, err := db.Open(context.Background(), dsn)
		if err != nil {
			return nil, nil, err
		}
		return residencypg.New(pool), pool, nil
	})
}

// --- AC5: migrations, RLS and the absence of any exemption -------------------------

// AC5: the migration is additive AND rollback-tested, proven against the real
// database: down removes the whole surface, up restores it, and up is
// idempotent enough to run the cycle repeatedly.
func TestAC5_UpAndDownMigrationsAreReversible(t *testing.T) {
	su := superPool(t)
	up, err := os.ReadFile("migrations/0001_residency_declarations.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := os.ReadFile("migrations/0001_residency_declarations.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	objectsExist := func() bool {
		var n int
		err := su.QueryRow(t.Context(),
			`SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
			  WHERE n.nspname = 'residency' AND c.relname IN ('declarations', 'observations')`).Scan(&n)
		if err != nil {
			t.Fatalf("probe tables: %v", err)
		}
		return n == 2
	}
	if !objectsExist() {
		t.Fatal("precondition failed: up migration not applied")
	}

	if _, err := su.Exec(t.Context(), string(down)); err != nil {
		t.Fatalf("down: %v", err)
	}
	if objectsExist() {
		t.Fatal("down migration left the residency tables behind")
	}
	if _, err := su.Exec(t.Context(), string(up)); err != nil {
		t.Fatalf("up after down: %v", err)
	}
	if !objectsExist() {
		t.Fatal("up migration did not restore the residency tables")
	}
	// Idempotence: the suite keeps running after this test, so the re-apply
	// must be safe to run on a database where everything already exists.
	if _, err := su.Exec(t.Context(), string(up)); err != nil {
		t.Fatalf("up is not idempotent: %v", err)
	}
}

// AC5: both tables are RLS-enabled AND forced with exactly one
// tenant_isolation policy each — verified in the catalog, not in the SQL text.
func TestAC5_RLSEnabledForcedWithTenantIsolationPolicy(t *testing.T) {
	pool := rawAppPool(t)
	for _, table := range []string{"declarations", "observations"} {
		var enabled, forced bool
		err := pool.QueryRow(t.Context(),
			`SELECT c.relrowsecurity, c.relforcerowsecurity
			   FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
			  WHERE n.nspname = 'residency' AND c.relname = $1`, table,
		).Scan(&enabled, &forced)
		if err != nil {
			t.Fatalf("catalog probe %s: %v", table, err)
		}
		if !enabled || !forced {
			t.Errorf("residency.%s: ENABLE=%t FORCE=%t — both must be true", table, enabled, forced)
		}
		var polName string
		var polCmd rune
		err = pool.QueryRow(t.Context(),
			`SELECT p.polname, p.polcmd FROM pg_policy p
			   JOIN pg_class c ON c.oid = p.polrelid
			   JOIN pg_namespace n ON n.oid = c.relnamespace
			  WHERE n.nspname = 'residency' AND c.relname = $1`, table,
		).Scan(&polName, &polCmd)
		if err != nil {
			t.Fatalf("policy probe %s: %v", table, err)
		}
		if polName != "tenant_isolation" || polCmd != '*' {
			t.Errorf("residency.%s: policy %q cmd %c — want tenant_isolation covering ALL", table, polName, polCmd)
		}
	}
}

// AC5: RLS fails closed across tenants at the SQL layer, on BOTH tables.
// Under tenant B's setting, tenant A's rows are invisible and a cross-tenant
// write is refused; with no setting at all, everything is invisible.
func TestAC5_RLSIsolatesTenantsAtTheSQLLayer(t *testing.T) {
	s := store(t)
	tenantA, tenantB := tenantFor(t), tenantFor(t)+"-other"
	base := time.Now().Truncate(time.Microsecond)
	declare(t, s, tenantA, "aws", "eu-central-1", base, 1)
	if err := s.PutObservation(tenantCtx(tenantA), string(tenantA), "plane-a-"+runID, "aws", "eu-central-1"); err != nil {
		t.Fatalf("put observation: %v", err)
	}

	raw := rawAppPool(t)
	count := func(asTenant string, query string) int {
		tx, err := raw.Begin(t.Context())
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer func() { _ = tx.Rollback(t.Context()) }()
		if asTenant != "" {
			if _, err := tx.Exec(t.Context(), fmt.Sprintf("SET LOCAL app.tenant_id = '%s'", asTenant)); err != nil {
				t.Fatalf("set tenant: %v", err)
			}
		}
		var n int
		if err := tx.QueryRow(t.Context(), query).Scan(&n); err != nil {
			t.Fatalf("count: %v", err)
		}
		return n
	}
	declsVisible := fmt.Sprintf(`SELECT count(*) FROM residency.declarations WHERE record_hash = 'hash-%s-1'`, runID)
	obsVisible := fmt.Sprintf(`SELECT count(*) FROM residency.observations WHERE data_plane_id = 'plane-a-%s'`, runID)

	if n := count(string(tenantA), declsVisible); n != 1 {
		t.Errorf("owner tenant sees %d declarations, want 1", n)
	}
	if n := count(string(tenantA), obsVisible); n != 1 {
		t.Errorf("owner tenant sees %d observations, want 1", n)
	}
	if n := count(string(tenantB), declsVisible); n != 0 {
		t.Errorf("other tenant sees %d of tenant A's declarations, want 0", n)
	}
	if n := count(string(tenantB), obsVisible); n != 0 {
		t.Errorf("other tenant sees %d of tenant A's observations, want 0", n)
	}
	if n := count("", declsVisible); n != 0 {
		t.Errorf("UNSCOPED session sees %d declarations, want 0 (fail closed)", n)
	}
	if n := count("", obsVisible); n != 0 {
		t.Errorf("UNSCOPED session sees %d observations, want 0 (fail closed)", n)
	}

	// A cross-tenant write trips WITH CHECK and is refused, not silenced —
	// on both tables.
	for _, probe := range []struct {
		name string
		stmt string
		args []any
	}{
		{"declarations",
			`INSERT INTO residency.declarations (tenant_id, cloud, region, effective_at, actor_id, chain_seq, record_hash)
			 VALUES ($1, 'aws', 'eu-central-1', now(), 'x', 999999, $2)`,
			[]any{string(tenantA), "cross-tenant-decl-" + runID}},
		{"observations",
			`INSERT INTO residency.observations (tenant_id, data_plane_id, cloud, region, observed_at)
			 VALUES ($1, $2, 'aws', 'eu-central-1', now())`,
			[]any{string(tenantA), "cross-tenant-obs-" + runID}},
	} {
		tx, err := raw.Begin(t.Context())
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		if _, err = tx.Exec(t.Context(), fmt.Sprintf("SET LOCAL app.tenant_id = '%s'", tenantB)); err != nil {
			t.Fatalf("set tenant: %v", err)
		}
		_, err = tx.Exec(t.Context(), probe.stmt, probe.args...)
		_ = tx.Rollback(t.Context())
		if err == nil {
			t.Fatalf("cross-tenant INSERT into residency.%s succeeded — WITH CHECK is not enforcing", probe.name)
		}
	}
}

// AC5: the residency tables carry NO exemption of any kind — the platform's
// single pre-tenancy exemption lives in the agent module, nowhere else. Two
// assertions: the live database holds no SECURITY DEFINER function in the
// residency schema, and the adapter source contains no InTxUnscoped call at
// all. A new un-scoped path here fails this test.
func TestAC5_NoUnscopedPathExists(t *testing.T) {
	pool := rawAppPool(t)
	var n int
	if err := pool.QueryRow(t.Context(),
		`SELECT count(*) FROM pg_proc p
		   JOIN pg_namespace ns ON ns.oid = p.pronamespace
		  WHERE ns.nspname = 'residency' AND p.prosecdef`).Scan(&n); err != nil {
		t.Fatalf("enumerate: %v", err)
	}
	if n != 0 {
		t.Fatalf("residency schema has %d SECURITY DEFINER functions, want 0 — this module gets no exemption", n)
	}

	src, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(src), "InTxUnscoped("); got != 0 {
		t.Errorf("store.go has %d InTxUnscoped call sites, want 0 — every residency path is tenant-scoped", got)
	}
}

// --- AC3: durable, effective-dated declarations -------------------------------------

// AC3: a declaration written before a kill -9 is exactly what the restarted
// store cites — same cloud, region, effective instant, actor and chain
// position. The successor process has zero memory of the write.
func TestAC3_DeclarationSurvivesKillRestart(t *testing.T) {
	plane := chaosStore(t)
	if err := plane.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	tenant := tenantFor(t)
	base := time.Now().Truncate(time.Microsecond)
	want := declare(t, plane.State, tenant, "aws", "eu-central-1", base, 1)

	if err := plane.Restart(); err != nil {
		t.Fatalf("restart: %v", err)
	}

	got, ok, err := plane.State.Declaration(tenantCtx(tenant), string(tenant))
	if err != nil || !ok {
		t.Fatalf("declaration after restart: ok=%t err=%v", ok, err)
	}
	if got != want {
		t.Fatalf("declaration changed across restart:\n before %+v\n after  %+v", want, got)
	}
}

// AC3: declarations are effective-dated and append-only. A replace APPENDS a
// new row and retains the old one; the declaration in force at an instant t
// is the one with the maximum effective_at <= t; nothing is ever overwritten.
func TestAC3_EffectiveDateRangeSemantics(t *testing.T) {
	s := store(t)
	tenant := tenantFor(t)
	base := time.Now().Add(-time.Hour).Truncate(time.Microsecond)

	first := declare(t, s, tenant, "aws", "eu-central-1", base, 1)
	second := declare(t, s, tenant, "gcp", "europe-west3", base.Add(30*time.Minute), 2)
	future := declare(t, s, tenant, "azure", "northeurope", base.Add(2*time.Hour), 3)

	inForce := func(at time.Time) api.Declaration {
		t.Helper()
		d, ok, err := s.DeclarationAt(tenantCtx(tenant), string(tenant), at)
		if err != nil || !ok {
			t.Fatalf("declaration at %s: ok=%t err=%v", at, ok, err)
		}
		return d
	}

	// Before the first declaration: nothing in force.
	if _, ok, err := s.DeclarationAt(tenantCtx(tenant), string(tenant), base.Add(-time.Second)); err != nil || ok {
		t.Fatalf("before any declaration: ok=%t err=%v, want ok=false", ok, err)
	}
	// At and between: max effective_at <= t.
	if got := inForce(base); got.ChainSeq != first.ChainSeq {
		t.Fatalf("in force at first instant = seq %d, want %d", got.ChainSeq, first.ChainSeq)
	}
	if got := inForce(base.Add(29 * time.Minute)); got.ChainSeq != first.ChainSeq {
		t.Fatalf("in force just before the replace = seq %d, want %d", got.ChainSeq, first.ChainSeq)
	}
	if got := inForce(base.Add(30 * time.Minute)); got.ChainSeq != second.ChainSeq {
		t.Fatalf("in force at the replace instant = seq %d, want %d", got.ChainSeq, second.ChainSeq)
	}
	// A declaration with a future effective_at is NOT yet in force — the
	// "currently in force" read agrees.
	if got := inForce(base.Add(time.Hour)); got.ChainSeq != second.ChainSeq {
		t.Fatalf("future declaration already in force: seq %d, want %d", got.ChainSeq, second.ChainSeq)
	}
	now, ok, err := s.Declaration(tenantCtx(tenant), string(tenant))
	if err != nil || !ok || now.ChainSeq != second.ChainSeq {
		t.Fatalf("current declaration = seq %d ok=%t err=%v, want %d", now.ChainSeq, ok, err, second.ChainSeq)
	}
	// And once its instant has passed, the future declaration takes over.
	if got := inForce(future.EffectiveAt.Add(time.Second)); got.ChainSeq != future.ChainSeq {
		t.Fatalf("in force after the third instant = seq %d, want %d", got.ChainSeq, future.ChainSeq)
	}

	// History retained, never overwritten: all three rows exist, and the
	// replace did not rewrite the first.
	pool := rawAppPool(t)
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	if _, err := tx.Exec(t.Context(), fmt.Sprintf("SET LOCAL app.tenant_id = '%s'", tenant)); err != nil {
		t.Fatal(err)
	}
	var rows int
	if err := tx.QueryRow(t.Context(), `SELECT count(*) FROM residency.declarations`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 3 {
		t.Fatalf("declarations table holds %d rows after two replaces, want 3 — history must be retained", rows)
	}
	var firstCloud string
	if err := tx.QueryRow(t.Context(),
		`SELECT cloud FROM residency.declarations WHERE chain_seq = 1`).Scan(&firstCloud); err != nil {
		t.Fatal(err)
	}
	if firstCloud != "aws" {
		t.Fatalf("first declaration row was rewritten: cloud=%q, want aws", firstCloud)
	}
}

// AC3 under -race: concurrent declares and reads serialize on the database.
// Every declare appends, the retained history keeps every row, and the
// declaration finally in force is one of the rows actually written — never a
// torn read of two of them.
func TestAC3_ConcurrentDeclareReplace(t *testing.T) {
	s := store(t)
	tenant := tenantFor(t)
	base := time.Now().Truncate(time.Microsecond)

	const writers = 16
	var wg sync.WaitGroup
	for i := range writers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Distinct chain positions and effective instants: whichever
			// interleaving wins, each writer's row is its own.
			declare(t, s, tenant, "aws", fmt.Sprintf("region-%d", i),
				base.Add(time.Duration(i)*time.Microsecond), int64(100+i))
		}(i)
	}
	// Concurrent readers must see either nothing yet or one whole row.
	for i := range writers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				d, ok, err := s.Declaration(tenantCtx(tenant), string(tenant))
				if err != nil {
					t.Errorf("reader %d: %v", i, err)
					return
				}
				if ok && d.Cloud != "aws" {
					t.Errorf("reader %d saw a torn row: %+v", i, d)
					return
				}
			}
		}(i)
	}
	wg.Wait()

	// All rows retained: append-only under contention.
	pool := rawAppPool(t)
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	if _, err := tx.Exec(t.Context(), fmt.Sprintf("SET LOCAL app.tenant_id = '%s'", tenant)); err != nil {
		t.Fatal(err)
	}
	var rows int
	if err := tx.QueryRow(t.Context(), `SELECT count(*) FROM residency.declarations`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != writers {
		t.Fatalf("%d concurrent declares retained %d rows, want %d", writers, rows, writers)
	}
	// The declaration in force is a whole row someone wrote.
	final, ok, err := s.Declaration(tenantCtx(tenant), string(tenant))
	if err != nil || !ok {
		t.Fatalf("final declaration: ok=%t err=%v", ok, err)
	}
	if final.Cloud != "aws" || final.ChainSeq < 100 || final.ChainSeq >= 100+writers {
		t.Fatalf("final declaration is not one of the written rows: %+v", final)
	}
	if final.Region != fmt.Sprintf("region-%d", final.ChainSeq-100) {
		t.Fatalf("final declaration mixes two rows: %+v", final)
	}
}

// --- AC3: the pack assembled after a restart cites what one before did ---------------

// allowPDP lets every operator act through: authorization is proven by its
// own suite, not re-litigated here.
type allowPDP struct{}

func (allowPDP) Decide(context.Context, policyapi.Request) (policyapi.Decision, error) {
	return policyapi.Decision{Allowed: true}, nil
}

// noopBus swallows audit emissions: these proofs are about the stores and the
// trail, and a dead bus must not mask a durability failure.
type noopBus struct{}

func (noopBus) Publish(context.Context, bus.Event) error { return nil }
func (noopBus) Subscribe(string, bus.Handler)            {}

// trailWitness adapts the durable audit trail onto the Residency context's
// witness port, exactly as the composition root does: every residency record
// is a first-party fact appended to the tenant's chain.
type trailWitness struct{ trail auditapi.Log }

func (w trailWitness) AppendResidencyRecord(ctx context.Context, e api.WitnessEntry) (api.WitnessRecord, error) {
	outcome := auditapi.OutcomeAllowed
	if e.Denied {
		outcome = auditapi.OutcomeDenied
	}
	record, err := w.trail.Append(ctx, auditapi.Entry{
		TenantID:   e.TenantID,
		Action:     auditapi.Action(e.Action),
		ActorID:    e.ActorID,
		Resource:   e.Resource,
		Outcome:    outcome,
		Detail:     e.Detail,
		OccurredAt: e.OccurredAt,
		Provenance: auditapi.ProvenanceFirstParty,
	})
	if err != nil {
		return api.WitnessRecord{}, err
	}
	return api.WitnessRecord{Seq: record.Seq, Hash: record.Hash}, nil
}

// packPlane is one live composition under test: the residency service on the
// durable store, witnessing onto the durable trail, plus the evidence pack
// assembler reading that same trail — everything a restarted control plane
// would compose over the same database.
type packPlane struct {
	svc      *app.Service
	store    *residencypg.Store
	evidence auditapi.PackService
}

func chaosPackPlane(t *testing.T) *chaos.Plane[packPlane] {
	t.Helper()
	return chaos.New(dsnOrSkip(t), func(dsn string) (packPlane, *db.Pool, error) {
		pool, err := db.Open(context.Background(), dsn)
		if err != nil {
			return packPlane{}, nil, err
		}
		st := residencypg.New(pool)
		trail := audit.NewPostgresTrail(pool)
		svc := app.New(allowPDP{}, trailWitness{trail}, st, api.Config{Now: time.Now}, nil)
		evidence := audit.NewEvidenceService(allowPDP{}, noopBus{}, trail, nil, nil, nil)
		return packPlane{svc: svc, store: st, evidence: evidence}, pool, nil
	})
}

// residencySectionOf requests one pack over the range and returns its
// residency section, waiting for assembly to finish.
func residencySectionOf(t *testing.T, plane packPlane, tenant tenancy.ID, from, to time.Time, requestID string) auditapi.Section {
	t.Helper()
	c := auditapi.Context{TenantID: string(tenant), ActorID: "owner-1", ActorRoles: []string{"owner"}, RequestID: requestID}
	packID, _, err := plane.evidence.RequestPack(context.Background(), c, auditapi.PackRequest{RangeFrom: from, RangeTo: to})
	if err != nil {
		t.Fatalf("request pack: %v", err)
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		st, err := plane.evidence.PackStatus(context.Background(), c, packID)
		if err != nil {
			t.Fatalf("pack status: %v", err)
		}
		switch st.State {
		case auditapi.PackReady:
			chunks, err := plane.evidence.GetPack(context.Background(), c, packID)
			if err != nil {
				t.Fatalf("get pack: %v", err)
			}
			for _, ch := range chunks {
				if ch.Section != nil && ch.Section.Type == auditapi.SectionResidency {
					return *ch.Section
				}
			}
			t.Fatal("pack carried no residency section")
		case auditapi.PackFailed:
			t.Fatalf("pack assembly failed: %s", st.FailureReason)
		}
		if time.Now().After(deadline) {
			t.Fatal("pack assembly did not finish in time")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// AC3 at the composition level: declare → kill -9 → restart → the store read
// AND the pack's residency section cite the SAME declaration the pre-restart
// pack cited. The pack assembled after restart reproduces what one assembled
// before would (SPEC-0042 AC3).
func TestAC3_PackCitesSameDeclarationAcrossKillRestart(t *testing.T) {
	plane := chaosPackPlane(t)
	if err := plane.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	tenant := tenantFor(t)
	ctx := tenantCtx(tenant)

	decl, err := plane.State.svc.Declare(ctx, string(tenant), "owner-1", []string{"owner"}, "aws", "eu-central-1")
	if err != nil {
		t.Fatalf("declare: %v", err)
	}
	// Strip the monotonic clock reading: the database round-trip keeps the
	// wall instant but never the process-local monotonic part of it.
	decl.EffectiveAt = decl.EffectiveAt.Round(0)

	rangeFrom, rangeTo := decl.EffectiveAt.Add(-time.Hour), decl.EffectiveAt.Add(time.Hour)
	before := residencySectionOf(t, plane.State, tenant, rangeFrom, rangeTo, "req-before-"+runID)
	if len(before.Records) == 0 {
		t.Fatal("pre-restart pack cites no residency records")
	}

	// kill -9: no graceful shutdown; only the database outlives this.
	if err := plane.Restart(); err != nil {
		t.Fatalf("restart: %v", err)
	}

	// The store read cites the same declaration — chain position, record
	// hash and effective instant included.
	got, ok, err := plane.State.store.Declaration(ctx, string(tenant))
	if err != nil || !ok {
		t.Fatalf("declaration after restart: ok=%t err=%v", ok, err)
	}
	if got != decl {
		t.Fatalf("declaration changed across restart:\n before %+v\n after  %+v", decl, got)
	}

	// And a pack assembled by the RESTARTED composition cites exactly the
	// records the pre-restart pack cited — record for record.
	after := residencySectionOf(t, plane.State, tenant, rangeFrom, rangeTo, "req-after-"+runID)
	if !reflect.DeepEqual(before.Records, after.Records) {
		t.Fatalf("pack residency section differs across restart:\n before %+v\n after  %+v", before.Records, after.Records)
	}
	if before.RecordsDigest != after.RecordsDigest {
		t.Fatalf("records digest differs across restart: %q vs %q", before.RecordsDigest, after.RecordsDigest)
	}
}
