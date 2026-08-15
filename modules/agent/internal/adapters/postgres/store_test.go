package postgres_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/gitfrok/backend/internal/chaos"
	agentpg "github.com/gitfrok/backend/modules/agent/internal/adapters/postgres"
	"github.com/gitfrok/backend/modules/agent/internal/domain"
	"github.com/gitfrok/backend/platform/db"
	"github.com/gitfrok/backend/platform/tenancy"
)

// SPEC-0042 AC1, AC2 and AC5 against a real Postgres. The claims are about
// what survives a kill -9 and what the *database* permits, so an in-memory
// fake proves nothing: durability is a statement about committed rows, and
// isolation about RLS policies — neither exists in process memory.
//
//	kubectl port-forward -n default deploy/postgres 15432:5432
//	TEST_DATABASE_URL='postgres://gitfrok_app:gitfrok_app@127.0.0.1:15432/gitfrok' \
//	TEST_SUPERUSER_DATABASE_URL='postgres://postgres:postgres@127.0.0.1:15432/gitfrok' \
//	  go test -race ./modules/agent/internal/adapters/postgres/...
//
// TestMain applies the module's own migration via the superuser DSN when it
// is available, so the suite does not depend on the dev-provision list
// knowing about this wave's migration yet.

// runID makes each `go test` invocation use fresh tenants: there is no
// deletion path for the app role (by design), so the fixture moves instead.
var runID = fmt.Sprintf("%d", time.Now().UnixNano()%1_000_000_000)

func TestMain(m *testing.M) {
	if dsn := os.Getenv("TEST_SUPERUSER_DATABASE_URL"); dsn != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		for _, f := range []string{
			"migrations/0001_agent_enrolment.sql",
			"migrations/0002_release_trust_plane_state.sql",
		} {
			if err := applyMigration(ctx, dsn, f); err != nil {
				fmt.Fprintf(os.Stderr, "agent postgres tests: could not self-apply %s: %v\n", f, err)
			}
		}
		cancel()
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

func store(t *testing.T) *agentpg.Store {
	t.Helper()
	return agentpg.New(openPool(t))
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

// issueToken inserts one fresh, unspent token and returns it with its secret.
func issueToken(t *testing.T, s *agentpg.Store, tenant tenancy.ID, now time.Time, lifetime time.Duration) (domain.Token, string) {
	t.Helper()
	secret, err := domain.GenerateSecret()
	if err != nil {
		t.Fatalf("generate secret: %v", err)
	}
	tok := domain.Token{
		ID: fmt.Sprintf("tok-%s-%d", runID, time.Now().UnixNano()), TenantID: string(tenant), IssuedBy: "operator-1",
		TokenHash: domain.HashSecret(secret),
		IssuedAt:  now, ExpiresAt: now.Add(lifetime),
	}
	if err := s.PutToken(context.Background(), tok); err != nil {
		t.Fatalf("put token: %v", err)
	}
	return tok, secret
}

func putPlane(t *testing.T, s *agentpg.Store, d domain.DataPlane) {
	t.Helper()
	if err := s.PutDataPlane(context.Background(), d); err != nil {
		t.Fatalf("put data plane: %v", err)
	}
}

// chaosStore builds the reusable kill-restart plane over the store: one
// db.Open per incarnation, discarded without ceremony on Kill.
func chaosStore(t *testing.T) *chaos.Plane[*agentpg.Store] {
	t.Helper()
	return chaos.New(dsnOrSkip(t), func(dsn string) (*agentpg.Store, *db.Pool, error) {
		pool, err := db.Open(context.Background(), dsn)
		if err != nil {
			return nil, nil, err
		}
		return agentpg.New(pool), pool, nil
	})
}

// --- AC5: migrations, RLS and the enumerated exemption ----------------------------

// AC5: the migrations are additive AND rollback-tested, proven against the
// real database: down — newest first, since 0002's table lives in the schema
// 0001 created — removes the whole surface, up restores it, and up is
// idempotent enough to run the cycle repeatedly.
func TestAC5_UpAndDownMigrationsAreReversible(t *testing.T) {
	su := superPool(t)
	read := func(name string) string {
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	ups := []string{
		read("migrations/0001_agent_enrolment.sql"),
		read("migrations/0002_release_trust_plane_state.sql"),
	}
	// Down runs newest-first: 0001's down ends in DROP SCHEMA agent, which
	// 0002's table would otherwise block.
	downs := []string{
		read("migrations/0002_release_trust_plane_state.down.sql"),
		read("migrations/0001_agent_enrolment.down.sql"),
	}
	objectsExist := func() bool {
		var n int
		err := su.QueryRow(t.Context(),
			`SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
			  WHERE n.nspname = 'agent' AND c.relname IN ('enrolment_tokens', 'data_planes', 'release_trust_plane_state')`).Scan(&n)
		if err != nil {
			t.Fatalf("probe tables: %v", err)
		}
		return n == 3
	}
	if !objectsExist() {
		t.Fatal("precondition failed: up migrations not applied")
	}

	for _, d := range downs {
		if _, err := su.Exec(t.Context(), d); err != nil {
			t.Fatalf("down: %v", err)
		}
	}
	if objectsExist() {
		t.Fatal("down migrations left the agent tables behind")
	}
	for _, u := range ups {
		if _, err := su.Exec(t.Context(), u); err != nil {
			t.Fatalf("up after down: %v", err)
		}
	}
	if !objectsExist() {
		t.Fatal("up migrations did not restore the agent tables")
	}
	// Idempotence: the suite keeps running after this test, so the re-apply
	// must be safe to run on a database where everything already exists.
	for _, u := range ups {
		if _, err := su.Exec(t.Context(), u); err != nil {
			t.Fatalf("up is not idempotent: %v", err)
		}
	}
}

// AC5: both tables are RLS-enabled AND forced with exactly one
// tenant_isolation policy each — verified in the catalog, not in the SQL text.
func TestAC5_RLSEnabledForcedWithTenantIsolationPolicy(t *testing.T) {
	pool := rawAppPool(t)
	for _, table := range []string{"enrolment_tokens", "data_planes"} {
		var enabled, forced bool
		err := pool.QueryRow(t.Context(),
			`SELECT c.relrowsecurity, c.relforcerowsecurity
			   FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
			  WHERE n.nspname = 'agent' AND c.relname = $1`, table,
		).Scan(&enabled, &forced)
		if err != nil {
			t.Fatalf("catalog probe %s: %v", table, err)
		}
		if !enabled || !forced {
			t.Errorf("agent.%s: ENABLE=%t FORCE=%t — both must be true", table, enabled, forced)
		}
		var polName string
		var polCmd rune
		err = pool.QueryRow(t.Context(),
			`SELECT p.polname, p.polcmd FROM pg_policy p
			   JOIN pg_class c ON c.oid = p.polrelid
			   JOIN pg_namespace n ON n.oid = c.relnamespace
			  WHERE n.nspname = 'agent' AND c.relname = $1`, table,
		).Scan(&polName, &polCmd)
		if err != nil {
			t.Fatalf("policy probe %s: %v", table, err)
		}
		if polName != "tenant_isolation" || polCmd != '*' {
			t.Errorf("agent.%s: policy %q cmd %c — want tenant_isolation covering ALL", table, polName, polCmd)
		}
	}
}

// AC5: RLS fails closed across tenants at the SQL layer. Under tenant B's
// setting, tenant A's rows are invisible and a cross-tenant write is refused;
// with no setting at all, everything is invisible.
func TestAC5_RLSIsolatesTenantsAtTheSQLLayer(t *testing.T) {
	s := store(t)
	tenantA, tenantB := tenantFor(t), tenantFor(t)+"-other"
	tokA, _ := issueToken(t, s, tenantA, time.Now(), time.Hour)
	putPlane(t, s, domain.DataPlane{
		ID: "plane-a-" + runID, TenantID: string(tenantA),
		EnrolledAt: time.Now(), LastSeenAt: time.Now(),
	})

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
	tokensVisible := fmt.Sprintf(`SELECT count(*) FROM agent.enrolment_tokens WHERE id = '%s'`, tokA.ID)
	planesVisible := fmt.Sprintf(`SELECT count(*) FROM agent.data_planes WHERE id = 'plane-a-%s'`, runID)

	if n := count(string(tenantA), tokensVisible); n != 1 {
		t.Errorf("owner tenant sees %d tokens, want 1", n)
	}
	if n := count(string(tenantB), tokensVisible); n != 0 {
		t.Errorf("other tenant sees %d of tenant A's tokens, want 0", n)
	}
	if n := count("", tokensVisible); n != 0 {
		t.Errorf("UNSCOPED session sees %d tokens, want 0 (fail closed)", n)
	}
	if n := count(string(tenantB), planesVisible); n != 0 {
		t.Errorf("other tenant sees %d of tenant A's planes, want 0", n)
	}

	// A cross-tenant write trips WITH CHECK and is refused, not silenced.
	tx, err := raw.Begin(t.Context())
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	if _, err = tx.Exec(t.Context(), fmt.Sprintf("SET LOCAL app.tenant_id = '%s'", tenantB)); err != nil {
		t.Fatalf("set tenant: %v", err)
	}
	_, err = tx.Exec(t.Context(),
		`INSERT INTO agent.enrolment_tokens (id, tenant_id, issued_by, token_hash, issued_at, expires_at)
		 VALUES ($1, $2, 'x', $3, now(), now() + interval '1 hour')`,
		"cross-tenant-"+runID, string(tenantA), []byte("cross-tenant-write-probe"),
	)
	if err == nil {
		t.Fatal("cross-tenant INSERT succeeded — WITH CHECK is not enforcing")
	}
}

// AC5: the exempt set is enumerated in the live database and is EXACTLY the
// two named functions. Any new SECURITY DEFINER in the agent schema fails
// this test; the matching assertion over the adapter source keeps the Go
// side to the single stated unscoped reason.
func TestAC5_ExemptPathEnumeration(t *testing.T) {
	pool := rawAppPool(t)
	rows, err := pool.Query(t.Context(),
		`SELECT p.proname FROM pg_proc p
		   JOIN pg_namespace n ON n.oid = p.pronamespace
		  WHERE n.nspname = 'agent' AND p.prosecdef
		  ORDER BY p.proname`)
	if err != nil {
		t.Fatalf("enumerate: %v", err)
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	want := []string{"claim_enrolment_token", "lookup_enrolment_token"}
	if !slices.Equal(names, want) {
		t.Fatalf("SECURITY DEFINER functions in agent schema = %v, want exactly %v", names, want)
	}

	// The adapter side: the stated escape hatch appears exactly once as a
	// reason constant and exactly twice as call sites (lookup + claim, the
	// two halves of the one pre-tenancy act). A third caller fails here.
	src, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(src), "InTxUnscoped(ctx, unscopedTokenReason"); got != 2 {
		t.Errorf("store.go has %d unscoped call sites, want exactly 2 (lookup + claim)", got)
	}
}

// --- AC1: durable single-use across a kill -9 --------------------------------------

// AC1: a spent token stays spent after the control plane is killed and
// restarted — the replay is refused by durable state, not by the memory of
// the process that saw the first spend.
func TestAC1_SpentTokenStaysSpentAcrossKillRestart(t *testing.T) {
	plane := chaosStore(t)
	if err := plane.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	tenant := tenantFor(t)
	now := time.Now()
	tok, secret := issueToken(t, plane.State, tenant, now, time.Hour)

	claimed, ok, err := plane.State.ClaimToken(context.Background(), tok.TokenHash, "plane-1-"+runID, now)
	if err != nil || !ok {
		t.Fatalf("claim before restart: ok=%t err=%v", ok, err)
	}
	if !claimed.Spent() || claimed.DataPlaneID != "plane-1-"+runID {
		t.Fatalf("claim returned wrong state: %+v", claimed)
	}

	// kill -9: no graceful shutdown, then a brand-new process against the
	// same database.
	if err := plane.Restart(); err != nil {
		t.Fatalf("restart: %v", err)
	}

	after, ok, err := plane.State.TokenByHash(context.Background(), domain.HashSecret(secret))
	if err != nil || !ok {
		t.Fatalf("lookup after restart: ok=%t err=%v", ok, err)
	}
	if !after.Spent() {
		t.Fatal("token is UNSPENT after restart — the spend was process memory, not platform state")
	}
	if _, reClaimed, err := plane.State.ClaimToken(context.Background(), after.TokenHash, "plane-2-"+runID, now.Add(time.Second)); err != nil || reClaimed {
		t.Fatalf("replay after restart: claimed=%t err=%v — want refused", reClaimed, err)
	}
	// And the identity it minted is still the first one's.
	if after.DataPlaneID != "plane-1-"+runID {
		t.Fatalf("data plane identity changed across restart: %q", after.DataPlaneID)
	}
}

// AC1: a revocation issued before the restart still refuses after it.
func TestAC1_RevocationBeforeRestartStillRefuses(t *testing.T) {
	plane := chaosStore(t)
	if err := plane.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	tenant := tenantFor(t)
	now := time.Now()
	tok, secret := issueToken(t, plane.State, tenant, now, time.Hour)
	if err := plane.State.RevokeToken(context.Background(), string(tenant), tok.ID, now); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	if err := plane.Restart(); err != nil {
		t.Fatalf("restart: %v", err)
	}

	after, ok, err := plane.State.TokenByHash(context.Background(), domain.HashSecret(secret))
	if err != nil || !ok {
		t.Fatalf("lookup after restart: ok=%t err=%v", ok, err)
	}
	if !after.Revoked() {
		t.Fatal("revocation lost across restart")
	}
	if _, claimed, err := plane.State.ClaimToken(context.Background(), after.TokenHash, "plane-x-"+runID, now.Add(time.Second)); err != nil || claimed {
		t.Fatalf("revoked token claimed after restart: claimed=%t err=%v", claimed, err)
	}
	if outcome := after.PresentOutcome(now.Add(time.Second)); outcome != "TOKEN_REVOKED" {
		t.Fatalf("presentation outcome after restart = %q, want TOKEN_REVOKED", outcome)
	}
}

// AC1 under -race: N concurrent presenters of ONE token — exactly one spends
// it. The conditional UPDATE makes the race the database's to serialize, not
// the adapter's to lock around.
func TestAC1_ConcurrentClaimsExactlyOneSpends(t *testing.T) {
	s := store(t)
	tenant := tenantFor(t)
	now := time.Now()
	tok, _ := issueToken(t, s, tenant, now, time.Hour)

	const presenters = 16
	var wg sync.WaitGroup
	results := make(chan string, presenters) // data-plane IDs of successful claims
	for i := range presenters {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			planeID := fmt.Sprintf("racer-%d-%s", i, runID)
			_, claimed, err := s.ClaimToken(context.Background(), tok.TokenHash, planeID, now)
			if err != nil {
				return // a serialization error loses the race; the count below catches it
			}
			if claimed {
				results <- planeID
			}
		}(i)
	}
	wg.Wait()
	close(results)

	var winners []string
	for w := range results {
		winners = append(winners, w)
	}
	if len(winners) != 1 {
		t.Fatalf("%d presenters spent one single-use token: %v", len(winners), winners)
	}
	final, ok, err := s.TokenByHash(context.Background(), tok.TokenHash)
	if err != nil || !ok {
		t.Fatalf("final lookup: ok=%t err=%v", ok, err)
	}
	if final.DataPlaneID != winners[0] {
		t.Fatalf("recorded identity %q != the sole winner %q", final.DataPlaneID, winners[0])
	}
}

// --- AC2: the staleness machine reads durable liveness -----------------------------

// AC2: NEVER_CONNECTED / CONNECTED / STALE / REVOKED all recompute from
// durable columns after a kill-and-restart — the machine has no access to the
// dead process's uptime, which is exactly the property under test.
func TestAC2_StalenessRecomputedFromDurableLivenessAfterRestart(t *testing.T) {
	plane := chaosStore(t)
	if err := plane.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	tenant := tenantFor(t)
	now := time.Now()
	staleAfter := 5 * time.Minute

	certified := domain.DataPlane{
		ID: "plane-live-" + runID, TenantID: string(tenant),
		EnrolledAt: now, LastSeenAt: now,
		CurrentCertificateID: "cert-1", CertificateExpiresAt: now.Add(time.Hour),
	}
	uncertified := domain.DataPlane{
		ID: "plane-partial-" + runID, TenantID: string(tenant),
		EnrolledAt: now, LastSeenAt: now, // enrolled, but issuance never completed
	}
	putPlane(t, plane.State, certified)
	putPlane(t, plane.State, uncertified)

	status := func(id string, at time.Time) string {
		d, ok, err := plane.State.DataPlane(context.Background(), string(tenant), id)
		if err != nil || !ok {
			t.Fatalf("read %s: ok=%t err=%v", id, ok, err)
		}
		return string(domain.DeriveStatus(d, false, at, staleAfter))
	}

	if got := status(certified.ID, now); got != "CONNECTED" {
		t.Fatalf("before restart: %s, want CONNECTED", got)
	}
	if got := status(uncertified.ID, now); got != "NEVER_CONNECTED" {
		t.Fatalf("uncertified before restart: %s, want NEVER_CONNECTED", got)
	}

	if err := plane.Restart(); err != nil {
		t.Fatalf("restart: %v", err)
	}

	// The restarted process has zero uptime history: everything it says about
	// liveness comes from the rows it reads.
	if got := status(certified.ID, now); got != "CONNECTED" {
		t.Fatalf("after restart: %s, want CONNECTED (durable last_seen)", got)
	}
	if got := status(uncertified.ID, now); got != "NEVER_CONNECTED" {
		t.Fatalf("uncertified after restart: %s, want NEVER_CONNECTED", got)
	}

	// Backdate liveness — a silent plane — and the machine reads STALE on the
	// very next read, before and after another restart. No sleep involved:
	// staleness is arithmetic on last_seen_at, which is the point.
	silent := now.Add(-1 * time.Hour)
	if err := plane.State.MarkSeen(context.Background(), string(tenant), certified.ID, silent); err != nil {
		t.Fatalf("backdate liveness: %v", err)
	}
	if got := status(certified.ID, now); got != "STALE" {
		t.Fatalf("silent plane: %s, want STALE", got)
	}
	if err := plane.Restart(); err != nil {
		t.Fatalf("restart 2: %v", err)
	}
	if got := status(certified.ID, now); got != "STALE" {
		t.Fatalf("stale across restart: %s, want STALE", got)
	}

	// Revocation wins over everything, and survives too.
	if err := plane.State.RevokeDataPlane(context.Background(), string(tenant), certified.ID, now); err != nil {
		t.Fatalf("revoke plane: %v", err)
	}
	if err := plane.Restart(); err != nil {
		t.Fatalf("restart 3: %v", err)
	}
	if got := status(certified.ID, now); got != "REVOKED" {
		t.Fatalf("revoked after restart: %s, want REVOKED", got)
	}
}

// --- store semantics (the ports' contract, durable edition) ------------------------

func TestStore_TokenLifecycleSentinels(t *testing.T) {
	s := store(t)
	tenant := tenantFor(t)
	now := time.Now()
	tok, secret := issueToken(t, s, tenant, now, time.Hour)

	got, ok, err := s.TokenByID(context.Background(), string(tenant), tok.ID)
	if err != nil || !ok || got.ID != tok.ID {
		t.Fatalf("by id: ok=%t err=%v", ok, err)
	}
	if _, ok, _ := s.TokenByID(context.Background(), string(tenant)+"-other", tok.ID); ok {
		t.Fatal("another tenant resolved this token by ID")
	}
	if got, ok, err := s.TokenByHash(context.Background(), domain.HashSecret(secret)); err != nil || !ok || got.ID != tok.ID {
		t.Fatalf("by hash: ok=%t err=%v", ok, err)
	}
	if _, ok, _ := s.TokenByHash(context.Background(), domain.HashSecret("no-such-secret")); ok {
		t.Fatal("unknown hash resolved")
	}

	tokens, err := s.TokensByTenant(context.Background(), string(tenant))
	if err != nil || len(tokens) != 1 {
		t.Fatalf("tokens by tenant: %d, err=%v", len(tokens), err)
	}

	// Spend, then the revoke vocabulary: spent → ErrTokenSpent, unknown → ErrStoreNotFound.
	if _, ok, err := s.ClaimToken(context.Background(), tok.TokenHash, "plane-lc-"+runID, now); err != nil || !ok {
		t.Fatalf("claim: ok=%t err=%v", ok, err)
	}
	if err := s.RevokeToken(context.Background(), string(tenant), tok.ID, now); !errors.Is(err, domain.ErrTokenSpent) {
		t.Fatalf("revoke spent: %v, want ErrTokenSpent", err)
	}
	if err := s.RevokeToken(context.Background(), string(tenant), "no-such-token", now); !errors.Is(err, domain.ErrStoreNotFound) {
		t.Fatalf("revoke unknown: %v, want ErrStoreNotFound", err)
	}
}

// AC6's durable half (the app-level behaviour arrives with its own test): a
// released claim un-spends the token but keeps the recorded data plane, so a
// retry re-binds the SAME identity — never mints a new one.
func TestStore_ReleaseClaimKeepsRecordedDataPlane(t *testing.T) {
	s := store(t)
	tenant := tenantFor(t)
	now := time.Now()
	tok, secret := issueToken(t, s, tenant, now, time.Hour)

	first, ok, err := s.ClaimToken(context.Background(), tok.TokenHash, "plane-ac6-"+runID, now)
	if err != nil || !ok {
		t.Fatalf("claim: ok=%t err=%v", ok, err)
	}
	if err := s.ReleaseClaim(context.Background(), string(tenant), tok.ID); err != nil {
		t.Fatalf("release claim: %v", err)
	}
	released, ok, err := s.TokenByHash(context.Background(), domain.HashSecret(secret))
	if err != nil || !ok {
		t.Fatalf("lookup released: ok=%t err=%v", ok, err)
	}
	if released.Spent() {
		t.Fatal("released claim is still spent")
	}
	if released.DataPlaneID != first.DataPlaneID || released.DataPlaneID != "plane-ac6-"+runID {
		t.Fatalf("released claim lost its identity: %q", released.DataPlaneID)
	}

	// The retry spends it again — and the claim keeps the SAME recorded
	// identity even when the presenter argues for a new one.
	retried, ok, err := s.ClaimToken(context.Background(), tok.TokenHash, "plane-IMPOSTOR-"+runID, now.Add(time.Second))
	if err != nil || !ok {
		t.Fatalf("retry claim: ok=%t err=%v", ok, err)
	}
	if retried.DataPlaneID != "plane-ac6-"+runID {
		t.Fatalf("retry re-bound a NEW identity %q — one token minted two data planes", retried.DataPlaneID)
	}

	// Releasing something unspent or unknown is the shared not-found shape.
	if err := s.ReleaseClaim(context.Background(), string(tenant), "no-such-token"); !errors.Is(err, domain.ErrStoreNotFound) {
		t.Fatalf("release unknown: %v, want ErrStoreNotFound", err)
	}
}

func TestStore_PlaneLifecycle(t *testing.T) {
	s := store(t)
	tenant := tenantFor(t)
	now := time.Now()
	id := "plane-lifecycle-" + runID

	d := domain.DataPlane{
		ID: id, TenantID: string(tenant), Cloud: "aws", Region: "eu-central-1",
		AgentVersion: "0.1.0", K8sVersion: "1.31.0", Capabilities: []string{"ci"},
		EnrolledAt: now, LastSeenAt: now,
	}
	putPlane(t, s, d)

	got, ok, err := s.DataPlane(context.Background(), string(tenant), id)
	if err != nil || !ok {
		t.Fatalf("read: ok=%t err=%v", ok, err)
	}
	if got.Cloud != "aws" || !slices.Equal(got.Capabilities, []string{"ci"}) {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
	if _, ok, _ := s.DataPlane(context.Background(), string(tenant)+"-other", id); ok {
		t.Fatal("another tenant resolved this plane")
	}

	// Upsert: the AC6 retry writes the same identity again and converges.
	d.Cloud = "gcp"
	putPlane(t, s, d)
	planes, err := s.DataPlanesByTenant(context.Background(), string(tenant))
	if err != nil || len(planes) != 1 {
		t.Fatalf("planes by tenant: %d, err=%v", len(planes), err)
	}
	if planes[0].Cloud != "gcp" {
		t.Fatalf("upsert did not converge: %+v", planes[0])
	}

	if err := s.MarkSeen(context.Background(), string(tenant), id, now.Add(time.Minute)); err != nil {
		t.Fatalf("mark seen: %v", err)
	}
	if err := s.SetCertificate(context.Background(), string(tenant), id, "cert-9", now.Add(time.Hour)); err != nil {
		t.Fatalf("set certificate: %v", err)
	}
	got, _, _ = s.DataPlane(context.Background(), string(tenant), id)
	if !got.Certified() || got.LastSeenAt.IsZero() {
		t.Fatalf("cert/liveness not recorded: %+v", got)
	}

	if err := s.RevokeDataPlane(context.Background(), string(tenant), id, now); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	got, _, _ = s.DataPlane(context.Background(), string(tenant), id)
	if !got.Revoked() {
		t.Fatal("revocation not durable")
	}

	for _, miss := range []struct {
		name string
		fn   func() error
	}{
		{"mark seen unknown", func() error { return s.MarkSeen(context.Background(), string(tenant), "ghost", now) }},
		{"set certificate unknown", func() error { return s.SetCertificate(context.Background(), string(tenant), "ghost", "c", now) }},
		{"revoke unknown", func() error { return s.RevokeDataPlane(context.Background(), string(tenant), "ghost", now) }},
	} {
		if err := miss.fn(); !errors.Is(err, domain.ErrStoreNotFound) {
			t.Errorf("%s: %v, want ErrStoreNotFound", miss.name, err)
		}
	}
}

// Hash-only-at-rest: the raw secret's only appearance anywhere in this path
// is the caller's variable — the row stores its hash. Reading the row back
// through SQL as the app role must never yield the secret's bytes.
func TestStore_SecretIsNeverAtRest(t *testing.T) {
	s := store(t)
	tenant := tenantFor(t)
	_, secret := issueToken(t, s, tenant, time.Now(), time.Hour)

	pool := rawAppPool(t)
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	if _, err := tx.Exec(t.Context(), fmt.Sprintf("SET LOCAL app.tenant_id = '%s'", tenant)); err != nil {
		t.Fatal(err)
	}
	rows, err := tx.Query(t.Context(),
		`SELECT id, tenant_id, issued_by, token_hash, data_plane_id FROM agent.enrolment_tokens`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		vals, err := rows.Values()
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range vals {
			if b, ok := v.([]byte); ok && strings.Contains(string(b), secret) {
				t.Fatal("raw secret found at rest in agent.enrolment_tokens")
			}
			if str, ok := v.(string); ok && strings.Contains(str, secret) {
				t.Fatal("raw secret found at rest in agent.enrolment_tokens")
			}
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
}
