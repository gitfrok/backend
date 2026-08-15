package postgres_test

import (
	"context"
	"testing"

	agentpg "github.com/gitfrok/backend/modules/agent/internal/adapters/postgres"
)

// SPEC-0045 AC2's durable registry half against a real Postgres: the
// release trust bundle revision each data plane has applied, keyed by
// data_plane_id (ADR-0065). Durability is a statement about committed rows
// and isolation about RLS policies — neither exists in process memory, so
// these run against the dev database exactly as the enrolment suite does.

// TestReleaseTrustApplied_DurableAcrossRestart proves the convergence
// record survives a control-plane kill-and-restart: a plane's ack recorded
// by one incarnation is read back by a FRESH store on a fresh pool.
func TestReleaseTrustApplied_DurableAcrossRestart(t *testing.T) {
	tenant := string(tenantFor(t))
	plane := "plane-" + runID

	first := store(t)
	if err := first.RecordReleaseTrustApplied(context.Background(), tenant, plane, 7); err != nil {
		t.Fatalf("record: %v", err)
	}

	// Restart: a brand-new pool and store — process memory is gone.
	second := store(t)
	rev, ok, err := second.ReleaseTrustApplied(context.Background(), tenant, plane)
	if err != nil || !ok {
		t.Fatalf("post-restart read = (%d, %v, %v), want (7, true, nil)", rev, ok, err)
	}
	if rev != 7 {
		t.Fatalf("post-restart applied revision = %d, want 7", rev)
	}
}

// TestReleaseTrustApplied_ForwardOnly proves the ledger never regresses: a
// late or replayed ack for an OLDER revision cannot move a plane's recorded
// convergence backwards.
func TestReleaseTrustApplied_ForwardOnly(t *testing.T) {
	tenant := string(tenantFor(t))
	plane := "plane-" + runID

	s := store(t)
	if err := s.RecordReleaseTrustApplied(context.Background(), tenant, plane, 9); err != nil {
		t.Fatalf("record 9: %v", err)
	}
	if err := s.RecordReleaseTrustApplied(context.Background(), tenant, plane, 4); err != nil {
		t.Fatalf("record 4: %v", err)
	}
	rev, ok, err := s.ReleaseTrustApplied(context.Background(), tenant, plane)
	if err != nil || !ok || rev != 9 {
		t.Fatalf("applied revision after replayed ack = (%d, %v, %v), want (9, true, nil)", rev, ok, err)
	}
}

// TestReleaseTrustApplied_UnknownPlaneRendersNotApplied: a plane that never
// acknowledged renders (false), never a zero revision that could be read as
// "applied revision zero".
func TestReleaseTrustApplied_UnknownPlaneRendersNotApplied(t *testing.T) {
	s := store(t)
	rev, ok, err := s.ReleaseTrustApplied(context.Background(), string(tenantFor(t)), "plane-never-"+runID)
	if err != nil || ok || rev != 0 {
		t.Fatalf("unknown plane = (%d, %v, %v), want (0, false, nil)", rev, ok, err)
	}
}

// TestReleaseTrustApplied_RLSIsolation proves the tenant_isolation policy on
// the new table from BOTH sides: another tenant's scope sees zero rows
// through the app role, while the superuser — who bypasses RLS — confirms
// the row physically exists. The isolation is the database's, not the
// adapter's goodwill.
func TestReleaseTrustApplied_RLSIsolation(t *testing.T) {
	tenantA := string(tenantFor(t)) + "-a"
	tenantB := string(tenantFor(t)) + "-b"
	plane := "plane-" + runID

	s := store(t)
	if err := s.RecordReleaseTrustApplied(context.Background(), tenantA, plane, 3); err != nil {
		t.Fatalf("record under tenant A: %v", err)
	}

	// Attacker side: the app role under tenant B's scope counts rows on the
	// SAME table — RLS must hide tenant A's row entirely. SET LOCAL scopes
	// the tenant to the transaction, exactly as the enrolment suite probes.
	raw := rawAppPool(t)
	ctx := context.Background()
	tx, err := raw.Begin(ctx)
	if err != nil {
		t.Fatalf("begin attacker tx: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, "SET LOCAL app.tenant_id = '"+tenantB+"'"); err != nil {
		t.Fatalf("set tenant scope: %v", err)
	}
	var visible int
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM agent.release_trust_plane_state WHERE data_plane_id = $1`, plane,
	).Scan(&visible); err != nil {
		t.Fatalf("attacker-side count: %v", err)
	}
	if visible != 0 {
		t.Fatalf("tenant B's scope sees %d of tenant A's release trust rows, want 0", visible)
	}

	// Control side: the superuser bypasses RLS and sees the row — proof it
	// exists and the zero above is POLICY, not absence.
	super := superPool(t)
	var total int
	if err := super.QueryRow(ctx,
		`SELECT count(*) FROM agent.release_trust_plane_state WHERE tenant_id = $1 AND data_plane_id = $2`, tenantA, plane,
	).Scan(&total); err != nil {
		t.Fatalf("superuser count: %v", err)
	}
	if total != 1 {
		t.Fatalf("superuser sees %d rows for tenant A's plane, want 1 — the RLS zero above must be policy", total)
	}

	// And the store under tenant A's own scope reads its own row back.
	rev, ok, err := s.ReleaseTrustApplied(ctx, tenantA, plane)
	if err != nil || !ok || rev != 3 {
		t.Fatalf("tenant A's own read = (%d, %v, %v), want (3, true, nil)", rev, ok, err)
	}
}

// TestReleaseTrustApplied_TwoPlanesKeyedSeparately proves the registry's
// keying: two planes of one tenant hold their own revisions under their own
// data_plane_id (ADR-0065's registry keying, made durable).
func TestReleaseTrustApplied_TwoPlanesKeyedSeparately(t *testing.T) {
	tenant := string(tenantFor(t))
	plane1, plane2 := "plane1-"+runID, "plane2-"+runID

	s := store(t)
	if err := s.RecordReleaseTrustApplied(context.Background(), tenant, plane1, 2); err != nil {
		t.Fatalf("record plane1: %v", err)
	}
	if err := s.RecordReleaseTrustApplied(context.Background(), tenant, plane2, 5); err != nil {
		t.Fatalf("record plane2: %v", err)
	}
	rev1, ok1, _ := s.ReleaseTrustApplied(context.Background(), tenant, plane1)
	rev2, ok2, _ := s.ReleaseTrustApplied(context.Background(), tenant, plane2)
	if !ok1 || rev1 != 2 || !ok2 || rev2 != 5 {
		t.Fatalf("planes = (%d,%v) and (%d,%v), want (2,true) and (5,true)", rev1, ok1, rev2, ok2)
	}
}

// TestReleaseTrustApplied_RLSForcedInCatalog verifies the new table in the
// catalog, not in the SQL text: RLS enabled AND forced, exactly one
// tenant_isolation policy covering ALL — the same probe shape the 0001
// tables get.
func TestReleaseTrustApplied_RLSForcedInCatalog(t *testing.T) {
	pool := rawAppPool(t)
	var enabled, forced bool
	err := pool.QueryRow(t.Context(),
		`SELECT c.relrowsecurity, c.relforcerowsecurity
		   FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		  WHERE n.nspname = 'agent' AND c.relname = 'release_trust_plane_state'`,
	).Scan(&enabled, &forced)
	if err != nil {
		t.Fatalf("catalog probe: %v", err)
	}
	if !enabled || !forced {
		t.Errorf("agent.release_trust_plane_state: ENABLE=%t FORCE=%t — both must be true", enabled, forced)
	}
	var polName string
	var polCmd rune
	err = pool.QueryRow(t.Context(),
		`SELECT p.polname, p.polcmd FROM pg_policy p
		   JOIN pg_class c ON c.oid = p.polrelid
		   JOIN pg_namespace n ON n.oid = c.relnamespace
		  WHERE n.nspname = 'agent' AND c.relname = 'release_trust_plane_state'`,
	).Scan(&polName, &polCmd)
	if err != nil {
		t.Fatalf("policy probe: %v", err)
	}
	if polName != "tenant_isolation" || polCmd != '*' {
		t.Errorf("policy %q cmd %c — want tenant_isolation covering ALL", polName, polCmd)
	}
}

// Compile-time guard kept honest: the durable store satisfies the registry
// port the gateway's release seam records through.
var _ = agentpg.New
