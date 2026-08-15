package migrations

import (
	"os"
	"strings"
	"testing"
)

// T-0036 / SPEC-0042 AC5. The migration itself is the reviewable boundary:
// both tables RLS-enabled AND forced with a tenant_isolation policy each,
// minimal grants, and no deletion path for the application role. Style
// clones identity's migration_test.go — text assertions over the SQL, so the
// privilege surface is reviewed where it is declared, not remembered.
func TestEnrolmentMigrationIsRLSIsolated(t *testing.T) {
	sql := readSQL(t, "0001_agent_enrolment.sql")
	for _, want := range []string{
		// RLS markers the arch lint keys off.
		"-- rls: tenant-key=tenant_id",
		"CREATE TABLE IF NOT EXISTS agent.enrolment_tokens",
		"CREATE TABLE IF NOT EXISTS agent.data_planes",
		// Both tables isolated: enabled AND forced, one policy each.
		"ALTER TABLE agent.enrolment_tokens ENABLE ROW LEVEL SECURITY",
		"ALTER TABLE agent.enrolment_tokens FORCE ROW LEVEL SECURITY",
		"ALTER TABLE agent.data_planes ENABLE ROW LEVEL SECURITY",
		"ALTER TABLE agent.data_planes FORCE ROW LEVEL SECURITY",
		"CREATE POLICY tenant_isolation ON agent.enrolment_tokens",
		"CREATE POLICY tenant_isolation ON agent.data_planes",
		"tenant_id = current_setting('app.tenant_id', true)",
		// Minimal grants; revocation is an UPDATE, never a DELETE.
		"GRANT SELECT, INSERT, UPDATE ON agent.enrolment_tokens, agent.data_planes TO gitfrok_app",
		"REVOKE DELETE, TRUNCATE ON agent.enrolment_tokens, agent.data_planes FROM gitfrok_app",
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("migration missing %q", want)
		}
	}
	// The policy must bind both directions, or an insert could cross tenants.
	if strings.Count(sql, "WITH CHECK (tenant_id = current_setting('app.tenant_id', true))") != 2 {
		t.Error("expected one WITH CHECK tenant binding per table")
	}
}

// SPEC-0042 AC5: tokens persist as one-way hashes only. The raw secret must
// have no at-rest form — the only token-bearing column is the UNIQUE BYTEA
// hash the exempt paths key on.
func TestEnrolmentMigrationStoresHashesOnly(t *testing.T) {
	sql := readSQL(t, "0001_agent_enrolment.sql")
	if !strings.Contains(sql, "token_hash    BYTEA NOT NULL UNIQUE") &&
		!strings.Contains(strings.Join(strings.Fields(sql), " "), "token_hash BYTEA NOT NULL UNIQUE") {
		t.Error("migration missing the UNIQUE BYTEA token_hash column")
	}
	for _, forbidden := range []string{
		"token TEXT", "token_secret", "raw_token", "plaintext",
	} {
		if strings.Contains(strings.ToLower(sql), strings.ToLower(forbidden)) {
			t.Errorf("migration stores a raw-token form: %q", forbidden)
		}
	}
}

// SPEC-0042 AC5: the pre-tenancy exemption is enumerated, not implied.
// Exactly two SECURITY DEFINER functions may exist in this migration — the
// hash-keyed lookup and the atomic claim — each narrow, fixed and
// search_path-pinned. A third one fails this test the way the live-database
// enumeration test in store_test.go fails it at runtime.
func TestExemptPathsAreNarrowAndEnumerated(t *testing.T) {
	sql := readSQL(t, "0001_agent_enrolment.sql")

	// Count only function-definition occurrences (their own line), not prose
	// in the header comment.
	if got := strings.Count(sql, "\nSECURITY DEFINER\n"); got != 2 {
		t.Fatalf("expected exactly 2 SECURITY DEFINER exempt paths, found %d", got)
	}
	for _, want := range []string{
		// Shape clones identity.resolve_active_credential (ADR-0043).
		"CREATE OR REPLACE FUNCTION agent.lookup_enrolment_token(",
		"CREATE OR REPLACE FUNCTION agent.claim_enrolment_token(",
		"LANGUAGE sql",
		"SET search_path = pg_catalog, agent",
		"REVOKE ALL ON FUNCTION agent.lookup_enrolment_token(BYTEA) FROM PUBLIC",
		"GRANT EXECUTE ON FUNCTION agent.lookup_enrolment_token(BYTEA) TO gitfrok_app",
		"REVOKE ALL ON FUNCTION agent.claim_enrolment_token(BYTEA, TEXT) FROM PUBLIC",
		"GRANT EXECUTE ON FUNCTION agent.claim_enrolment_token(BYTEA, TEXT) TO gitfrok_app",
		// The re-apply drops the superseded caller-clock signature first, or
		// CREATE OR REPLACE would leave two claim functions beside each other.
		"DROP FUNCTION IF EXISTS agent.claim_enrolment_token(BYTEA, TEXT, TIMESTAMPTZ);",
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("migration missing %q", want)
		}
	}

	// The claim clock is SERVER-SIDE (identity.resolve_active_credential
	// precedent): no caller-supplied time parameter survives anywhere in the
	// migration, and both the spend instant and the expiry guard read now().
	if strings.Contains(sql, "p_now") {
		t.Error("claim function still takes a caller-supplied clock (p_now) — the guard and spent_at must read now()")
	}

	// Both exempt paths match the UNIQUE hash column only — never a tenant
	// scan, never a range — so each returns at most one row by construction.
	if got := strings.Count(sql, "t.token_hash = p_token_hash"); got != 2 {
		t.Errorf("expected both exempt paths keyed on token_hash, found %d", got)
	}

	// The claim is one atomic conditional UPDATE, not a select-then-update.
	for _, want := range []string{
		"UPDATE agent.enrolment_tokens AS t",
		"SET spent_at = now()",
		"t.spent_at IS NULL",
		"t.revoked_at IS NULL",
		"t.expires_at > now()",
		"RETURNING",
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("claim function missing guard %q", want)
		}
	}

	// ADR-0060: a released claim keeps its recorded data plane so a retry
	// re-binds to the SAME identity — the claim must never overwrite one.
	if !strings.Contains(sql, "CASE WHEN t.data_plane_id <> ''") {
		t.Error("claim function overwrites a recorded data_plane_id — one token could mint two identities")
	}

	// The lookup stays read-only: no write inside the resolver.
	lookup := sqlSegment(t, sql, "CREATE OR REPLACE FUNCTION agent.lookup_enrolment_token", "$$;")
	for _, forbidden := range []string{"INSERT", "UPDATE", "DELETE"} {
		if strings.Contains(lookup, forbidden) {
			t.Errorf("lookup function contains forbidden write %q", forbidden)
		}
	}
}

// SPEC-0042 AC5: the migration is additive AND rollback-tested. The down
// file must undo exactly the up file's surface, dependencies first.
func TestDownMigrationUndoesUp(t *testing.T) {
	down := readSQL(t, "0001_agent_enrolment.down.sql")

	for _, want := range []string{
		"DROP FUNCTION IF EXISTS agent.claim_enrolment_token(BYTEA, TEXT, TIMESTAMPTZ)",
		"DROP FUNCTION IF EXISTS agent.lookup_enrolment_token(BYTEA)",
		"DROP TABLE IF EXISTS agent.data_planes",
		"DROP TABLE IF EXISTS agent.enrolment_tokens",
		"DROP SCHEMA IF EXISTS agent",
	} {
		if !strings.Contains(down, want) {
			t.Errorf("down migration missing %q", want)
		}
	}

	// Dependency order: functions (which reference the table) before the
	// table, the table before its schema.
	order := []string{
		"DROP FUNCTION IF EXISTS agent.claim_enrolment_token",
		"DROP TABLE IF EXISTS agent.enrolment_tokens",
		"DROP SCHEMA IF EXISTS agent",
	}
	pos := 0
	for _, o := range order {
		i := strings.Index(down, o)
		if i < pos {
			t.Errorf("down migration drops out of order at %q", o)
		}
		pos = i
	}

	// The down must not leave the up's surface behind, and must not create
	// anything new.
	for _, forbidden := range []string{"CREATE TABLE", "CREATE POLICY", "GRANT"} {
		if strings.Contains(down, forbidden) {
			t.Errorf("down migration contains forbidden %q", forbidden)
		}
	}
}

func readSQL(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// sqlSegment returns the text between the marker and the first terminator
// after it, so one function's body can be asserted without another's text
// leaking in.
func sqlSegment(t *testing.T, sql, marker, terminator string) string {
	t.Helper()
	start := strings.Index(sql, marker)
	if start < 0 {
		t.Fatalf("marker %q not found", marker)
	}
	rest := sql[start:]
	end := strings.Index(rest, terminator)
	if end < 0 {
		t.Fatalf("terminator %q not found after %q", terminator, marker)
	}
	return rest[:end+len(terminator)]
}
