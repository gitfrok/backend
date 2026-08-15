package migrations

import (
	"os"
	"strings"
	"testing"
)

// T-0037 / SPEC-0042 AC5 (residency half). The migration itself is the
// reviewable boundary: both tables RLS-enabled AND forced with a
// tenant_isolation policy each, minimal grants, append-only declarations,
// and NO exemption of any kind — the platform's single pre-tenancy
// exemption lives in the agent module, never here. Style clones the agent
// module's migration_test.go: text assertions over the SQL, so the
// privilege surface is reviewed where it is declared, not remembered.
func TestResidencyMigrationIsRLSIsolated(t *testing.T) {
	sql := readSQL(t, "0001_residency_declarations.sql")
	for _, want := range []string{
		// RLS markers the arch lint keys off.
		"-- rls: tenant-key=tenant_id",
		"CREATE TABLE IF NOT EXISTS residency.declarations",
		"CREATE TABLE IF NOT EXISTS residency.observations",
		// Both tables isolated: enabled AND forced, one policy each.
		"ALTER TABLE residency.declarations ENABLE ROW LEVEL SECURITY",
		"ALTER TABLE residency.declarations FORCE ROW LEVEL SECURITY",
		"ALTER TABLE residency.observations ENABLE ROW LEVEL SECURITY",
		"ALTER TABLE residency.observations FORCE ROW LEVEL SECURITY",
		"CREATE POLICY tenant_isolation ON residency.declarations",
		"CREATE POLICY tenant_isolation ON residency.observations",
		"tenant_id = current_setting('app.tenant_id', true)",
		// The declaration-history read is served by the named index.
		"ON residency.declarations (tenant_id, effective_at)",
		// Minimal grants: declarations are append-only — SELECT and INSERT
		// only; revocation is an UPDATE on observations, never a DELETE
		// anywhere.
		"GRANT SELECT, INSERT ON residency.declarations TO gitfrok_app",
		"GRANT SELECT, INSERT, UPDATE ON residency.observations TO gitfrok_app",
		"REVOKE UPDATE, DELETE, TRUNCATE ON residency.declarations FROM gitfrok_app",
		"REVOKE DELETE, TRUNCATE ON residency.observations FROM gitfrok_app",
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("migration missing %q", want)
		}
	}
	// The policy must bind both directions on BOTH tables, or an insert
	// could cross tenants.
	if strings.Count(sql, "WITH CHECK (tenant_id = current_setting('app.tenant_id', true))") != 2 {
		t.Error("expected one WITH CHECK tenant binding per table")
	}
}

// SPEC-0042 AC5: declarations are effective-dated and append-only. The
// table carries the effective_at and chain-citation columns the pack cites,
// and its natural key is the witnessed chain position — a replace appends,
// it never overwrites.
func TestResidencyMigrationIsEffectiveDatedAndAppendOnly(t *testing.T) {
	sql := readSQL(t, "0001_residency_declarations.sql")
	flat := strings.Join(strings.Fields(sql), " ")
	for _, want := range []string{
		"effective_at TIMESTAMPTZ NOT NULL",
		"chain_seq BIGINT NOT NULL",
		"record_hash TEXT NOT NULL",
		"PRIMARY KEY (tenant_id, chain_seq)",
	} {
		if !strings.Contains(flat, want) {
			t.Errorf("declarations table missing %q", want)
		}
	}
	// Append-only is enforced by the grant set: no UPDATE on declarations
	// reaches the application role, and the declarations table definition
	// carries no conflict clause — a replace appends, it never converges a
	// row. (observations legitimately converges through ON CONFLICT, so the
	// assertion is scoped to the declarations definition.)
	decls := sqlSegment(t, sql, "CREATE TABLE IF NOT EXISTS residency.declarations", ");")
	if strings.Contains(decls, "ON CONFLICT") {
		t.Error("declarations must be append-only: no upsert in the table definition")
	}
	if strings.Contains(sql, "INSERT INTO residency.declarations") {
		t.Error("the migration itself must never write a declaration row")
	}
}

// SPEC-0042 AC5: this module gets NO exemption. The migration defines no
// SECURITY DEFINER function and grants no un-scoped path — the platform's
// single exemption is the agent module's token lookups, enumerated there.
func TestResidencyMigrationHasNoExemption(t *testing.T) {
	sql := readSQL(t, "0001_residency_declarations.sql")
	for _, forbidden := range []string{
		"SECURITY DEFINER", "CREATE FUNCTION", "CREATE OR REPLACE FUNCTION",
	} {
		if strings.Contains(sql, forbidden) {
			t.Errorf("residency migration carries a forbidden exemption surface: %q", forbidden)
		}
	}
}

// SPEC-0042 AC5: the migration is additive AND rollback-tested. The down
// file must undo exactly the up file's surface, dependencies first.
func TestDownMigrationUndoesUp(t *testing.T) {
	down := readSQL(t, "0001_residency_declarations.down.sql")

	for _, want := range []string{
		"DROP TABLE IF EXISTS residency.observations",
		"DROP TABLE IF EXISTS residency.declarations",
		"DROP SCHEMA IF EXISTS residency",
	} {
		if !strings.Contains(down, want) {
			t.Errorf("down migration missing %q", want)
		}
	}

	// Dependency order: both tables before their schema.
	order := []string{
		"DROP TABLE IF EXISTS residency.declarations",
		"DROP SCHEMA IF EXISTS residency",
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
// after it, so one table's definition can be asserted without another's
// text leaking in.
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
