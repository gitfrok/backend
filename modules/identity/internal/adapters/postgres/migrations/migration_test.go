package migrations

import (
	"os"
	"strings"
	"testing"
)

// ADR-0043 requires a single, narrow SECURITY DEFINER read path before a
// tenant context exists. This test keeps that privilege boundary reviewable in
// the migration rather than relying on an application-side convention.
func TestCredentialResolverMigrationIsNarrowAndReadOnly(t *testing.T) {
	b, err := os.ReadFile("0001_identity_credentials.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(b)
	for _, want := range []string{
		"CREATE OR REPLACE FUNCTION identity.resolve_active_credential",
		"SECURITY DEFINER",
		"SET search_path = pg_catalog, identity",
		"RETURNS TABLE (tenant_id TEXT, actor_id TEXT, roles TEXT[])",
		"credential_kind = p_kind",
		"key_id = p_key_id",
		"verifier = p_verifier",
		"revoked_at IS NULL",
		"GRANT EXECUTE ON FUNCTION identity.resolve_active_credential",
		"REVOKE ALL ON FUNCTION identity.resolve_active_credential",
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("migration missing %q", want)
		}
	}
	for _, forbidden := range []string{"INSERT INTO identity.", "UPDATE identity.", "DELETE FROM identity."} {
		if strings.Contains(sql, forbidden) {
			t.Errorf("resolver migration contains forbidden %q", forbidden)
		}
	}
}

// SPEC-0033: auditor grants are tenant-scoped, RLS-isolated and immutable.
// The migration itself is the reviewable boundary: RLS enabled AND forced,
// one tenant_isolation policy per table, minimal grants and no deletion path
// for the application role.
func TestAuditorGrantsMigrationIsRLSIsolatedAndImmutable(t *testing.T) {
	b, err := os.ReadFile("0002_identity_auditor_grants.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(b)
	for _, want := range []string{
		// RLS markers the arch lint keys off.
		"-- rls: tenant-key=tenant_id",
		// Both tables isolated: enabled AND forced, one policy each.
		"ALTER TABLE identity.auditor_grants ENABLE ROW LEVEL SECURITY",
		"ALTER TABLE identity.auditor_grants FORCE ROW LEVEL SECURITY",
		"ALTER TABLE identity.auditor_grant_transitions ENABLE ROW LEVEL SECURITY",
		"ALTER TABLE identity.auditor_grant_transitions FORCE ROW LEVEL SECURITY",
		"CREATE POLICY tenant_isolation ON identity.auditor_grants",
		"CREATE POLICY tenant_isolation ON identity.auditor_grant_transitions",
		"tenant_id = current_setting('app.tenant_id', true)",
		// The lifecycle invariants the schema encodes.
		"CHECK (range_from <= range_to)",
		"CHECK (cardinality(pack_ids) > 0)",
		"PRIMARY KEY (tenant_id, grant_id, kind)",
		"CREATE UNIQUE INDEX IF NOT EXISTS auditor_grant_issue_replay",
		// Minimal grants: revocation happens via UPDATE; lifecycle records are
		// never deleted by the application role.
		"GRANT SELECT, INSERT, UPDATE ON identity.auditor_grants TO gitfrok_app",
		"GRANT SELECT, INSERT ON identity.auditor_grant_transitions TO gitfrok_app",
		"REVOKE DELETE, TRUNCATE ON identity.auditor_grants, identity.auditor_grant_transitions FROM gitfrok_app",
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("migration missing %q", want)
		}
	}
	// State is deliberately not stored: expiry is a clock rendering, not a
	// column to move — a state column would reintroduce the operator action
	// AC3 removes.
	if strings.Contains(sql, "state TEXT") || strings.Contains(sql, "\"state\"") {
		t.Error("grant migration stores a state column — expiry must be the server's clock, not stored state")
	}
}
