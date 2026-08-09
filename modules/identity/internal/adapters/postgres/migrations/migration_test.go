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
		"CREATE FUNCTION identity.resolve_active_credential",
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
