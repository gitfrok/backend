package migrations

import (
	"os"
	"strings"
	"testing"
)

// T-0068 / SPEC-0057 AC11/AC12 at the schema. The migration is the reviewable boundary: what a
// settings surface may store is decided here, and the two things ADR-0076 refused are refused by
// their absence from a file rather than by anyone remembering.
//
// Style follows the identity and residency modules' migration tests: text assertions over the SQL, so
// the privilege surface is reviewed where it is declared.

func readSQL(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The registry is RLS-isolated and the settings migration does not touch that. It is asserted here
// because 0002 ALTERs the table 0001 protects: a migration that dropped the policy to add a column
// would still apply cleanly.
func TestRegistryMigrationIsRLSIsolated(t *testing.T) {
	sql := readSQL(t, "0001_repository_registry.sql")
	for _, want := range []string{
		"-- rls: tenant-key=tenant_id",
		"CREATE TABLE IF NOT EXISTS repo.repositories",
		"ALTER TABLE repo.repositories ENABLE ROW LEVEL SECURITY",
		"ALTER TABLE repo.repositories FORCE ROW LEVEL SECURITY",
		"CREATE POLICY tenant_isolation ON repo.repositories",
		"tenant_id = current_setting('app.tenant_id', true)",
		"GRANT SELECT, INSERT, UPDATE ON repo.repositories TO gitfrok_app",
		"REVOKE DELETE, TRUNCATE ON repo.repositories FROM gitfrok_app",
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("0001 no longer contains %q", want)
		}
	}
}

// AC8: the settings columns are additive, nullable where absence is a real state, and paired.
func TestSettingsMigrationIsAdditiveAndPaired(t *testing.T) {
	sql := readSQL(t, "0002_repository_settings.sql")
	for _, want := range []string{
		"ADD COLUMN IF NOT EXISTS description         TEXT        NOT NULL DEFAULT ''",
		"ADD COLUMN IF NOT EXISTS archived_at         TIMESTAMPTZ",
		"ADD COLUMN IF NOT EXISTS settings_updated_at TIMESTAMPTZ",
		"ADD COLUMN IF NOT EXISTS settings_updated_by TEXT",
		"repositories_description_bounded CHECK (length(description) <= 4096)",
		"repositories_settings_change_is_whole",
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("0002 does not contain %q", want)
		}
	}
	// archived_at carries no NOT NULL and no default: "not archived" is an absence, and a zero
	// timestamp would make every repository in the registry claim an archival date.
	if strings.Contains(sql, "archived_at         TIMESTAMPTZ NOT NULL") {
		t.Error("archived_at must be nullable — not archived is an absence, not an instant")
	}
}

// AC11: the schema has no column for anything ADR-0076 refused. A settings table with a visibility
// column is how "public" arrives as a feature nobody decided.
func TestSettingsMigrationHasNoAuthorizationColumn(t *testing.T) {
	sql := strings.ToLower(readSQL(t, "0002_repository_settings.sql"))
	for _, forbidden := range []string{
		"add column if not exists visibility",
		"add column if not exists is_public",
		"add column if not exists members",
		"add column if not exists branch_protection",
		"add column if not exists required_approvals",
		"create table repo.members",
		"create table if not exists repo.members",
	} {
		if strings.Contains(sql, forbidden) {
			t.Errorf("0002 carries %q — outside ADR-0076's accepted increment", forbidden)
		}
	}
}

// AC12: the migration that delivers PR-30 does not restore the DELETE grant 0001 revoked while
// waiting for it. Deletion is still ADR-0076's deferred decision, and the grant set is where that
// stops being a promise.
func TestSettingsMigrationDoesNotRestoreTheDeleteGrant(t *testing.T) {
	sql := readSQL(t, "0002_repository_settings.sql")
	if strings.Contains(sql, "GRANT DELETE") || strings.Contains(sql, "GRANT ALL") {
		t.Error("0002 grants deletion — repository deletion is out of scope (ADR-0076 decision 3)")
	}
}

// The down migration reverses exactly what the up migration added, so a rollback does not leave a
// constraint referring to a column that no longer exists.
func TestSettingsMigrationIsReversible(t *testing.T) {
	down := readSQL(t, "0002_repository_settings.down.sql")
	for _, want := range []string{
		"DROP CONSTRAINT IF EXISTS repositories_settings_change_is_whole",
		"DROP CONSTRAINT IF EXISTS repositories_description_bounded",
		"DROP COLUMN IF EXISTS settings_updated_by",
		"DROP COLUMN IF EXISTS archived_at",
		"DROP COLUMN IF EXISTS description",
	} {
		if !strings.Contains(down, want) {
			t.Errorf("the down migration does not contain %q", want)
		}
	}
	if strings.Contains(down, "DROP TABLE") {
		t.Error("the down migration drops the table — it added columns, it must remove columns")
	}
}
