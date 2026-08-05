package arch

import (
	"os"
	"path/filepath"
	"testing"
)

// SPEC-0001 AC4. Same three-layer shape as the boundary tests: scan the real tree, prove each rule
// fires on a fixture built to break it, and prove legitimate SQL is not flagged. Without the middle
// layer, "no violations" on a clean tree would be indistinguishable from a lint that checks nothing.

// The real migrations must be clean. This is the assertion that actually protects the database.
func TestRealMigrationsAreTenantScoped(t *testing.T) {
	root := repoRoot(t)
	vs, err := CheckMigrations(root)
	if err != nil {
		t.Fatalf("lint: %v", err)
	}
	for _, v := range vs {
		t.Errorf("migration violation: %s", v)
	}
}

// Every rule must be reachable. A rule nobody can trip is a rule that is not enforcing anything.
func TestEachRuleFiresOnItsFixture(t *testing.T) {
	dir := filepath.Join("testdata", "migrations-bad")
	want := map[string]string{
		"0001_no_tenant_col.sql":      RuleMissingTenantColumn,
		"0002_no_rls.sql":             RuleMissingRLS,
		"0003_rls_but_no_policy.sql":  RuleMissingPolicy,
		"0004_enabled_not_forced.sql": RuleMissingRLS,
	}
	for file, rule := range want {
		b, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil {
			t.Fatalf("read fixture %s: %v", file, err)
		}
		vs := lintMigration(file, string(b))
		if !hasMigrationRule(vs, rule) {
			t.Errorf("%s did not produce %s; got %v — the rule is not enforcing anything", file, rule, vs)
		}
	}
}

// 0004 is the subtle one and deserves its own assertion: ENABLE without FORCE leaves the table
// owner exempt, and migrations typically run as the owner. It looks protected and is not.
func TestEnableWithoutForceIsAViolation(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("testdata", "migrations-bad", "0004_enabled_not_forced.sql"))
	if err != nil {
		t.Fatal(err)
	}
	vs := lintMigration("0004", string(b))
	if !hasMigrationRule(vs, RuleMissingRLS) {
		t.Error("ENABLE ROW LEVEL SECURITY without FORCE was accepted; the owner would bypass every policy")
	}
}

// Legitimate SQL must pass, including the documented exemption. A lint that also rejects correct
// migrations gets disabled, and then it protects nothing.
func TestLegitimateMigrationsAreAccepted(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("testdata", "migrations-good", "0001_ok.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if vs := lintMigration("0001_ok.sql", string(b)); len(vs) != 0 {
		t.Errorf("clean migration was flagged: %v", vs)
	}
}

// The `-- rls: tenant-key=<col>` escape hatch must work, since the tenant registry itself relies on
// it — and it must not become a blanket exemption: the named column still has to exist.
func TestTenantKeyExemptionRequiresTheNamedColumn(t *testing.T) {
	ok := `-- rls: tenant-key=id
CREATE TABLE tenant.tenants (id TEXT PRIMARY KEY, name TEXT NOT NULL);
ALTER TABLE tenant.tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant.tenants FORCE ROW LEVEL SECURITY;
CREATE POLICY p ON tenant.tenants FOR ALL USING (id = current_setting('app.tenant_id', true));`
	if vs := lintMigration("x.sql", ok); len(vs) != 0 {
		t.Errorf("tenant-key exemption rejected a valid table: %v", vs)
	}

	missing := `-- rls: tenant-key=account_id
CREATE TABLE repo.thing (id TEXT PRIMARY KEY, name TEXT NOT NULL);
ALTER TABLE repo.thing ENABLE ROW LEVEL SECURITY;
ALTER TABLE repo.thing FORCE ROW LEVEL SECURITY;
CREATE POLICY p ON repo.thing FOR ALL USING (true);`
	if vs := lintMigration("y.sql", missing); !hasMigrationRule(vs, RuleMissingTenantColumn) {
		t.Error("tenant-key named a column that does not exist and was accepted — the exemption is a hole")
	}
}

func hasMigrationRule(vs []MigrationViolation, rule string) bool {
	for _, v := range vs {
		if v.Rule == rule {
			return true
		}
	}
	return false
}
