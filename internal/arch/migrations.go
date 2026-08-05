package arch

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Migration lint — SPEC-0001 AC4, T-0004.
//
// A tenant-owned table with no `tenant_id` and no RLS policy is a cross-tenant leak that no code
// review reliably catches, because the omission is invisible: the table works perfectly, for
// everyone, including people it should not work for. The application-layer scoping in platform/db
// cannot save it either — RLS is the half that survives a caller who forgets.
//
// LAYOUT (T-0004): migrations live beside the module that owns the schema —
//
//	modules/<ctx>/internal/adapters/postgres/migrations/*.sql
//
// which is "each module owns its schema" (backend AGENTS.md) expressed on disk. The tenant registry
// itself is not owned by any single context, so the baseline lives at
//
//	platform/db/migrations/*.sql
//
// and is linted by exactly the same rules.
//
// WHAT THIS DOES NOT DO: it is a text lint, not a migration runner, and nothing applies these files
// yet — the dev cluster still creates its schema from deploy/dev/postgres.yaml. Recorded in T-0004
// rather than implied, because a lint over files nobody runs would otherwise look like enforcement.

// MigrationRoots are the directories scanned for migration SQL, relative to the repo root.
var MigrationRoots = []string{
	"platform/db/migrations",
	"modules", // walked for */internal/adapters/postgres/migrations
}

// RuleMissingTenantColumn fires when a tenant-owned table has no tenant-scoping column.
const RuleMissingTenantColumn = "migration-missing-tenant-column"

// RuleMissingRLS fires when a tenant-owned table does not enable *and* force row-level security.
const RuleMissingRLS = "migration-missing-rls"

// RuleMissingPolicy fires when a tenant-owned table has RLS but no policy — which denies everything
// rather than isolating anything, so it fails closed but is still wrong.
const RuleMissingPolicy = "migration-missing-policy"

// MigrationViolation is one lint finding.
type MigrationViolation struct {
	File  string
	Table string
	Rule  string
}

func (v MigrationViolation) String() string {
	return fmt.Sprintf("%s: table %s: %s", v.File, v.Table, v.Rule)
}

var (
	createTableRe = regexp.MustCompile(`(?is)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-zA-Z_][\w.]*)\s*\(`)
	// An escape hatch that must be written down next to the table it exempts. Two forms:
	//   -- rls: not-tenant-owned   (reference data shared by every tenant)
	//   -- rls: tenant-key=<col>   (the tenant is identified by a differently named column)
	exemptRe    = regexp.MustCompile(`(?i)--\s*rls:\s*not-tenant-owned`)
	tenantKeyRe = regexp.MustCompile(`(?i)--\s*rls:\s*tenant-key\s*=\s*([a-zA-Z_]\w*)`)
)

// CheckMigrations lints every migration under root and returns the violations found.
func CheckMigrations(root string) ([]MigrationViolation, error) {
	files, err := migrationFiles(root)
	if err != nil {
		return nil, err
	}
	var vs []MigrationViolation
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		rel, _ := filepath.Rel(root, f)
		vs = append(vs, lintMigration(filepath.ToSlash(rel), string(b))...)
	}
	return vs, nil
}

func migrationFiles(root string) ([]string, error) {
	var out []string
	for _, r := range MigrationRoots {
		dir := filepath.Join(root, r)
		if _, err := os.Stat(dir); err != nil {
			continue // a root that does not exist yet is not a violation
		}
		err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".sql") {
				return nil
			}
			// Under modules/, only the conventional location counts. A stray .sql elsewhere is not
			// a migration, and treating it as one would make the lint fire on fixtures and dumps.
			slash := filepath.ToSlash(path)
			if strings.Contains(slash, "/modules/") &&
				!strings.Contains(slash, "/internal/adapters/postgres/migrations/") {
				return nil
			}
			out = append(out, path)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// lintMigration checks one file's CREATE TABLE statements.
//
// Deliberately a text lint rather than a SQL parse: the rules are about whether three specific
// statements are present for each table, and a parser would add a dependency and a second dialect
// to keep in step with Postgres for no additional signal.
func lintMigration(file, sql string) []MigrationViolation {
	var vs []MigrationViolation

	for _, m := range createTableRe.FindAllStringSubmatchIndex(sql, -1) {
		table := sql[m[2]:m[3]]
		body, ok := tableBody(sql, m[1]-1) // m[1]-1 is the opening paren
		if !ok {
			continue
		}
		// The statement plus whatever follows it, so the RLS/policy statements that belong to this
		// table are in view without needing to attribute every statement in the file.
		rest := sql[m[1]:]

		if exemptRe.MatchString(body) || exemptRe.MatchString(precedingComment(sql, m[0])) {
			continue
		}

		tenantCol := "tenant_id"
		if km := tenantKeyRe.FindStringSubmatch(body + precedingComment(sql, m[0])); km != nil {
			tenantCol = km[1]
		}
		if !regexp.MustCompile(`(?i)(^|[^\w])` + regexp.QuoteMeta(tenantCol) + `\s`).MatchString(body) {
			vs = append(vs, MigrationViolation{File: file, Table: table, Rule: RuleMissingTenantColumn})
		}

		enabled := matchesTable(rest, table, `ENABLE\s+ROW\s+LEVEL\s+SECURITY`)
		forced := matchesTable(rest, table, `FORCE\s+ROW\s+LEVEL\s+SECURITY`)
		if !enabled || !forced {
			// FORCE matters as much as ENABLE: without it the table owner is exempt, and migrations
			// commonly run as the owner, so a policy that looks enforced silently is not.
			vs = append(vs, MigrationViolation{File: file, Table: table, Rule: RuleMissingRLS})
		}
		if !regexp.MustCompile(`(?is)CREATE\s+POLICY\s+\w+\s+ON\s+` + regexp.QuoteMeta(table)).MatchString(rest) {
			vs = append(vs, MigrationViolation{File: file, Table: table, Rule: RuleMissingPolicy})
		}
	}
	return vs
}

// matchesTable reports whether an ALTER TABLE <table> ... <what> statement appears in sql.
func matchesTable(sql, table, what string) bool {
	re := regexp.MustCompile(`(?is)ALTER\s+TABLE\s+(?:ONLY\s+)?` + regexp.QuoteMeta(table) + `\s+` + what)
	return re.MatchString(sql)
}

// tableBody returns the parenthesised column list starting at open.
func tableBody(sql string, open int) (string, bool) {
	if open < 0 || open >= len(sql) || sql[open] != '(' {
		return "", false
	}
	depth := 0
	for i := open; i < len(sql); i++ {
		switch sql[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return sql[open+1 : i], true
			}
		}
	}
	return "", false
}

// precedingComment returns the comment lines immediately above a statement, so an exemption may be
// written where a reader looks for it rather than only inside the column list.
func precedingComment(sql string, start int) string {
	lines := strings.Split(sql[:start], "\n")
	var out []string
	for i := len(lines) - 1; i >= 0 && i > len(lines)-6; i-- {
		l := strings.TrimSpace(lines[i])
		if l == "" {
			continue
		}
		if !strings.HasPrefix(l, "--") {
			break
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}
