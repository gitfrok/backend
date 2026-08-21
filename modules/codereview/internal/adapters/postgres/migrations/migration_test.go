package migrations

import (
	"os"
	"strings"
	"testing"
)

// T-0078 / SPEC-0061 AC13, AC14, AC15, AC16. The migration is the reviewable boundary: what this
// context may store, and what the application role may do to it, are decided here — so they are
// asserted here rather than inferred from an adapter that could change under them.
//
// Style follows the identity, residency and repository modules: text assertions over the SQL.

// normalized collapses runs of spaces so an assertion about a STATEMENT is not also an assertion
// about the column alignment that makes the file readable. The column-shape tests below read the
// unnormalised text on purpose: there, the padding is part of what is being asserted.
func normalized(sql string) string {
	return strings.Join(strings.Fields(sql), " ")
}

func readSQL(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// AC13: every table is tenant-scoped, RLS enabled AND forced, one policy each.
func TestEveryTableIsRLSIsolated(t *testing.T) {
	sql := normalized(readSQL(t, "0001_codereview.sql"))
	tables := []string{"merge_requests", "reviews", "branch_protections", "ref_revisions", "applied_requests"}

	if !strings.Contains(sql, "-- rls: tenant-key=tenant_id") {
		t.Error("the marker T-0004's arch lint reads is missing")
	}
	for _, table := range tables {
		for _, want := range []string{
			"CREATE TABLE IF NOT EXISTS codereview." + table,
			"ALTER TABLE codereview." + table + " ENABLE ROW LEVEL SECURITY",
			"ALTER TABLE codereview." + table + " FORCE ROW LEVEL SECURITY",
			"CREATE POLICY tenant_isolation ON codereview." + table,
		} {
			if !strings.Contains(sql, want) {
				t.Errorf("%s: missing %q", table, want)
			}
		}
	}
	if !strings.Contains(sql, "tenant_id = current_setting('app.tenant_id', true)") {
		t.Error("the policy does not key on app.tenant_id, so it cannot fail closed when unset")
	}
}

// AC14: the application role reads and writes; it deletes nothing.
//
// Nothing in the Store port removes a merge request, a review, a protection or a ref revision —
// closing a merge request is a state change — so the capability is not granted rather than granted
// and left unused.
func TestTheApplicationRoleCannotDelete(t *testing.T) {
	sql := normalized(readSQL(t, "0001_codereview.sql"))
	for _, table := range []string{"merge_requests", "reviews", "branch_protections", "ref_revisions", "applied_requests"} {
		if !strings.Contains(sql, "GRANT SELECT, INSERT, UPDATE ON codereview."+table) {
			t.Errorf("%s: the app role's grant is not the minimal one", table)
		}
		if !strings.Contains(sql, "REVOKE DELETE, TRUNCATE ON codereview."+table) {
			t.Errorf("%s: DELETE and TRUNCATE are not revoked", table)
		}
	}
	if strings.Contains(sql, "GRANT ALL") || strings.Contains(sql, "GRANT DELETE") {
		t.Error("the migration grants deletion")
	}
}

// AC15: the domain's bound on external issue references is repeated at the column.
func TestTheReferenceBoundIsAtTheColumn(t *testing.T) {
	sql := normalized(readSQL(t, "0001_codereview.sql"))
	for _, want := range []string{
		"external_issues JSONB NOT NULL DEFAULT '[]'::jsonb",
		"jsonb_array_length(external_issues) <= 25",
		"jsonb_typeof(external_issues) = 'array'",
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("missing %q", want)
		}
	}
}

// AC9's schema half: a version is positive, and it is what the write guards on.
func TestTheVersionColumnIsBounded(t *testing.T) {
	sql := normalized(readSQL(t, "0001_codereview.sql"))
	if !strings.Contains(sql, "version BIGINT NOT NULL CHECK (version > 0)") {
		t.Error("the merge request's version is not bounded to positive")
	}
	if !strings.Contains(sql, "required_approvals INTEGER NOT NULL CHECK (required_approvals >= 0)") {
		t.Error("required_approvals must allow zero — a protected ref with no approval requirement " +
			"still refuses direct pushes")
	}
}

// The idempotency key and the `seen` request ID share a table because they are the same fact. The
// kind column is what keeps them legible; a table that could not tell them apart would be one where
// a replayed write and a created merge request collide on a key.
func TestAppliedRequestsDistinguishesItsTwoKinds(t *testing.T) {
	sql := normalized(readSQL(t, "0001_codereview.sql"))
	if !strings.Contains(sql, "kind TEXT NOT NULL CHECK (kind IN ('idempotency', 'seen'))") {
		t.Error("applied_requests does not constrain its kind")
	}
	if !strings.Contains(sql, "PRIMARY KEY (tenant_id, kind, key)") {
		t.Error("the key is not unique per kind, so the two kinds can collide")
	}
}
