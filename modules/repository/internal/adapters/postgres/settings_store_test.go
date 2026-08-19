package postgres_test

import (
	"strings"
	"testing"
	"time"

	repopg "github.com/gitfrok/backend/modules/repository/internal/adapters/postgres"
	"github.com/gitfrok/backend/modules/repository/internal/domain"
	"github.com/gitfrok/backend/platform/tenancy"
)

// SPEC-0057 AC8 and AC9 against a real Postgres.
//
// The claims are about what the DATABASE keeps and what it permits: that settings survive the
// process, that the who/when of a change cannot be written as half a record, and that a settings
// write for one tenant under a context scoped to another is refused before any statement runs.
// None of that exists in process memory, so a fake would prove a fake behaves.
//
// **Carried limit 5 applies.** Without TEST_DATABASE_URL these SKIP, and what skips is the
// isolation proof. Count the skips before believing the exit record.

var settingsAt = time.Date(2026, 8, 19, 9, 30, 0, 0, time.UTC)

// AC8: the description, the archived instant and the who/when of the change survive the store that
// wrote them.
func TestSettingsSurviveTheStoreThatWroteThem(t *testing.T) {
	pool := openPool(t)
	tenant := tenantFor(t)

	r := repo(tenant, "alpha", "Alpha")
	r.Description = "the cluster"
	r.ArchivedAt = settingsAt
	r.SettingsUpdatedAt = settingsAt
	r.SettingsUpdatedBy = "user-9"

	if err := repopg.New(pool).Save(t.Context(), r); err != nil {
		t.Fatalf("save: %v", err)
	}

	got, err := repopg.New(pool).Load(t.Context(), tenant, "alpha")
	if err != nil {
		t.Fatalf("load after rebuild: %v", err)
	}
	if got.Description != "the cluster" {
		t.Errorf("description did not survive: %q", got.Description)
	}
	if !got.IsArchived() || !got.ArchivedAt.Equal(settingsAt) {
		t.Errorf("archival did not survive: %+v", got.ArchivedAt)
	}
	if got.SettingsUpdatedBy != "user-9" || !got.SettingsUpdatedAt.Equal(settingsAt) {
		t.Errorf("the who and the when did not survive: %q at %v", got.SettingsUpdatedBy, got.SettingsUpdatedAt)
	}
}

// AC8: a repository nobody has touched reads back as unarchived with no settings change, rather than
// as archived at the zero time.
//
// The columns are nullable for this reason, and it is not cosmetic: a zero timestamp would make every
// repository in the registry claim it was archived, and the archived label is the one thing this
// surface renders.
func TestAnUntouchedRepositoryIsNotArchived(t *testing.T) {
	pool := openPool(t)
	tenant := tenantFor(t)
	store := repopg.New(pool)

	if err := store.Save(t.Context(), repo(tenant, "plain", "Plain")); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := store.Load(t.Context(), tenant, "plain")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.IsArchived() {
		t.Errorf("a repository nobody archived reads as archived at %v", got.ArchivedAt)
	}
	if !got.SettingsUpdatedAt.IsZero() || got.SettingsUpdatedBy != "" {
		t.Errorf("a repository whose settings nobody changed claims a change: %q at %v",
			got.SettingsUpdatedBy, got.SettingsUpdatedAt)
	}
}

// AC8: archiving and unarchiving converge on the row rather than accumulating rows.
func TestArchivingAndUnarchivingConvergeOnTheRow(t *testing.T) {
	pool := openPool(t)
	tenant := tenantFor(t)
	store := repopg.New(pool)

	r := repo(tenant, "cycle", "Cycle")
	if err := store.Save(t.Context(), r); err != nil {
		t.Fatalf("save: %v", err)
	}

	archived, changed, err := r.WithArchived(true, "user-1", settingsAt)
	if err != nil || !changed {
		t.Fatalf("WithArchived: changed=%v err=%v", changed, err)
	}
	if err := store.Save(t.Context(), archived); err != nil {
		t.Fatalf("save archived: %v", err)
	}

	active, changed, err := archived.WithArchived(false, "user-1", settingsAt.Add(time.Hour))
	if err != nil || !changed {
		t.Fatalf("WithArchived back: changed=%v err=%v", changed, err)
	}
	if err := store.Save(t.Context(), active); err != nil {
		t.Fatalf("save active: %v", err)
	}

	got, err := store.Load(t.Context(), tenant, "cycle")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.IsArchived() {
		t.Error("unarchiving did not clear the instant in the database")
	}
	// The candidate list is where a duplicated row would show: the registry is the truth for
	// existence, and one repository must appear once.
	candidates, err := store.Candidates(t.Context(), tenant, "", 10)
	if err != nil {
		t.Fatalf("candidates: %v", err)
	}
	if len(candidates) != 1 {
		t.Errorf("want one row for one repository, got %d", len(candidates))
	}
}

// AC7 at the database: an archived repository is still a candidate.
//
// Archival narrowing a list would be archival changing a read outcome, which is the boundary
// ADR-0076 decision 1 draws. The app layer asserts it over the use case; this asserts the adapter
// does not quietly filter.
func TestAnArchivedRepositoryIsStillACandidate(t *testing.T) {
	pool := openPool(t)
	tenant := tenantFor(t)
	store := repopg.New(pool)

	r := repo(tenant, "archived", "Archived")
	r.ArchivedAt = settingsAt
	r.SettingsUpdatedAt = settingsAt
	r.SettingsUpdatedBy = "user-1"
	if err := store.Save(t.Context(), r); err != nil {
		t.Fatalf("save: %v", err)
	}

	candidates, err := store.Candidates(t.Context(), tenant, "", 10)
	if err != nil {
		t.Fatalf("candidates: %v", err)
	}
	if len(candidates) != 1 || !candidates[0].IsArchived() {
		t.Fatalf("an archived repository must still be a candidate, and still say it is archived: %+v", candidates)
	}
}

// AC8: the who and the when cannot be written as half a record — the column constraint refuses.
func TestASettingsChangeCannotBeHalfRecorded(t *testing.T) {
	pool := openPool(t)
	tenant := tenantFor(t)
	store := repopg.New(pool)

	half := repo(tenant, "half", "Half")
	half.SettingsUpdatedAt = settingsAt // an instant with nobody attached to it

	err := store.Save(t.Context(), half)
	if err == nil {
		t.Fatal("a settings change with an instant and no actor must be refused by the database")
	}
	if !strings.Contains(err.Error(), "repositories_settings_change_is_whole") {
		t.Errorf("want the pairing constraint to refuse it, got %v", err)
	}
}

// AC8: the description is bounded at the column, not only at the domain.
func TestTheDescriptionIsBoundedAtTheColumn(t *testing.T) {
	pool := openPool(t)
	tenant := tenantFor(t)
	store := repopg.New(pool)

	long := repo(tenant, "long", "Long")
	long.Description = strings.Repeat("x", domain.MaxDescriptionBytes+1)

	err := store.Save(t.Context(), long)
	if err == nil {
		t.Fatal("a description past the bound must be refused by the database")
	}
	if !strings.Contains(err.Error(), "repositories_description_bounded") {
		t.Errorf("want the description bound to refuse it, got %v", err)
	}
}

// AC8/AC9: a settings write for one tenant under a context scoped to another is refused before any
// database work — RLS cannot make this refusal, because the transaction would be scoped to the tenant
// the call named.
func TestASettingsWriteRefusesACrossTenantContext(t *testing.T) {
	pool := openPool(t)
	mine := tenantFor(t)
	theirs := domain.TenantID(string(mine) + "-other")
	store := repopg.New(pool)

	r := repo(theirs, "theirs", "Theirs")
	r.Description = "not mine to change"

	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(mine))
	err := store.Save(ctx, r)
	if err == nil {
		t.Fatal("a write for another tenant under this tenant's context must be refused")
	}
	if !strings.Contains(err.Error(), "refusing a call for tenant") {
		t.Errorf("want the scoping refusal, got %v", err)
	}
}
