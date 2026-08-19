package app_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/gitfrok/backend/modules/repository/api"
	"github.com/gitfrok/backend/modules/repository/internal/adapters/memstore"
	"github.com/gitfrok/backend/modules/repository/internal/app"
	"github.com/gitfrok/backend/platform/bus"
)

// SPEC-0057 AC1–AC7 at the application layer. AC8 and AC9 are the Postgres adapter's
// (store_test.go), because durability and RLS are properties of the adapter, not of the use case.

var settingsNow = time.Date(2026, 8, 19, 9, 30, 0, 0, time.UTC)

// allowAll and denyAll are the two decision points a settings test needs. They are separate from the
// listing tests' authorizer because settings ask a different question — `repo.admin`, not
// `repo.read` — and a fake that answered both with one bool would hide exactly the mistake worth
// catching: a read authorizer standing in for an administration one.
type fixedAdmin struct {
	allowed bool
	err     error
	asked   int
}

func (a *fixedAdmin) MayAdminister(context.Context, string, string, []string, string) (bool, error) {
	a.asked++
	return a.allowed, a.err
}

type fixedReader struct{ allowed bool }

func (r fixedReader) MayRead(context.Context, string, string, []string, string) (bool, error) {
	return r.allowed, nil
}

// trailSpy is the audit trail as this surface sees it: a list of records, in order.
type trailSpy struct {
	records []api.WitnessEntry
	err     error
}

func (t *trailSpy) AppendSettingsRecord(_ context.Context, e api.WitnessEntry) error {
	if t.err != nil {
		return t.err
	}
	t.records = append(t.records, e)
	return nil
}

type settingsFixture struct {
	svc   *app.Service
	admin *fixedAdmin
	trail *trailSpy
	bus   *recorder
}

func newSettingsFixture(t *testing.T, mayRead, mayAdminister bool) settingsFixture {
	t.Helper()
	rec := &recorder{}
	admin := &fixedAdmin{allowed: mayAdminister}
	trail := &trailSpy{}
	svc := app.New(memstore.New(), rec,
		app.WithClock(func() time.Time { return settingsNow }),
		app.WithAuthorizer(fixedReader{allowed: mayRead}),
		app.WithAdministrator(admin),
		app.WithWitness(trail),
	)
	if _, err := svc.Create(t.Context(), "t-1", "repo-1", "infra", "user-1"); err != nil {
		t.Fatalf("seeding: %v", err)
	}
	return settingsFixture{svc: svc, admin: admin, trail: trail, bus: rec}
}

// TestAC1_GetSettingsServesTheRecord: the read returns the record, and it is a repo.read decision.
func TestAC1_GetSettingsServesTheRecord(t *testing.T) {
	f := newSettingsFixture(t, true, true)

	got, err := f.svc.GetSettings(t.Context(), api.SettingsQuery{
		TenantID: "t-1", RepoID: "repo-1", ActorID: "user-1",
	})
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	if got.Name != "infra" || got.Description != "" {
		t.Errorf("unexpected settings %+v", got)
	}
	if got.Archived() {
		t.Error("a repository nobody archived is not archived")
	}
	if f.admin.asked != 0 {
		t.Error("reading settings must not ask repo.admin: a reader who can see the repository can see its name")
	}
}

// TestAC1_GetSettingsIsARepoReadDecision: a caller the read authorizer refuses learns nothing.
func TestAC1_GetSettingsIsARepoReadDecision(t *testing.T) {
	f := newSettingsFixture(t, false, true)

	if _, err := f.svc.GetSettings(t.Context(), api.SettingsQuery{
		TenantID: "t-1", RepoID: "repo-1", ActorID: "stranger",
	}); !errors.Is(err, api.ErrSettingsForbidden) {
		t.Fatalf("want the coarse refusal, got %v", err)
	}
}

// TestAC1_AnotherTenantsRepositoryIsAbsent: the refusal for a repository in another tenant is not a
// different shape from the refusal for one that does not exist. Both are the store's absence.
func TestAC1_AnotherTenantsRepositoryIsAbsent(t *testing.T) {
	f := newSettingsFixture(t, true, true)

	// Both calls are made by the same caller, in the same tenant, naming a repository that tenant
	// does not have. One of them exists in ANOTHER tenant; the other exists nowhere. The refusals
	// must be the same refusal, because the difference between them is the disclosure.
	_, inAnotherTenant := f.svc.GetSettings(t.Context(), api.SettingsQuery{
		TenantID: "t-2", RepoID: "repo-1", ActorID: "user-1",
	})
	_, nowhere := f.svc.GetSettings(t.Context(), api.SettingsQuery{
		TenantID: "t-2", RepoID: "repo-9", ActorID: "user-1",
	})
	if inAnotherTenant == nil || nowhere == nil {
		t.Fatal("both must refuse")
	}
	// The refusals quote the repository ID the caller itself sent, which discloses nothing. What
	// must not differ is anything else, so the ID is normalised away before comparing.
	left := strings.ReplaceAll(inAnotherTenant.Error(), "repo-1", "<asked>")
	right := strings.ReplaceAll(nowhere.Error(), "repo-9", "<asked>")
	if left != right {
		t.Errorf("a repository in another tenant is distinguishable from one that does not exist:\n other tenant: %v\n nowhere:      %v",
			inAnotherTenant, nowhere)
	}
}

// TestAC2_UpdateChangesNameAndDescriptionOnly.
func TestAC2_UpdateChangesNameAndDescriptionOnly(t *testing.T) {
	f := newSettingsFixture(t, true, true)

	got, err := f.svc.UpdateSettings(t.Context(), api.SettingsUpdate{
		TenantID: "t-1", RepoID: "repo-1", ActorID: "user-1",
		Name: "platform-infra", Description: "the cluster",
	})
	if err != nil {
		t.Fatalf("UpdateSettings: %v", err)
	}
	if got.Name != "platform-infra" || got.Description != "the cluster" {
		t.Errorf("unexpected settings %+v", got)
	}
	if got.SettingsUpdatedBy != "user-1" || !got.SettingsUpdatedAt.Equal(settingsNow) {
		t.Errorf("the who and the when must both be recorded: %+v", got)
	}
	if got.Archived() {
		t.Error("changing a name must not archive anything")
	}
}

// TestAC2_RenameToNothingIsRefused: the registry's CHECK says a repository has a name, and the domain
// says so first, so the caller learns which field it was.
func TestAC2_RenameToNothingIsRefused(t *testing.T) {
	f := newSettingsFixture(t, true, true)

	if _, err := f.svc.UpdateSettings(t.Context(), api.SettingsUpdate{
		TenantID: "t-1", RepoID: "repo-1", ActorID: "user-1", Name: "",
	}); err == nil {
		t.Fatal("a rename to nothing must be refused")
	}
	after, err := f.svc.GetSettings(t.Context(), api.SettingsQuery{TenantID: "t-1", RepoID: "repo-1", ActorID: "user-1"})
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	if after.Name != "infra" {
		t.Errorf("a refused write left the record changed: %+v", after)
	}
}

// TestAC3_ArchivingTwiceIsOneRecord: the same fact stated twice is accepted and writes nothing.
func TestAC3_ArchivingTwiceIsOneRecord(t *testing.T) {
	f := newSettingsFixture(t, true, true)
	req := api.ArchiveRequest{TenantID: "t-1", RepoID: "repo-1", ActorID: "user-1", Archived: true}

	first, err := f.svc.SetArchived(t.Context(), req)
	if err != nil {
		t.Fatalf("SetArchived: %v", err)
	}
	if !first.Archived() {
		t.Fatal("the repository must be archived")
	}

	second, err := f.svc.SetArchived(t.Context(), req)
	if err != nil {
		t.Fatalf("archiving an archived repository must be accepted, got %v", err)
	}
	if !second.ArchivedAt.Equal(first.ArchivedAt) {
		t.Errorf("the recorded instant moved: %v then %v", first.ArchivedAt, second.ArchivedAt)
	}
	if n := len(f.trail.records); n != 1 {
		t.Errorf("want exactly 1 audit record for two identical archive calls, got %d", n)
	}
}

// TestAC3_UnarchivingClearsTheInstant.
func TestAC3_UnarchivingClearsTheInstant(t *testing.T) {
	f := newSettingsFixture(t, true, true)
	base := api.ArchiveRequest{TenantID: "t-1", RepoID: "repo-1", ActorID: "user-1"}

	if _, err := f.svc.SetArchived(t.Context(), withArchived(base, true)); err != nil {
		t.Fatalf("archive: %v", err)
	}
	got, err := f.svc.SetArchived(t.Context(), withArchived(base, false))
	if err != nil {
		t.Fatalf("unarchive: %v", err)
	}
	if got.Archived() || !got.ArchivedAt.IsZero() {
		t.Errorf("unarchiving must clear the instant, got %+v", got)
	}
	if n := len(f.trail.records); n != 2 {
		t.Errorf("want 2 records — one archive, one unarchive — got %d", n)
	}
	if f.trail.records[1].Detail["archived"] != "active" {
		t.Errorf("the record must say what the state now is: %+v", f.trail.records[1].Detail)
	}
}

// TestAC4_EachAcceptedChangeAppendsExactlyOneRecord.
func TestAC4_EachAcceptedChangeAppendsExactlyOneRecord(t *testing.T) {
	f := newSettingsFixture(t, true, true)

	if _, err := f.svc.UpdateSettings(t.Context(), api.SettingsUpdate{
		TenantID: "t-1", RepoID: "repo-1", ActorID: "user-7", Name: "renamed", Description: "prose",
	}); err != nil {
		t.Fatalf("UpdateSettings: %v", err)
	}
	if n := len(f.trail.records); n != 1 {
		t.Fatalf("want 1 record, got %d", n)
	}
	rec := f.trail.records[0]
	if rec.Action != api.ActionSettingsUpdated {
		t.Errorf("want %q, got %q", api.ActionSettingsUpdated, rec.Action)
	}
	if rec.ActorID != "user-7" || rec.Resource != "repo-1" || rec.TenantID != "t-1" {
		t.Errorf("the record must name actor, repository and tenant: %+v", rec)
	}
	if rec.Denied {
		t.Error("an accepted change is not a denial")
	}
	if rec.Detail["name"] != "renamed" {
		t.Errorf("the record must say what the name now is: %+v", rec.Detail)
	}
	// The description's TEXT is deliberately not in the trail: the record says it was set, not
	// what it says. Free-form user prose is referenced from a control record, never carried into
	// one — the same rule ADR-0074 decision 2 states for issue text.
	if rec.Detail["description"] != "set" {
		t.Errorf("want the description recorded as set, got %q", rec.Detail["description"])
	}
	for k, v := range rec.Detail {
		if v == "prose" {
			t.Errorf("the audit record carries the description's text under %q", k)
		}
	}
}

// TestAC4_ArchivalIsItsOwnAction: "who renamed this" and "who archived this" are not one question.
func TestAC4_ArchivalIsItsOwnAction(t *testing.T) {
	f := newSettingsFixture(t, true, true)

	if _, err := f.svc.SetArchived(t.Context(), api.ArchiveRequest{
		TenantID: "t-1", RepoID: "repo-1", ActorID: "user-1", Archived: true,
	}); err != nil {
		t.Fatalf("SetArchived: %v", err)
	}
	if got := f.trail.records[0].Action; got != api.ActionArchivalChanged {
		t.Errorf("want %q, got %q", api.ActionArchivalChanged, got)
	}
}

// TestAC5_ARefusedChangeIsAuditedAndCoarse.
func TestAC5_ARefusedChangeIsAuditedAndCoarse(t *testing.T) {
	f := newSettingsFixture(t, true, false)

	_, err := f.svc.UpdateSettings(t.Context(), api.SettingsUpdate{
		TenantID: "t-1", RepoID: "repo-1", ActorID: "intruder", Name: "mine",
	})
	if !errors.Is(err, api.ErrSettingsForbidden) {
		t.Fatalf("want the coarse refusal, got %v", err)
	}
	if n := len(f.trail.records); n != 1 {
		t.Fatalf("a refusal that reached the PDP is a record; got %d records", n)
	}
	if !f.trail.records[0].Denied {
		t.Error("the record must be marked denied")
	}
	if f.trail.records[0].ActorID != "intruder" {
		t.Errorf("the record must name who was refused: %+v", f.trail.records[0])
	}
	after, err := f.svc.GetSettings(t.Context(), api.SettingsQuery{TenantID: "t-1", RepoID: "repo-1", ActorID: "user-1"})
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	if after.Name != "infra" {
		t.Errorf("the refused write changed the record: %+v", after)
	}
}

// TestAC5_APDPErrorIsARefusal: an unavailable decision point refuses the write. There is no reading
// of ADR-0006 in which a settings change proceeds because the PDP could not be reached.
func TestAC5_APDPErrorIsARefusal(t *testing.T) {
	f := newSettingsFixture(t, true, true)
	f.admin.err = errors.New("pdp unavailable")

	if _, err := f.svc.SetArchived(t.Context(), api.ArchiveRequest{
		TenantID: "t-1", RepoID: "repo-1", ActorID: "user-1", Archived: true,
	}); !errors.Is(err, api.ErrSettingsForbidden) {
		t.Fatalf("want the coarse refusal, got %v", err)
	}
}

// TestAC6_AnUnwitnessedChangeIsRefused: PR-30's clause is "each change audited". A service with no
// witness refuses rather than making a change it cannot record.
func TestAC6_AnUnwitnessedChangeIsRefused(t *testing.T) {
	rec := &recorder{}
	svc := app.New(memstore.New(), rec,
		app.WithClock(func() time.Time { return settingsNow }),
		app.WithAuthorizer(fixedReader{allowed: true}),
		app.WithAdministrator(&fixedAdmin{allowed: true}),
	)
	if _, err := svc.Create(t.Context(), "t-1", "repo-1", "infra", "user-1"); err != nil {
		t.Fatalf("seeding: %v", err)
	}

	if _, err := svc.UpdateSettings(t.Context(), api.SettingsUpdate{
		TenantID: "t-1", RepoID: "repo-1", ActorID: "user-1", Name: "renamed",
	}); !errors.Is(err, api.ErrNoWitness) {
		t.Fatalf("want ErrNoWitness, got %v", err)
	}
}

// TestAC6_NoAdministratorRefusesRatherThanAllows: the wrong default for "may administer" is yes.
func TestAC6_NoAdministratorRefusesRatherThanAllows(t *testing.T) {
	rec := &recorder{}
	svc := app.New(memstore.New(), rec,
		app.WithClock(func() time.Time { return settingsNow }),
		app.WithAuthorizer(fixedReader{allowed: true}),
		app.WithWitness(&trailSpy{}),
	)
	if _, err := svc.Create(t.Context(), "t-1", "repo-1", "infra", "user-1"); err != nil {
		t.Fatalf("seeding: %v", err)
	}

	if _, err := svc.SetArchived(t.Context(), api.ArchiveRequest{
		TenantID: "t-1", RepoID: "repo-1", ActorID: "user-1", Archived: true,
	}); !errors.Is(err, api.ErrNoAdministrationPoint) {
		t.Fatalf("want ErrNoAdministrationPoint, got %v", err)
	}
}

// TestAC6_AFailedAuditFailsTheWrite: if the record cannot be appended the caller is told, rather than
// receiving a success for a change the trail does not know about.
func TestAC6_AFailedAuditFailsTheWrite(t *testing.T) {
	f := newSettingsFixture(t, true, true)
	f.trail.err = errors.New("trail unavailable")

	if _, err := f.svc.UpdateSettings(t.Context(), api.SettingsUpdate{
		TenantID: "t-1", RepoID: "repo-1", ActorID: "user-1", Name: "renamed",
	}); err == nil {
		t.Fatal("an unrecordable change must not report success")
	}
}

// TestAC7_ArchivalChangesNoReadOutcome is ADR-0076 decision 1 in executable form.
//
// An archived repository still lists, still reads, and is still writable. If archival ever starts
// narrowing a read or producing a read-only condition, this test is what fails — and the failure is
// the point: an archive that refuses writes is a git-write-path decision with an audited override
// behind it, not a settings form (SPEC-0057's archival rule).
func TestAC7_ArchivalChangesNoReadOutcome(t *testing.T) {
	f := newSettingsFixture(t, true, true)
	if _, err := f.svc.SetArchived(t.Context(), api.ArchiveRequest{
		TenantID: "t-1", RepoID: "repo-1", ActorID: "user-1", Archived: true,
	}); err != nil {
		t.Fatalf("SetArchived: %v", err)
	}

	if _, err := f.svc.Get(t.Context(), "t-1", "repo-1"); err != nil {
		t.Errorf("an archived repository must still read: %v", err)
	}

	page, err := f.svc.List(t.Context(), api.ListQuery{TenantID: "t-1", ActorID: "user-1"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(page.Repositories) != 1 || page.Repositories[0].RepoID != "repo-1" {
		t.Errorf("an archived repository must still list: %+v", page.Repositories)
	}

	// The read-only vocabulary has exactly two causes and neither is archival. Constructing one
	// from an archived state is impossible by design; this asserts the writable condition is what
	// an archived repository reports.
	if state := api.Writable(); state.ReadOnly {
		t.Error("the writable condition must not be read-only")
	}
	if _, ok := api.NewReadOnlyState("archived"); ok {
		t.Error("archival must not be constructible as a read-only cause")
	}
}

// withArchived returns the request with its wanted state changed, so a test reads as two acts on one
// repository rather than as two unrelated literals.
func withArchived(a api.ArchiveRequest, archived bool) api.ArchiveRequest {
	a.Archived = archived
	return a
}

var _ bus.Bus = (*recorder)(nil)
