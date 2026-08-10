package app

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/gitfrok/backend/modules/codereview/api"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
	"github.com/gitfrok/backend/platform/audit"
	"github.com/gitfrok/backend/platform/bus"
)

// actionPDP allows only the listed actions, so a test can assert which grant a
// path actually asks for rather than trusting a blanket allow.
type actionPDP struct {
	allow map[string]bool
	asked []policyapi.Request
}

func (p *actionPDP) Decide(_ context.Context, req policyapi.Request) (policyapi.Decision, error) {
	p.asked = append(p.asked, req)
	if !p.allow[req.Action] {
		return policyapi.Decision{Allowed: false, DecisionID: "d", PolicyRevision: "r"}, nil
	}
	return policyapi.Decision{Allowed: true, DecisionID: "d", PolicyRevision: "r"}, nil
}

// mappingFixture completes an import, then returns a service whose PDP grants
// exactly the actions given, plus the mapping events it publishes.
func mappingFixture(t *testing.T, allow ...string) (*ImportService, api.Import, *actionPDP, *[]audit.DeclaredActorMapped) {
	t.Helper()
	store := newStubImportStore()
	recordStore := NewMemoryRecordStore()
	b := bus.NewInProcess()

	granted := map[string]bool{"repository.import": true}
	setup := NewImportService(store, recordStore,
		&stubGitImporter{moved: []RefUpdate{{Ref: "refs/heads/main", Revision: "abc123"}}},
		&writingHistoryImporter{records: recordStore, put: importedFixture()},
		&actionPDP{allow: granted}, b)
	setup.newID = func() string { return "import-1" }
	setup.now = func() time.Time { return time.Unix(1780000000, 0).UTC() }
	imp, err := setup.Create(t.Context(), importRequest())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	pdp := &actionPDP{allow: map[string]bool{}}
	for _, action := range allow {
		pdp.allow[action] = true
	}
	svc := NewImportService(store, recordStore, &stubGitImporter{}, nil, pdp, b)
	// A counter, not a constant: with a fixed ID the idempotency assertion below
	// would pass even if a second mapping had been created.
	next := 0
	svc.newID = func() string {
		next++
		return fmt.Sprintf("mapping-%d", next)
	}
	svc.now = func() time.Time { return time.Unix(1780000000, 0).UTC() }

	mapped := &[]audit.DeclaredActorMapped{}
	b.Subscribe(audit.EventAudit, func(_ context.Context, e bus.Event) error {
		if ev, ok := e.(audit.DeclaredActorMapped); ok {
			*mapped = append(*mapped, ev)
		}
		return nil
	})
	return svc, imp, pdp, mapped
}

func mapRequest(imp api.Import) api.MapDeclaredActorRequest {
	return api.MapDeclaredActorRequest{
		Context: api.Context{
			TenantID: "tenant-a", RepositoryID: "repo-a", ActorID: "admin-a",
			ActorRoles: []string{"owner"}, RequestID: "req-map",
		},
		ImportID:       imp.ID,
		DeclaredActor:  "octocat",
		SourceInstance: "github.com",
		MappedActorID:  "user-7",
	}
}

// A mapping is a named admin's assertion: it is PDP-authorized under its own
// action, records who asserted it, and emits one first-party audit event naming
// that admin (SPEC-0011 AC10/AC22).
func TestMapDeclaredActorIsANamedAssertion(t *testing.T) {
	svc, imp, pdp, mapped := mappingFixture(t, "repository.import.map_actor")

	mapping, err := svc.MapDeclaredActor(t.Context(), mapRequest(imp))
	if err != nil {
		t.Fatalf("MapDeclaredActor: %v", err)
	}
	if mapping.AssertedBy != "admin-a" {
		t.Fatalf("asserted by %q, want the admin from the verified context", mapping.AssertedBy)
	}
	if mapping.ActorID != "user-7" || mapping.DeclaredActor != "octocat" || mapping.SourceInstance != "github.com" {
		t.Fatalf("mapping = %+v", mapping)
	}
	if len(pdp.asked) == 0 || pdp.asked[0].Action != "repository.import.map_actor" {
		t.Fatalf("PDP was asked %+v, want repository.import.map_actor", pdp.asked)
	}
	if pdp.asked[0].Resource.Type != "import" {
		t.Fatalf("resource type = %q, want import", pdp.asked[0].Resource.Type)
	}
	if len(*mapped) != 1 {
		t.Fatalf("DeclaredActorMapped events = %d, want exactly one", len(*mapped))
	}
	event := (*mapped)[0]
	if event.ActorID != "admin-a" || event.MappedActorID != "user-7" {
		t.Fatalf("event = %+v — the asserter and the asserted-about must not be swapped", event)
	}
}

// A caller without the mapping grant is denied, and nothing is recorded.
func TestMapDeclaredActorWithoutTheGrantIsDenied(t *testing.T) {
	svc, imp, _, mapped := mappingFixture(t, "repository.import.read")

	if _, err := svc.MapDeclaredActor(t.Context(), mapRequest(imp)); !errors.Is(err, ErrImportDenied) {
		t.Fatalf("MapDeclaredActor = %v, want ErrImportDenied", err)
	}
	if len(*mapped) != 0 {
		t.Fatal("a denied assertion still emitted an audit event")
	}
}

// A mapping never changes provenance: the imported record still reads as
// ATTESTED_IMPORT and its approval still satisfies no merge policy (AC23).
func TestMappingDoesNotChangeProvenance(t *testing.T) {
	svc, imp, _, _ := mappingFixture(t, "repository.import.map_actor", "repository.import.read")

	if _, err := svc.MapDeclaredActor(t.Context(), mapRequest(imp)); err != nil {
		t.Fatalf("MapDeclaredActor: %v", err)
	}
	page, err := svc.ListImportedHistory(t.Context(), api.ListImportedHistoryRequest{
		Context:  mapRequest(imp).Context,
		ImportID: imp.ID,
	})
	if err != nil {
		t.Fatalf("ListImportedHistory: %v", err)
	}
	record := page.MergeRequests[0]
	if record.Provenance.Class != api.AttestImported {
		t.Fatalf("class = %q after a mapping, want it unchanged", record.Provenance.Class)
	}
	if record.DeclaredCreator != "octocat" {
		t.Fatalf("declared creator = %q — a mapping rewrote the record", record.DeclaredCreator)
	}
	if record.Approvals[0].Provenance.Class != api.AttestImported {
		t.Fatal("an imported approval changed class after a mapping")
	}
}

// Re-asserting the same identity is idempotent; asserting a different one is
// refused rather than silently replacing another admin's claim.
func TestMappingIsIdempotentAndRefusesAConflict(t *testing.T) {
	svc, imp, _, mapped := mappingFixture(t, "repository.import.map_actor")

	first, err := svc.MapDeclaredActor(t.Context(), mapRequest(imp))
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	again, err := svc.MapDeclaredActor(t.Context(), mapRequest(imp))
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if again.MappingID != first.MappingID {
		t.Fatal("re-asserting the same identity created a second mapping")
	}

	conflicting := mapRequest(imp)
	conflicting.MappedActorID = "user-9"
	if _, err := svc.MapDeclaredActor(t.Context(), conflicting); !errors.Is(err, api.ErrMappingConflict) {
		t.Fatalf("conflicting assertion = %v, want ErrMappingConflict", err)
	}
	if len(*mapped) != 2 {
		t.Fatalf("audit events = %d, want one per accepted assertion", len(*mapped))
	}
}

// The same handle on another source instance is another person, so it maps
// independently rather than colliding with the first claim.
func TestHandleIsScopedToItsSourceInstance(t *testing.T) {
	svc, imp, _, _ := mappingFixture(t, "repository.import.map_actor", "repository.import.read")

	if _, err := svc.MapDeclaredActor(t.Context(), mapRequest(imp)); err != nil {
		t.Fatalf("first: %v", err)
	}
	elsewhere := mapRequest(imp)
	elsewhere.SourceInstance = "gitlab.example.com"
	elsewhere.MappedActorID = "user-9"
	if _, err := svc.MapDeclaredActor(t.Context(), elsewhere); err != nil {
		t.Fatalf("same handle on another instance: %v", err)
	}

	mappings, err := svc.ListDeclaredActorMappings(t.Context(), mapRequest(imp).Context, imp.ID)
	if err != nil {
		t.Fatalf("ListDeclaredActorMappings: %v", err)
	}
	if len(mappings) != 2 {
		t.Fatalf("mappings = %d, want one per (handle, instance) pair", len(mappings))
	}
}

// A mapping in another tenant is refused, and the refusal says nothing about
// whether the import exists.
func TestMappingDeniesAnotherTenant(t *testing.T) {
	svc, imp, _, _ := mappingFixture(t, "repository.import.map_actor")

	other := mapRequest(imp)
	other.Context.TenantID = "tenant-b"
	other.Context.ActorID = "admin-b"
	if _, err := svc.MapDeclaredActor(t.Context(), other); !errors.Is(err, ErrImportDenied) {
		t.Fatalf("cross-tenant assertion = %v, want ErrImportDenied", err)
	}
}

// A request missing the handle, its instance, or the identity being asserted is
// refused: a mapping with a hole in it is not an assertion anyone can be held to.
func TestIncompleteAssertionIsRefused(t *testing.T) {
	svc, imp, _, _ := mappingFixture(t, "repository.import.map_actor")

	for name, mutate := range map[string]func(*api.MapDeclaredActorRequest){
		"no handle":   func(r *api.MapDeclaredActorRequest) { r.DeclaredActor = "" },
		"no instance": func(r *api.MapDeclaredActorRequest) { r.SourceInstance = "" },
		"no identity": func(r *api.MapDeclaredActorRequest) { r.MappedActorID = "" },
		"no import":   func(r *api.MapDeclaredActorRequest) { r.ImportID = "" },
		"no admin":    func(r *api.MapDeclaredActorRequest) { r.Context.ActorID = "" },
	} {
		t.Run(name, func(t *testing.T) {
			req := mapRequest(imp)
			mutate(&req)
			if _, err := svc.MapDeclaredActor(t.Context(), req); err == nil {
				t.Fatalf("an assertion with %s was accepted", name)
			}
		})
	}
}

// A revoked import has no records left to describe, so it accepts no mapping and
// returns none (AC24).
func TestRevokedImportAcceptsNoMapping(t *testing.T) {
	svc, imp, pdp, _ := mappingFixture(t, "repository.import.map_actor", "repository.import.revoke", "repository.import.read")
	pdp.allow["repository.import.revoke"] = true

	if _, err := svc.MapDeclaredActor(t.Context(), mapRequest(imp)); err != nil {
		t.Fatalf("MapDeclaredActor: %v", err)
	}
	if _, err := svc.Revoke(t.Context(), api.RevokeImportRequest{
		Context:  mapRequest(imp).Context,
		ImportID: imp.ID,
	}); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	if _, err := svc.MapDeclaredActor(t.Context(), mapRequest(imp)); !errors.Is(err, ErrImportDenied) {
		t.Fatalf("assertion on a revoked import = %v, want ErrImportDenied", err)
	}
	mappings, err := svc.ListDeclaredActorMappings(t.Context(), mapRequest(imp).Context, imp.ID)
	if err != nil {
		t.Fatalf("ListDeclaredActorMappings: %v", err)
	}
	if len(mappings) != 0 {
		t.Fatalf("a revoked import returned %d mappings", len(mappings))
	}
}
