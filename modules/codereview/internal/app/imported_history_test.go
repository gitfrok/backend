package app

import (
	"context"
	"fmt"
	"testing"

	"github.com/gitfrok/backend/modules/codereview/api"
)

// seedImportedHistory records an import owned by tenantID and stores count
// imported merge requests under it, named so their order is checkable.
func seedImportedHistory(t *testing.T, svc *ImportService, store *stubImportStore, importID, tenantID string, count int) {
	t.Helper()
	store.imports[importID] = api.Import{
		ID: importID, TenantID: tenantID, RepositoryID: "repo-a",
		SourceSystem: "github", SourceInstance: "github.com",
		State: api.ImportComplete,
	}
	records := make([]api.ImportedMergeRequest, 0, count)
	for i := range count {
		records = append(records, api.ImportedMergeRequest{
			MergeRequestID:  fmt.Sprintf("mr-%02d", i),
			Title:           fmt.Sprintf("imported %d", i),
			State:           "merged",
			DeclaredCreator: "octocat",
			Provenance: api.Provenance{
				Class: api.AttestImported, ImportID: importID,
				SourceSystem: "github", SourceInstance: "github.com",
				DeclaredActor: "octocat",
			},
		})
	}
	if err := svc.records.PutImport(context.Background(), importID, records); err != nil {
		t.Fatalf("PutImport: %v", err)
	}
}

func readContext(tenantID string) api.Context {
	return api.Context{TenantID: tenantID, RepositoryID: "repo-a", ActorID: "actor-a", RequestID: "req-1"}
}

// The read pages: every record is returned exactly once, in a stable order, and
// the last page returns an empty token. An import may hold tens of thousands of
// records, so the surface must not depend on a caller asking for all of them.
func TestListImportedHistoryPages(t *testing.T) {
	store := newStubImportStore()
	svc, _, _, _ := newTestImportService(store, &stubGitImporter{}, &stubHistoryImporter{})
	seedImportedHistory(t, svc, store, "import-1", "tenant-a", 5)

	var seen []string
	token := ""
	for pages := 0; ; pages++ {
		if pages > 5 {
			t.Fatal("paging did not terminate")
		}
		page, err := svc.ListImportedHistory(context.Background(), api.ListImportedHistoryRequest{
			Context: readContext("tenant-a"), ImportID: "import-1", PageSize: 2, PageToken: token,
		})
		if err != nil {
			t.Fatalf("ListImportedHistory: %v", err)
		}
		if len(page.MergeRequests) > 2 {
			t.Fatalf("page held %d records, want at most 2", len(page.MergeRequests))
		}
		for _, mr := range page.MergeRequests {
			seen = append(seen, mr.MergeRequestID)
		}
		if page.NextPageToken == "" {
			break
		}
		token = page.NextPageToken
	}

	want := []string{"mr-00", "mr-01", "mr-02", "mr-03", "mr-04"}
	if len(seen) != len(want) {
		t.Fatalf("read %v, want %v", seen, want)
	}
	for i := range want {
		if seen[i] != want[i] {
			t.Fatalf("read %v, want %v", seen, want)
		}
	}
}

// Every returned record carries its ATTESTED_IMPORT provenance and its declared
// creator as an opaque handle. Without provenance on the record the reader has
// nothing to distinguish imported history with (AC23 depends on AC20).
func TestListImportedHistoryCarriesProvenance(t *testing.T) {
	store := newStubImportStore()
	svc, _, _, _ := newTestImportService(store, &stubGitImporter{}, &stubHistoryImporter{})
	seedImportedHistory(t, svc, store, "import-1", "tenant-a", 1)

	page, err := svc.ListImportedHistory(context.Background(), api.ListImportedHistoryRequest{
		Context: readContext("tenant-a"), ImportID: "import-1",
	})
	if err != nil {
		t.Fatalf("ListImportedHistory: %v", err)
	}
	if len(page.MergeRequests) != 1 {
		t.Fatalf("records = %d, want 1", len(page.MergeRequests))
	}
	record := page.MergeRequests[0]
	if record.Provenance.Class != api.AttestImported {
		t.Fatalf("class = %q, want %q", record.Provenance.Class, api.AttestImported)
	}
	if record.Provenance.ImportID != "import-1" || record.Provenance.SourceSystem != "github" {
		t.Fatalf("provenance = %+v", record.Provenance)
	}
	if record.DeclaredCreator != "octocat" {
		t.Fatalf("declared creator = %q", record.DeclaredCreator)
	}
}

// A revoked import returns nothing: its records are dropped from every read
// (AC17). The import row itself still exists, so this is the read path
// respecting the tombstone rather than the row having vanished.
func TestListImportedHistoryOfRevokedImportIsEmpty(t *testing.T) {
	store := newStubImportStore()
	svc, _, _, _ := newTestImportService(store, &stubGitImporter{}, &stubHistoryImporter{})
	seedImportedHistory(t, svc, store, "import-1", "tenant-a", 3)

	if _, err := svc.Revoke(context.Background(), api.RevokeImportRequest{
		Context: readContext("tenant-a"), ImportID: "import-1",
	}); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	page, err := svc.ListImportedHistory(context.Background(), api.ListImportedHistoryRequest{
		Context: readContext("tenant-a"), ImportID: "import-1",
	})
	if err != nil {
		t.Fatalf("ListImportedHistory: %v", err)
	}
	if len(page.MergeRequests) != 0 || page.NextPageToken != "" {
		t.Fatalf("revoked import returned %+v", page)
	}
}

// A read from another tenant is denied, and the denial does not distinguish a
// cross-tenant import from one that does not exist (invariants 1-2, AC21).
func TestListImportedHistoryDeniesAnotherTenant(t *testing.T) {
	store := newStubImportStore()
	svc, _, _, _ := newTestImportService(store, &stubGitImporter{}, &stubHistoryImporter{})
	seedImportedHistory(t, svc, store, "import-1", "tenant-a", 3)

	_, err := svc.ListImportedHistory(context.Background(), api.ListImportedHistoryRequest{
		Context: readContext("tenant-b"), ImportID: "import-1",
	})
	if err == nil {
		t.Fatal("a cross-tenant read was allowed")
	}
	_, missing := svc.ListImportedHistory(context.Background(), api.ListImportedHistoryRequest{
		Context: readContext("tenant-b"), ImportID: "import-nonexistent",
	})
	if err.Error() != missing.Error() {
		t.Fatalf("cross-tenant %v distinguishable from missing %v", err, missing)
	}
}

// A caller cannot ask for the whole set: an oversized page size is clamped, and
// an unset one takes the default.
func TestListImportedHistoryClampsPageSize(t *testing.T) {
	store := newStubImportStore()
	svc, _, _, _ := newTestImportService(store, &stubGitImporter{}, &stubHistoryImporter{})
	seedImportedHistory(t, svc, store, "import-1", "tenant-a", api.MaxImportedHistoryPageSize+10)

	page, err := svc.ListImportedHistory(context.Background(), api.ListImportedHistoryRequest{
		Context: readContext("tenant-a"), ImportID: "import-1", PageSize: 10_000,
	})
	if err != nil {
		t.Fatalf("ListImportedHistory: %v", err)
	}
	if len(page.MergeRequests) != api.MaxImportedHistoryPageSize {
		t.Fatalf("page held %d records, want the %d cap", len(page.MergeRequests), api.MaxImportedHistoryPageSize)
	}
	if page.NextPageToken == "" {
		t.Fatal("a clamped page claimed to be the last one")
	}

	defaulted, err := svc.ListImportedHistory(context.Background(), api.ListImportedHistoryRequest{
		Context: readContext("tenant-a"), ImportID: "import-1",
	})
	if err != nil {
		t.Fatalf("ListImportedHistory: %v", err)
	}
	if len(defaulted.MergeRequests) != api.DefaultImportedHistoryPageSize {
		t.Fatalf("default page held %d records, want %d", len(defaulted.MergeRequests), api.DefaultImportedHistoryPageSize)
	}
}

// A page token that names nothing in this import returns an empty page rather
// than restarting from the beginning: a reader that silently restarts would
// loop forever, and one that dumps the whole set ignores the cap.
func TestListImportedHistoryUnknownTokenReturnsNothing(t *testing.T) {
	store := newStubImportStore()
	svc, _, _, _ := newTestImportService(store, &stubGitImporter{}, &stubHistoryImporter{})
	seedImportedHistory(t, svc, store, "import-1", "tenant-a", 3)

	page, err := svc.ListImportedHistory(context.Background(), api.ListImportedHistoryRequest{
		Context: readContext("tenant-a"), ImportID: "import-1", PageToken: "mr-zz",
	})
	if err != nil {
		t.Fatalf("ListImportedHistory: %v", err)
	}
	if len(page.MergeRequests) != 0 || page.NextPageToken != "" {
		t.Fatalf("unknown token returned %+v", page)
	}
}

// An empty context, or an empty import ID, is a coarse denial.
func TestListImportedHistoryRequiresVerifiedContext(t *testing.T) {
	store := newStubImportStore()
	svc, _, _, _ := newTestImportService(store, &stubGitImporter{}, &stubHistoryImporter{})
	seedImportedHistory(t, svc, store, "import-1", "tenant-a", 1)

	for name, req := range map[string]api.ListImportedHistoryRequest{
		"no context":   {ImportID: "import-1"},
		"no actor":     {Context: api.Context{TenantID: "tenant-a", RepositoryID: "repo-a"}, ImportID: "import-1"},
		"no import id": {Context: readContext("tenant-a")},
	} {
		if _, err := svc.ListImportedHistory(context.Background(), req); err == nil {
			t.Fatalf("%s was allowed", name)
		}
	}
}
