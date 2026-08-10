package app

import (
	"context"
	"testing"
	"time"

	"github.com/gitfrok/backend/modules/codereview/api"
	"github.com/gitfrok/backend/platform/bus"
)

// importWithRecords runs a complete import whose history phase writes the given
// records, and returns the service, the completed import, and the record store.
func importWithRecords(t *testing.T, records []api.ImportedMergeRequest) (*ImportService, api.Import, api.ImportedRecordStore) {
	t.Helper()
	store := newStubImportStore()
	recordStore := NewMemoryRecordStore()
	git := &stubGitImporter{moved: []RefUpdate{{Ref: "refs/heads/main", Revision: "abc123"}}}
	history := &writingHistoryImporter{records: recordStore, put: records}

	svc := NewImportService(store, recordStore, git, history, stubPDP{}, bus.NewInProcess())
	svc.newID = func() string { return "import-1" }
	svc.now = func() time.Time { return time.Unix(1780000000, 0).UTC() }

	imp, err := svc.Create(t.Context(), importRequest())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return svc, imp, recordStore
}

// writingHistoryImporter writes real records into the shared store, which is
// what the manifest is computed over.
type writingHistoryImporter struct {
	records api.ImportedRecordStore
	put     []api.ImportedMergeRequest
}

func (w *writingHistoryImporter) ImportHistory(ctx context.Context, command ImportHistoryCommand) (HistoryResult, error) {
	if err := w.records.PutImport(ctx, command.ImportID, w.put); err != nil {
		return HistoryResult{}, err
	}
	return HistoryResult{Counts: map[string]int64{"merge_requests": int64(len(w.put))}}, nil
}

func importedFixture() []api.ImportedMergeRequest {
	declared := time.Date(2019, 4, 2, 9, 30, 0, 0, time.UTC)
	provenance := api.Provenance{
		Class: api.AttestImported, ImportID: "import-1", SourceSystem: "github",
		SourceInstance: "github.com", SourceRef: "7", DeclaredActor: "octocat",
		DeclaredAt: declared, PayloadDigest: "sha256:pr",
	}
	return []api.ImportedMergeRequest{{
		MergeRequestID: "imported-7", SourceRef: "refs/heads/topic", TargetRef: "refs/heads/main",
		Title: "Old pull request", Description: "from GitHub", State: "merged",
		DeclaredCreator: "octocat", Provenance: provenance,
		Threads: []api.ImportedThread{{
			ThreadID: "thread-1", MergeRequestID: "imported-7", Path: "cmd/main.go",
			Anchor: api.AnchorDiff, Provenance: provenance,
			Comments: []api.ImportedComment{{
				CommentID: "comment-1", DeclaredActor: "octocat", Body: "looks fine to me",
				DeclaredAt: declared, Provenance: provenance,
			}},
		}},
		Approvals: []api.ImportedApproval{{
			ApprovalID: "approval-1", MergeRequestID: "imported-7", DeclaredActor: "hubber",
			DeclaredAt: declared, Provenance: provenance,
		}},
	}}
}

// The manifest digest verifies against the set it was computed over (AC16).
func TestManifestVerifiesAgainstTheImportedSet(t *testing.T) {
	svc, imp, _ := importWithRecords(t, importedFixture())
	if imp.ManifestDigest == "" {
		t.Fatal("a completed import recorded no manifest digest")
	}
	ok, err := svc.VerifyImport(t.Context(), importRequest().Context, imp.ID)
	if err != nil {
		t.Fatalf("VerifyImport: %v", err)
	}
	if !ok {
		t.Fatal("an untouched import failed verification")
	}
}

// Mutating any imported record afterwards makes verification fail. This is the
// half of AC16 a digest over metadata and counts alone could never deliver.
func TestMutatingAnImportedRecordFailsVerification(t *testing.T) {
	mutations := map[string]func(records []api.ImportedMergeRequest){
		"comment body": func(r []api.ImportedMergeRequest) {
			r[0].Threads[0].Comments[0].Body = "actually this is terrible"
		},
		"declared actor": func(r []api.ImportedMergeRequest) {
			r[0].Threads[0].Comments[0].DeclaredActor = "someone-else"
		},
		"declared time": func(r []api.ImportedMergeRequest) {
			r[0].Threads[0].Comments[0].DeclaredAt = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
		},
		"mr title": func(r []api.ImportedMergeRequest) {
			r[0].Title = "A different pull request"
		},
		"approval actor": func(r []api.ImportedMergeRequest) {
			r[0].Approvals[0].DeclaredActor = "an-approver-who-never-approved"
		},
		"thread anchor": func(r []api.ImportedMergeRequest) {
			r[0].Threads[0].Anchor = api.AnchorMerge
		},
		"provenance payload digest": func(r []api.ImportedMergeRequest) {
			r[0].Provenance.PayloadDigest = "sha256:forged"
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			records := importedFixture()
			svc, imp, recordStore := importWithRecords(t, records)

			// Mutate the stored set behind the service's back — the shape a
			// tamper takes when it does not go through an API surface (AC18
			// guarantees none exists).
			stored, err := recordStore.ListImport(t.Context(), imp.ID)
			if err != nil {
				t.Fatalf("ListImport: %v", err)
			}
			mutate(stored)
			if err := recordStore.PutImport(t.Context(), imp.ID, stored); err != nil {
				t.Fatalf("PutImport: %v", err)
			}

			ok, err := svc.VerifyImport(t.Context(), importRequest().Context, imp.ID)
			if err != nil {
				t.Fatalf("VerifyImport: %v", err)
			}
			if ok {
				t.Fatalf("verification passed after mutating the %s", name)
			}
		})
	}
}

// A record added to the set after the fact fails verification too: the manifest
// covers what was imported, not merely what each record says.
func TestAddingARecordFailsVerification(t *testing.T) {
	svc, imp, recordStore := importWithRecords(t, importedFixture())
	stored, err := recordStore.ListImport(t.Context(), imp.ID)
	if err != nil {
		t.Fatalf("ListImport: %v", err)
	}
	extra := importedFixture()[0]
	extra.MergeRequestID = "imported-8"
	if err := recordStore.PutImport(t.Context(), imp.ID, append(stored, extra)); err != nil {
		t.Fatalf("PutImport: %v", err)
	}

	ok, err := svc.VerifyImport(t.Context(), importRequest().Context, imp.ID)
	if err != nil {
		t.Fatalf("VerifyImport: %v", err)
	}
	if ok {
		t.Fatal("verification passed after a record was added to the set")
	}
}

// The digest does not depend on the order a store happens to return records in:
// a reordered set is not a tampered one.
func TestDigestIsOrderIndependent(t *testing.T) {
	first := importedFixture()
	second := importedFixture()[0]
	second.MergeRequestID = "imported-8"
	set := append(first, second)

	reversed := []api.ImportedMergeRequest{set[1], set[0]}
	if recordsDigest(set) != recordsDigest(reversed) {
		t.Fatal("the same set hashed differently when returned in another order")
	}
}

// Length prefixing keeps a field boundary from being shifted: a body that ends
// where the next field begins must not hash the same as the pair swapped.
func TestFieldBoundariesCannotBeShifted(t *testing.T) {
	left := importedFixture()
	left[0].Threads[0].Comments[0].DeclaredActor = "ab"
	left[0].Threads[0].Comments[0].Body = "cd"

	right := importedFixture()
	right[0].Threads[0].Comments[0].DeclaredActor = "a"
	right[0].Threads[0].Comments[0].Body = "bcd"

	if recordsDigest(left) == recordsDigest(right) {
		t.Fatal("two different sets hashed the same by shifting a field boundary")
	}
}

// A cross-tenant verification is refused, like every other read of an import.
func TestVerifyImportDeniesAnotherTenant(t *testing.T) {
	svc, imp, _ := importWithRecords(t, importedFixture())
	other := api.Context{TenantID: "tenant-b", RepositoryID: "repo-a", ActorID: "actor-b", RequestID: "req-2"}
	if _, err := svc.VerifyImport(t.Context(), other, imp.ID); err == nil {
		t.Fatal("another tenant verified this import")
	}
}
