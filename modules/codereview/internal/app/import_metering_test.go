package app

import (
	"context"
	"errors"
	"testing"
)

// stubMeter records what an import attributed to a tenant.
type stubMeter struct {
	tenantID, repositoryID, importID string
	bytes                            int64
	calls                            int
	err                              error
}

func (s *stubMeter) RecordImportedBytes(_ context.Context, tenantID, repositoryID, importID string, bytes int64) error {
	s.calls++
	s.tenantID, s.repositoryID, s.importID, s.bytes = tenantID, repositoryID, importID, bytes
	return s.err
}

// The bytes charged are the ones the storage tier measured, attributed to the
// tenant, the repository and the import that wrote them (SPEC-0011 AC9/AC21).
func TestImportedBytesAreMeteredFromWhatStorageWrote(t *testing.T) {
	store := newStubImportStore()
	git := &stubGitImporter{
		moved: []RefUpdate{{Ref: "refs/heads/main", Revision: "abc123"}},
		bytes: 4 * 1024 * 1024,
	}
	history := &stubHistoryImporter{
		counts: map[string]int64{"merge_requests": 1},
		// Wire bytes read from the source API. They are a different quantity and
		// must never become the charge.
		sourceBytes: 999,
	}
	meter := &stubMeter{}
	svc, _, _, _ := newTestImportService(store, git, history)
	svc.WithStorageMeter(meter)

	if _, err := svc.Create(t.Context(), importRequest()); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if meter.calls != 1 {
		t.Fatalf("meter calls = %d, want exactly one per import", meter.calls)
	}
	if meter.bytes != 4*1024*1024 {
		t.Fatalf("metered bytes = %d, want what storage measured", meter.bytes)
	}
	if meter.tenantID != "tenant-a" || meter.repositoryID != "repo-a" || meter.importID != "import-1" {
		t.Fatalf("attribution = %s/%s/%s", meter.tenantID, meter.repositoryID, meter.importID)
	}
}

// A git phase that failed wrote nothing durable, so nothing is charged: a tenant
// must never be billed for storage it does not hold (AC7/AC9).
func TestFailedGitPhaseChargesNothing(t *testing.T) {
	store := newStubImportStore()
	git := &stubGitImporter{err: errors.New("fetch refused"), bytes: 8 * 1024}
	meter := &stubMeter{}
	svc, _, _, _ := newTestImportService(store, git, &stubHistoryImporter{})
	svc.WithStorageMeter(meter)

	if _, err := svc.Create(t.Context(), importRequest()); err == nil {
		t.Fatal("Create succeeded on a failed git phase")
	}
	if meter.calls != 0 {
		t.Fatalf("meter calls = %d, want none for an import that wrote nothing", meter.calls)
	}
}

// An import that grew the repository by nothing charges nothing rather than
// recording a zero-byte charge.
func TestNoGrowthChargesNothing(t *testing.T) {
	store := newStubImportStore()
	git := &stubGitImporter{moved: []RefUpdate{{Ref: "refs/heads/main", Revision: "abc123"}}, bytes: 0}
	meter := &stubMeter{}
	svc, _, _, _ := newTestImportService(store, git, &stubHistoryImporter{counts: map[string]int64{}})
	svc.WithStorageMeter(meter)

	if _, err := svc.Create(t.Context(), importRequest()); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if meter.calls != 0 {
		t.Fatalf("meter calls = %d, want none when nothing was written", meter.calls)
	}
}

// A meter that cannot record does not fail the import: the objects are already
// durable, and reporting the import as failed would leave the data in place and
// say otherwise.
func TestMeterFailureDoesNotFailTheImport(t *testing.T) {
	store := newStubImportStore()
	git := &stubGitImporter{moved: []RefUpdate{{Ref: "refs/heads/main", Revision: "abc123"}}, bytes: 1024}
	meter := &stubMeter{err: errors.New("meter unavailable")}
	svc, _, imported, _ := newTestImportService(store, git, &stubHistoryImporter{counts: map[string]int64{}})
	svc.WithStorageMeter(meter)

	imp, err := svc.Create(t.Context(), importRequest())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if !imp.GitPhaseComplete {
		t.Fatal("git phase was not marked complete")
	}
	if len(*imported) != 1 {
		t.Fatalf("HistoryImported events = %d, want exactly one", len(*imported))
	}
}

// A build with no meter still imports. The number is simply not recorded, which
// is the truth about a plane where fair-use metering is not wired (PRD PR-23).
func TestImportWithoutAMeterStillCompletes(t *testing.T) {
	store := newStubImportStore()
	git := &stubGitImporter{moved: []RefUpdate{{Ref: "refs/heads/main", Revision: "abc123"}}, bytes: 2048}
	svc, _, _, _ := newTestImportService(store, git, &stubHistoryImporter{counts: map[string]int64{}})

	imp, err := svc.Create(t.Context(), importRequest())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if !imp.GitPhaseComplete {
		t.Fatal("git phase was not marked complete")
	}
}
