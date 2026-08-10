package app

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/gitfrok/backend/modules/codereview/api"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
	"github.com/gitfrok/backend/platform/audit"
	"github.com/gitfrok/backend/platform/bus"
)

// stubImportStore is an in-memory ImportStore.
type stubImportStore struct {
	mu      sync.Mutex
	imports map[string]api.Import
	idem    map[string]string
	revoked map[string]bool
}

func newStubImportStore() *stubImportStore {
	return &stubImportStore{imports: map[string]api.Import{}, idem: map[string]string{}, revoked: map[string]bool{}}
}

func (s *stubImportStore) CreateOrGetImport(_ context.Context, key string, candidate api.Import) (api.Import, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id, ok := s.idem[key]; ok {
		return s.imports[id], false, nil
	}
	s.imports[candidate.ID], s.idem[key] = candidate, candidate.ID
	return candidate, true, nil
}

func (s *stubImportStore) GetImport(_ context.Context, id string) (api.Import, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	imp, ok := s.imports[id]
	if !ok {
		return api.Import{}, errors.New("not found")
	}
	return imp, nil
}

func (s *stubImportStore) ListImports(_ context.Context, tenantID, repositoryID string) ([]api.Import, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []api.Import
	for _, imp := range s.imports {
		if imp.TenantID == tenantID && imp.RepositoryID == repositoryID {
			out = append(out, imp)
		}
	}
	return out, nil
}

func (s *stubImportStore) MarkImportPhase(_ context.Context, id string, gitPhase, historyPhase bool, state api.ImportState, digest, reason string, counts map[string]int64) (api.Import, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	imp := s.imports[id]
	imp.GitPhaseComplete = gitPhase
	imp.HistoryPhaseComplete = historyPhase
	imp.State = state
	imp.ManifestDigest = digest
	imp.FailureReason = reason
	imp.RecordCounts = counts
	imp.UpdatedAt = time.Now().UTC()
	s.imports[id] = imp
	return imp, nil
}

func (s *stubImportStore) TombstoneImport(_ context.Context, id string) (api.Import, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	imp := s.imports[id]
	imp.State = api.ImportRevoked
	imp.UpdatedAt = time.Now().UTC()
	s.imports[id] = imp
	s.revoked[id] = true
	return imp, nil
}

type stubGitImporter struct {
	moved []RefUpdate
	err   error
}

func (s *stubGitImporter) ImportRefs(_ context.Context, command ImportRefsCommand) ([]RefUpdate, error) {
	return s.moved, s.err
}

type stubHistoryImporter struct {
	counts      map[string]int64
	sourceBytes int64
	err         error
}

func (s *stubHistoryImporter) ImportHistory(_ context.Context, command ImportHistoryCommand) (HistoryResult, error) {
	return HistoryResult{Counts: s.counts, SourceBytes: s.sourceBytes}, s.err
}

// stubPDP allows everything.
type stubPDP struct{}

func (stubPDP) Decide(context.Context, policyapi.Request) (policyapi.Decision, error) {
	return policyapi.Decision{Allowed: true, DecisionID: "decision-1", PolicyRevision: "rev-1"}, nil
}

func newTestImportService(store ImportStore, git GitImporter, history HistoryImporter) (*ImportService, *bus.InProcess, *[]audit.HistoryImported, *[]audit.HistoryImportRevoked) {
	b := bus.NewInProcess()
	svc := NewImportService(store, NewMemoryRecordStore(), git, history, stubPDP{}, b)
	svc.newID = func() string { return "import-1" }
	svc.now = func() time.Time { return time.Unix(1780000000, 0).UTC() }

	imported := &[]audit.HistoryImported{}
	revoked := &[]audit.HistoryImportRevoked{}
	b.Subscribe(audit.EventAudit, func(_ context.Context, e bus.Event) error {
		switch ev := e.(type) {
		case audit.HistoryImported:
			*imported = append(*imported, ev)
		case audit.HistoryImportRevoked:
			*revoked = append(*revoked, ev)
		}
		return nil
	})
	return svc, b, imported, revoked
}

func importRequest() api.CreateImportRequest {
	return api.CreateImportRequest{
		Context:        api.Context{TenantID: "tenant-a", RepositoryID: "repo-a", ActorID: "actor-a", RequestID: "req-1"},
		SourceURL:      "https://github.com/acme/widgets.git",
		SourceSystem:   "github",
		SourceInstance: "github.com",
		SourceToken:    "secret-token",
	}
}

// A complete import: git phase + history phase run, the state is COMPLETE, the
// manifest digest is set, and exactly one first-party HistoryImported event is
// published with the record counts (ADR-0029 §3, AC10).
func TestImportCompletesAndEmitsOneAuditEvent(t *testing.T) {
	store := newStubImportStore()
	git := &stubGitImporter{moved: []RefUpdate{{Ref: "refs/heads/main", Revision: "abc123"}}}
	history := &stubHistoryImporter{counts: map[string]int64{"merge_requests": 3, "comments": 12}}
	svc, _, imported, _ := newTestImportService(store, git, history)

	imp, err := svc.Create(context.Background(), importRequest())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if imp.State != api.ImportComplete || !imp.GitPhaseComplete || !imp.HistoryPhaseComplete {
		t.Fatalf("state = %+v", imp)
	}
	if imp.ManifestDigest == "" {
		t.Fatal("manifest digest not set")
	}
	if imp.RecordCounts["merge_requests"] != 3 {
		t.Fatalf("record counts = %v", imp.RecordCounts)
	}
	if len(*imported) != 1 {
		t.Fatalf("HistoryImported events = %d, want exactly 1", len(*imported))
	}
	if (*imported)[0].ImportID != imp.ID || (*imported)[0].ManifestDigest != imp.ManifestDigest {
		t.Fatalf("event = %+v", (*imported)[0])
	}
	if (*imported)[0].RecordCounts["comments"] != 12 {
		t.Fatalf("event counts = %v", (*imported)[0].RecordCounts)
	}
}

// A retried Create for the same source returns the existing import without
// duplicating work or emitting a second HistoryImported event (AC6 idempotency).
func TestCreateIsIdempotent(t *testing.T) {
	store := newStubImportStore()
	git := &stubGitImporter{moved: []RefUpdate{{Ref: "refs/heads/main", Revision: "abc"}}}
	history := &stubHistoryImporter{counts: map[string]int64{"merge_requests": 1}}
	svc, _, imported, _ := newTestImportService(store, git, history)

	first, err := svc.Create(context.Background(), importRequest())
	if err != nil {
		t.Fatal(err)
	}
	second, err := svc.Create(context.Background(), importRequest())
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != second.ID {
		t.Fatalf("idempotent key produced two imports: %s vs %s", first.ID, second.ID)
	}
	if len(*imported) != 1 {
		t.Fatalf("HistoryImported events = %d, want exactly 1", len(*imported))
	}
}

// A failed git phase marks the import FAILED and publishes no HistoryImported
// event (AC7: nothing partially visible).
func TestFailedGitPhaseIsNotVisible(t *testing.T) {
	store := newStubImportStore()
	git := &stubGitImporter{err: errors.New("fetch failed")}
	svc, _, imported, _ := newTestImportService(store, git, nil)

	if _, err := svc.Create(context.Background(), importRequest()); err == nil {
		t.Fatal("a failed import must return an error")
	}
	stored, _ := store.GetImport(context.Background(), "import-1")
	if stored.State != api.ImportFailed {
		t.Fatalf("state = %s, want FAILED", stored.State)
	}
	if len(*imported) != 0 {
		t.Fatalf("a failed import emitted %d HistoryImported events", len(*imported))
	}
}

// A history phase stalled by source-side rate limiting marks the import
// STALLED — resumable, not failed — and returns the stall error (AC8).
func TestHistoryRateLimitStallsNotFails(t *testing.T) {
	store := newStubImportStore()
	git := &stubGitImporter{moved: []RefUpdate{{Ref: "refs/heads/main", Revision: "abc"}}}
	history := &stubHistoryImporter{err: ErrImportStalled}
	svc, _, imported, _ := newTestImportService(store, git, history)

	if _, err := svc.Create(context.Background(), importRequest()); err != ErrImportStalled {
		t.Fatalf("Create = %v, want ErrImportStalled", err)
	}
	stored, _ := store.GetImport(context.Background(), "import-1")
	if stored.State != api.ImportStalled {
		t.Fatalf("state = %s, want STALLED", stored.State)
	}
	if len(*imported) != 0 {
		t.Fatalf("a stalled import emitted %d HistoryImported events", len(*imported))
	}
}

// An unauthorized caller is denied: the PDP decides, and denial is the coarse
// refusal with no state change.
func TestUnauthorizedImportIsDenied(t *testing.T) {
	store := newStubImportStore()
	svc, _, _, _ := newTestImportService(store, &stubGitImporter{}, nil)
	svc.pdp = denyPDP{}

	if _, err := svc.Create(context.Background(), importRequest()); err == nil {
		t.Fatal("an unauthorized import must be denied")
	}
	if len(store.imports) != 0 {
		t.Fatal("a denied import recorded state")
	}
}

// Revoking an import tombstones the records and emits exactly one
// HistoryImportRevoked event; the original HistoryImported chain entry is not
// touched by this service (invariant 5).
func TestRevokeTombstonesAndEmitsEvent(t *testing.T) {
	store := newStubImportStore()
	git := &stubGitImporter{moved: []RefUpdate{{Ref: "refs/heads/main", Revision: "abc"}}}
	history := &stubHistoryImporter{counts: map[string]int64{"merge_requests": 1}}
	svc, _, _, revoked := newTestImportService(store, git, history)

	imp, err := svc.Create(context.Background(), importRequest())
	if err != nil {
		t.Fatal(err)
	}
	rev, err := svc.Revoke(context.Background(), api.RevokeImportRequest{
		Context:  api.Context{TenantID: "tenant-a", RepositoryID: "repo-a", ActorID: "actor-a", RequestID: "req-2"},
		ImportID: imp.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if rev.State != api.ImportRevoked {
		t.Fatalf("state = %s, want REVOKED", rev.State)
	}
	if !store.revoked[imp.ID] {
		t.Fatal("records were not tombstoned")
	}
	if len(*revoked) != 1 || (*revoked)[0].ImportID != imp.ID {
		t.Fatalf("HistoryImportRevoked events = %+v", revoked)
	}
}

type denyPDP struct{}

func (denyPDP) Decide(context.Context, policyapi.Request) (policyapi.Decision, error) {
	return policyapi.Decision{Allowed: false, DecisionID: "denied", PolicyRevision: "rev-1"}, nil
}
