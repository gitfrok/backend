// The phase-2 fix wave's policy tests: H1 (decision-record reads must not mirror a
// caller-supplied tenant) and M12 (the decision-record append leaves Decide's synchronous
// path).
package app

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gitfrok/backend/modules/policy/api"
	"github.com/gitfrok/backend/platform/tenancy"
)

// --- H1: reads refuse a tenant the caller is not bound to -----------------------------------

// Cross-tenant Get and Range are denied: a ctx bound to tenant A cannot read tenant B's
// decision records, at the service AND at the store. Absent tenancy is refused outright.
func TestDecisionRecordReadsRefuseACrossTenantRequest(t *testing.T) {
	svc := newService(&stubPDP{decision: allowed()}, &recorder{})
	if _, err := svc.Decide(t.Context(), request()); err != nil {
		t.Fatalf("Decide: %v", err)
	}
	flush(svc)

	// The caller is tenant A; the request asks about tenant B. The guard refuses before any
	// store read — and with the same coarse shape as absence, so it cannot be probed.
	ctxA := tenancy.WithTenant(t.Context(), "acme")
	if _, err := svc.GetDecision(ctxA, "other-tenant", allowed().DecisionID); !errors.Is(err, api.ErrNotFound) {
		t.Errorf("cross-tenant GetDecision = %v, want the coarse ErrNotFound", err)
	}
	if _, err := svc.EvaluateDryRun(ctxA, api.DryRunRequest{
		TenantID: "other-tenant", CandidateBundleRef: "candidate/bundle",
	}); err == nil {
		t.Error("a cross-tenant dry-run replayed another tenant's history")
	}
	// The tenant's own reads still work under its own binding.
	if _, err := svc.GetDecision(ctxA, "acme", allowed().DecisionID); err != nil {
		t.Errorf("same-tenant GetDecision = %v, want the recorded decision", err)
	}
}

// A read with no tenancy bound at all is invariant 1's forbidden shape: refused, whatever the
// store's RLS would have filtered.
func TestDecisionRecordReadsRefuseAnAbsentTenantBinding(t *testing.T) {
	svc := newService(&stubPDP{decision: allowed()}, &recorder{})
	if _, err := svc.Decide(t.Context(), request()); err != nil {
		t.Fatalf("Decide: %v", err)
	}
	flush(svc)
	if _, err := svc.GetDecision(t.Context(), "acme", allowed().DecisionID); !errors.Is(err, tenancy.ErrNoTenant) {
		t.Errorf("unbound GetDecision = %v, want %v", err, tenancy.ErrNoTenant)
	}
	if _, err := svc.EvaluateDryRun(t.Context(), api.DryRunRequest{
		TenantID: "acme", CandidateBundleRef: "candidate/bundle",
	}); !errors.Is(err, tenancy.ErrNoTenant) {
		t.Errorf("unbound dry-run = %v, want %v", err, tenancy.ErrNoTenant)
	}
}

// The store enforces the same boundary on its own: defense in depth means a direct store
// read under a mismatched or absent binding is refused even if a future caller forgets the
// service guard.
func TestStoreReadsEnforceTheTenantBindingThemselves(t *testing.T) {
	store := NewMemoryStore()
	rec := recordOf(allowed(), request(), time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC))
	if err := store.Append(tenancy.WithTenant(t.Context(), "acme"), rec); err != nil {
		t.Fatalf("Append: %v", err)
	}

	cross := tenancy.WithTenant(t.Context(), "other-tenant")
	if _, err := store.Get(cross, "acme", rec.DecisionID); !errors.Is(err, api.ErrNotFound) {
		t.Errorf("cross-tenant store Get = %v, want ErrNotFound", err)
	}
	if _, err := store.Range(cross, "acme", api.HistoricalRange{}, 10); !errors.Is(err, api.ErrNotFound) {
		t.Errorf("cross-tenant store Range = %v, want ErrNotFound", err)
	}
	if _, err := store.Get(t.Context(), "acme", rec.DecisionID); !errors.Is(err, api.ErrNotFound) {
		t.Errorf("unbound store Get = %v, want ErrNotFound", err)
	}
	if _, err := store.Range(t.Context(), "acme", api.HistoricalRange{}, 10); !errors.Is(err, api.ErrNotFound) {
		t.Errorf("unbound store Range = %v, want ErrNotFound", err)
	}
	// And the matching binding reads its record.
	if _, err := store.Get(tenancy.WithTenant(t.Context(), "acme"), "acme", rec.DecisionID); err != nil {
		t.Errorf("bound store Get = %v, want the record", err)
	}
}

// --- M12: the append leaves Decide's synchronous path ----------------------------------------

// blockingStore holds every Append until released: whatever waits on it waits on the store.
type blockingStore struct {
	*MemoryStore
	block   chan struct{}
	appends atomic.Int64
}

func (s *blockingStore) Append(ctx context.Context, r api.Record) error {
	select {
	case <-s.block:
	case <-ctx.Done():
		return ctx.Err()
	}
	s.appends.Add(1)
	return s.MemoryStore.Append(ctx, r)
}

// takenByWorker waits until the queue is empty — the worker holding its current job — so a
// saturation test knows exactly how many slots remain free.
func takenByWorker(t *testing.T, r *asyncRecorder) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for len(r.jobs) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("the recorder worker never picked up its job")
		}
		time.Sleep(time.Millisecond)
	}
}

// The latency pattern M12 requires: Decide returns while the store is still blocked, and the
// record lands once the store unblocks. The synchronous path no longer waits on the insert.
func TestDecideDoesNotBlockOnTheRecordAppend(t *testing.T) {
	store := &blockingStore{MemoryStore: NewMemoryStore(), block: make(chan struct{})}
	svc := newServiceWithStore(&stubPDP{decision: allowed()}, &recorder{}, store)

	start := time.Now()
	if _, err := svc.Decide(t.Context(), request()); err != nil {
		t.Fatalf("Decide: %v", err)
	}
	elapsed := time.Since(start)
	if elapsed > 500*time.Millisecond {
		t.Fatalf("Decide took %v while the store was blocked — the append is still synchronous", elapsed)
	}
	if store.appends.Load() != 0 {
		t.Fatalf("the store applied %d appends while blocked", store.appends.Load())
	}

	close(store.block)
	flush(svc)
	if _, err := svc.GetDecision(acmeCtx(t), "acme", allowed().DecisionID); err != nil {
		t.Fatalf("the asynchronously appended record is missing: %v", err)
	}
}

// Saturation keeps Decide fail-closed: when the recorder cannot admit the record, the decision
// is surfaced as unrecorded — a caller that only checks errors denies, exactly as under a
// failed synchronous append.
func TestDecideFailsClosedWhenTheRecorderIsSaturated(t *testing.T) {
	store := &blockingStore{MemoryStore: NewMemoryStore(), block: make(chan struct{})}
	svc := newServiceWithStore(&stubPDP{decision: allowed()}, &recorder{}, store)
	old := svc.recorder
	svc.recorder = newAsyncRecorder(store, 2) // a tiny queue the blocked worker saturates
	old.Stop()
	defer svc.Close()

	pdp := svc.pdp.(*stubPDP)
	// Job 1 occupies the blocked worker; jobs 2 and 3 fill the queue.
	pdp.decision.DecisionID = allowed().DecisionID + "0"
	if _, err := svc.Decide(t.Context(), request()); err != nil {
		t.Fatalf("Decide 0: %v", err)
	}
	takenByWorker(t, svc.recorder)
	for i := 1; i < 3; i++ {
		pdp.decision.DecisionID = allowed().DecisionID + string(rune('0'+i))
		if _, err := svc.Decide(t.Context(), request()); err != nil {
			t.Fatalf("Decide %d: %v", i, err)
		}
	}
	pdp.decision.DecisionID = allowed().DecisionID + "x"
	decision, err := svc.Decide(t.Context(), request())
	if err == nil || !errors.Is(err, ErrRecorderFull) {
		t.Fatalf("a saturated recorder admitted an ENFORCED record: err = %v", err)
	}
	// The contract for an unrecordable decision: the error surfaces, so a caller that only
	// checks errors denies. Allowed is returned as decided — it is true only for a caller that
	// knowingly accepts the recording gap, exactly as under failed synchronous appends.
	_ = decision

	// Healing the store drains the queue; a later Decide succeeds again.
	close(store.block)
	flush(svc)
	if _, err := svc.Decide(t.Context(), request()); err != nil {
		t.Fatalf("Decide after drain: %v", err)
	}
}

// Backpressure semantics differ by mode: ENFORCED records refuse at admission; DRY_RUN records
// are dropped, counted, and logged — the M12 metric.
func TestRecorderBackpressureRefusesEnforcedAndDropsDryRun(t *testing.T) {
	store := &blockingStore{MemoryStore: NewMemoryStore(), block: make(chan struct{})}
	rec := newAsyncRecorder(store, 1)
	defer rec.Stop()

	enforced := func(id string) recordJob {
		return recordJob{rec: api.Record{DecisionID: id, TenantID: "acme", Mode: api.ModeEnforced}, enforced: true}
	}
	if err := rec.enqueue(enforced("d-1")); err != nil { // occupies the blocked worker
		t.Fatalf("first enforced enqueue: %v", err)
	}
	takenByWorker(t, rec)
	if err := rec.enqueue(enforced("d-2")); err != nil { // fills the one-slot queue
		t.Fatalf("second enforced enqueue: %v", err)
	}
	if err := rec.enqueue(enforced("d-3")); !errors.Is(err, ErrRecorderFull) {
		t.Fatalf("a saturated recorder admitted an ENFORCED record: %v", err)
	}

	dryRun := recordJob{rec: api.Record{DecisionID: "d-dry", TenantID: "acme", Mode: api.ModeDryRun}, enforced: false}
	if err := rec.enqueue(dryRun); err != nil {
		t.Fatalf("a droppable record errored under backpressure: %v", err)
	}
	if got := rec.dropped.Load(); got != 1 {
		t.Fatalf("dropped = %d, want the one shed DRY_RUN record counted", got)
	}

	close(store.block)
	rec.flush()
	if _, err := store.Get(tenancy.WithTenant(t.Context(), "acme"), "acme", "d-1"); err != nil {
		t.Errorf("d-1 missing after drain: %v", err)
	}
	if _, err := store.Get(tenancy.WithTenant(t.Context(), "acme"), "acme", "d-dry"); !errors.Is(err, api.ErrNotFound) {
		t.Errorf("the dropped DRY_RUN record landed anyway: %v", err)
	}
}
