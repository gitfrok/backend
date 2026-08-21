package app

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/gitfrok/backend/modules/codereview/api"
	"github.com/gitfrok/backend/platform/audit"
	"github.com/gitfrok/backend/platform/bus"
)

// The write split ADR-0084 decides, asserted at the service edge: the guarded
// Save surfaces its conflict as the wire's own ErrVersionConflict (AC11), Merge
// saves before it moves the ref (AC12), and a move that fails after the save is
// compensated by a re-open with its own version bump and a named audit record.

// conflictStore is the memory store with a Save that fails the durable adapter's
// way — with the adapter's own conflict error — whenever the test arms it.
type conflictStore struct {
	Store
	failNextSave error
}

func (s *conflictStore) Save(ctx context.Context, mr api.MergeRequest) error {
	if s.failNextSave != nil {
		err := s.failNextSave
		s.failNextSave = nil
		return err
	}
	return s.Store.Save(ctx, mr)
}

// guardedHarness is newService over a chosen store, collecting the compensation
// audit record alongside the approval and merge ones.
func guardedHarness(t *testing.T, store Store) (*Service, *recordingRefs, *collector, *[]audit.MergeRequestMergeCompensated) {
	t.Helper()
	pdp := &recordingPDP{deny: map[string]bool{}}
	refs := &recordingRefs{}
	events := bus.NewInProcess()
	got := &collector{}
	compensated := &[]audit.MergeRequestMergeCompensated{}
	events.Subscribe(audit.EventAudit, func(_ context.Context, e bus.Event) error {
		switch record := e.(type) {
		case audit.MergeRequestApproved:
			got.approvals = append(got.approvals, record)
		case audit.MergeRequestMerged:
			got.merges = append(got.merges, record)
		case audit.MergeRequestMergeCompensated:
			*compensated = append(*compensated, record)
		}
		return nil
	})
	bus.SubscribeTyped(events, func(_ context.Context, e api.MergeRequestMerged) error {
		got.merged = append(got.merged, e)
		return nil
	})

	counter := 0
	service := New(store, refs, pdp, events,
		WithIDs(func() string { counter++; return "id-" + strconv.Itoa(counter) }),
		WithClock(func() time.Time { return time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC) }),
	)
	service.SubscribeRefUpdates(events)
	got.events = events
	announceTarget(t, events, "refs/heads/main", "sha-target")
	announceTarget(t, events, "refs/heads/feature", "sha-head")
	return service, refs, got, compensated
}

// approveOne records one valid approval at the current head, the fact the merge
// gate counts.
func approveOne(t *testing.T, s *Service, mr api.MergeRequest, requestID string) api.MergeRequest {
	t.Helper()
	reviewed, err := s.Review(t.Context(), api.ReviewRequest{
		Context:        principal("tenant-a", "actor-b", requestID, "member"),
		MergeRequestID: mr.ID, Disposition: api.DispositionApprove,
		HeadRevision: mr.HeadRevision, ExpectedVersion: mr.Version,
	})
	if err != nil {
		t.Fatalf("Review: %v", err)
	}
	return reviewed
}

// AC11: a write that loses the race for a version is told so in the wire's own
// words — the pre-check and the guarded write surface the same error.
func TestAConflictingSaveSurfacesTheVersionConflict(t *testing.T) {
	store := &conflictStore{Store: NewMemoryStore()}
	service, _, _, _ := guardedHarness(t, store)
	mr := openOne(t, service, "request-open")
	mr = approveOne(t, service, mr, "request-review")

	store.failNextSave = api.ErrVersionConflict
	if _, err := service.Merge(t.Context(), api.MergeRequestCommand{
		Context:        principal("tenant-a", "actor-a", "request-merge", "member"),
		MergeRequestID: mr.ID, ExpectedVersion: mr.Version,
	}); !errors.Is(err, api.ErrVersionConflict) {
		t.Fatalf("a conflicting merge save must surface as the version conflict, got %v", err)
	}
}

// AC12 first half: the guarded Save runs BEFORE the ref moves, so a conflict
// refuses the merge while nothing has moved.
func TestAMergeWhoseSaveConflictsNeverMovesTheRef(t *testing.T) {
	store := &conflictStore{Store: NewMemoryStore()}
	service, refs, got, _ := guardedHarness(t, store)
	mr := openOne(t, service, "request-open")
	mr = approveOne(t, service, mr, "request-review")

	store.failNextSave = api.ErrVersionConflict
	if _, err := service.Merge(t.Context(), api.MergeRequestCommand{
		Context:        principal("tenant-a", "actor-a", "request-merge", "member"),
		MergeRequestID: mr.ID, ExpectedVersion: mr.Version,
	}); err == nil {
		t.Fatal("a conflicting merge was accepted")
	}
	if len(refs.commands) != 0 {
		t.Errorf("the ref move ran even though the save conflicted: %+v", refs.commands)
	}
	if len(got.merged) != 0 {
		t.Errorf("a conflicted merge announced itself: %+v", got.merged)
	}
	after, err := service.Get(t.Context(), principal("tenant-a", "actor-a", "request-get"), mr.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if after.State != api.StateOpen || after.Version != mr.Version {
		t.Errorf("the conflicted merge changed the record: state=%s version=%d", after.State, after.Version)
	}
}

// AC12 second half: a ref move that fails AFTER the guarded save left the record
// MERGED is compensated — the record returns to OPEN under its own version bump,
// the merge announces nothing, and the compensation is a named audit record.
func TestAFailedRefMoveIsCompensatedByAReopenAndAnAuditRecord(t *testing.T) {
	service, refs, got, compensated := guardedHarness(t, NewMemoryStore())
	mr := openOne(t, service, "request-open")
	mr = approveOne(t, service, mr, "request-review")

	refs.err = errors.New("the ref moved since the merge was decided")
	if _, err := service.Merge(t.Context(), api.MergeRequestCommand{
		Context:        principal("tenant-a", "actor-a", "request-merge", "member"),
		MergeRequestID: mr.ID, ExpectedVersion: mr.Version,
	}); !errors.Is(err, api.ErrDenied) {
		t.Fatalf("a merge whose ref move failed must be refused, got %v", err)
	}

	after, err := service.Get(t.Context(), principal("tenant-a", "actor-a", "request-get"), mr.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	// Two bumps past the approved version: the merge's own, and the re-open's.
	if after.State != api.StateOpen {
		t.Fatalf("the failed merge left the record %s — a retry would find a merge pointing at a ref that never moved", after.State)
	}
	if after.Version != mr.Version+2 {
		t.Errorf("the re-open did not carry its own version bump: version %d after merge at %d", after.Version, mr.Version)
	}
	if len(got.merged) != 0 || len(got.merges) != 0 {
		t.Errorf("the failed merge announced itself: events=%+v records=%+v", got.merged, got.merges)
	}
	if len(*compensated) != 1 {
		t.Fatalf("want exactly one compensation record, got %+v", *compensated)
	}
	record := (*compensated)[0]
	if record.MergeRequestID != mr.ID || record.TargetRef != mr.TargetRef || record.Reason == "" {
		t.Errorf("the compensation record does not name what happened: %+v", record)
	}
	if record.RequestID != "request-merge" || record.PolicyDecisionID != "decision-allow" {
		t.Errorf("the compensation record lost its correlation: %+v", record)
	}

	// The retry the compensation exists for: a fresh request ID merges the same
	// record cleanly, because it is OPEN at the version the re-open left it.
	refs.err = nil
	merged, err := service.Merge(t.Context(), api.MergeRequestCommand{
		Context:        principal("tenant-a", "actor-a", "request-merge-retry", "member"),
		MergeRequestID: mr.ID, ExpectedVersion: after.Version,
	})
	if err != nil || merged.State != api.StateMerged {
		t.Fatalf("the retry after compensation did not merge: %+v, %v", merged, err)
	}
}
