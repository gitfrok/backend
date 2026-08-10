package app

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/gitfrok/backend/modules/codereview/api"
)

// countingPacer records how often an import asked for permission to proceed.
type countingPacer struct {
	waits int
	err   error
}

func (p *countingPacer) Wait(context.Context) error {
	p.waits++
	return p.err
}

// An import asks the pacer before each phase, so import work is rate-limited
// ahead of the interactive traffic it shares the plane with (SPEC-0011 AC9).
func TestImportPacesEachPhase(t *testing.T) {
	pacer := &countingPacer{}
	store := newStubImportStore()
	svc, _, imported, _ := newTestImportService(store, &stubGitImporter{}, &stubHistoryImporter{counts: map[string]int64{"merge_requests": 2}})
	svc.pacer = pacer

	if _, err := svc.Create(context.Background(), importRequest()); err != nil {
		t.Fatalf("Create: %v", err)
	}
	// One for the git phase, one for the history phase.
	if pacer.waits != 2 {
		t.Fatalf("pacer waits = %d, want 2", pacer.waits)
	}
	if len(*imported) != 1 {
		t.Fatalf("HistoryImported events = %d, want 1", len(*imported))
	}
}

// A pacer that refuses stops the import instead of letting it run unthrottled,
// and records it as stalled — the resumable state. Being paced out is neither
// the caller's fault nor the source's, so it does not earn the terminal state a
// real failure does (AC4, AC8).
func TestImportRefusedByPacerStallsRatherThanFails(t *testing.T) {
	pacer := &countingPacer{err: errors.New("paced out")}
	store := newStubImportStore()
	svc, _, imported, _ := newTestImportService(store, &stubGitImporter{}, &stubHistoryImporter{})
	svc.pacer = pacer

	_, err := svc.Create(context.Background(), importRequest())
	if !errors.Is(err, ErrImportStalled) {
		t.Fatalf("err = %v, want ErrImportStalled", err)
	}
	if len(*imported) != 0 {
		t.Fatalf("HistoryImported events = %d, want 0", len(*imported))
	}
	imp, err := store.GetImport(context.Background(), "import-1")
	if err != nil {
		t.Fatalf("GetImport: %v", err)
	}
	if imp.State != api.ImportStalled {
		t.Fatalf("state = %q, want %q", imp.State, api.ImportStalled)
	}
}

// The interval pacer spaces import steps: a step taken before the interval has
// elapsed waits out the remainder, and one taken after it proceeds at once.
func TestIntervalPacerSpacesSteps(t *testing.T) {
	now := time.Unix(1780000000, 0).UTC()
	var slept []time.Duration
	pacer := NewIntervalPacer(100 * time.Millisecond)
	pacer.now = func() time.Time { return now }
	pacer.sleep = func(_ context.Context, d time.Duration) error {
		slept = append(slept, d)
		now = now.Add(d)
		return nil
	}

	// The first step has nothing to wait for.
	if err := pacer.Wait(context.Background()); err != nil {
		t.Fatalf("Wait: %v", err)
	}
	// The second, taken immediately, waits the whole interval.
	if err := pacer.Wait(context.Background()); err != nil {
		t.Fatalf("Wait: %v", err)
	}
	// The third, taken well after the interval, waits not at all.
	now = now.Add(time.Second)
	if err := pacer.Wait(context.Background()); err != nil {
		t.Fatalf("Wait: %v", err)
	}

	if len(slept) != 1 || slept[0] != 100*time.Millisecond {
		t.Fatalf("slept = %v, want one 100ms wait", slept)
	}
}

// A cancelled context ends the wait rather than pacing on.
func TestIntervalPacerHonoursCancellation(t *testing.T) {
	pacer := NewIntervalPacer(time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := pacer.Wait(ctx); err == nil {
		t.Fatal("Wait ignored a cancelled context")
	}
}

// An unpaced import service is still a paced one: the zero pacer permits every
// step, so a build that forgets to configure pacing does not silently block.
func TestNoPacerPermits(t *testing.T) {
	if err := (NoPacer{}).Wait(context.Background()); err != nil {
		t.Fatalf("NoPacer.Wait: %v", err)
	}
}

// Concurrent import steps queue behind each other rather than all sleeping the
// same remainder and then proceeding together. Run under -race, this is also
// where a locking regression in Wait would surface.
func TestIntervalPacerSerialisesConcurrentSteps(t *testing.T) {
	pacer := NewIntervalPacer(time.Millisecond)

	var mu sync.Mutex
	var slept []time.Duration
	pacer.sleep = func(_ context.Context, d time.Duration) error {
		mu.Lock()
		slept = append(slept, d)
		mu.Unlock()
		return nil
	}

	const steps = 8
	var wg sync.WaitGroup
	wg.Add(steps)
	for range steps {
		go func() {
			defer wg.Done()
			if err := pacer.Wait(context.Background()); err != nil {
				t.Errorf("Wait: %v", err)
			}
		}()
	}
	wg.Wait()

	// The first step through pays nothing; every other step waits for a slot, so
	// none of them run at once.
	mu.Lock()
	defer mu.Unlock()
	if len(slept) < steps-1 {
		t.Fatalf("%d of %d steps waited; concurrent steps are not queueing", len(slept), steps)
	}
}

// A stall is only honest if the import can be picked up again: a retry after a
// paced-out import resumes it, skips the phase that already finished, and
// completes (AC4).
func TestStalledImportResumesOnRetry(t *testing.T) {
	pacer := &countingPacer{err: errors.New("paced out")}
	store := newStubImportStore()
	git := &stubGitImporter{}
	svc, _, imported, _ := newTestImportService(store, git, &stubHistoryImporter{counts: map[string]int64{"merge_requests": 1}})
	svc.pacer = pacer

	if _, err := svc.Create(context.Background(), importRequest()); !errors.Is(err, ErrImportStalled) {
		t.Fatalf("first Create: err = %v, want ErrImportStalled", err)
	}

	// The pace clears and the caller retries the same import.
	pacer.err = nil
	imp, err := svc.Create(context.Background(), importRequest())
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if imp.State != api.ImportComplete {
		t.Fatalf("state = %q, want %q", imp.State, api.ImportComplete)
	}
	if len(*imported) != 1 {
		t.Fatalf("HistoryImported events = %d, want exactly one for the import", len(*imported))
	}
	if git.calls != 1 {
		t.Fatalf("git phase ran %d times; a resumed import must not redo finished work", git.calls)
	}
}

// A completed import is observed, not restarted.
func TestCompletedImportIsNotRerun(t *testing.T) {
	store := newStubImportStore()
	git := &stubGitImporter{}
	svc, _, imported, _ := newTestImportService(store, git, &stubHistoryImporter{counts: map[string]int64{"merge_requests": 1}})

	if _, err := svc.Create(context.Background(), importRequest()); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := svc.Create(context.Background(), importRequest()); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if git.calls != 1 || len(*imported) != 1 {
		t.Fatalf("git calls = %d, events = %d; a completed import was re-run", git.calls, len(*imported))
	}
}
