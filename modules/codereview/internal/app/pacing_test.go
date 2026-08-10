package app

import (
	"context"
	"errors"
	"testing"
	"time"
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

// countingMeter records the imported bytes charged to each tenant.
type countingMeter struct {
	bytes map[string]int64
}

func newCountingMeter() *countingMeter { return &countingMeter{bytes: map[string]int64{}} }

func (m *countingMeter) RecordImportedBytes(_ context.Context, tenantID, repositoryID string, bytes int64) error {
	m.bytes[tenantID+"/"+repositoryID] += bytes
	return nil
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

// A pacer that refuses (a cancelled context, a closed budget) stops the import
// instead of letting it run unthrottled.
func TestImportRefusedByPacerDoesNotImport(t *testing.T) {
	pacer := &countingPacer{err: errors.New("paced out")}
	store := newStubImportStore()
	svc, _, imported, _ := newTestImportService(store, &stubGitImporter{}, &stubHistoryImporter{})
	svc.pacer = pacer

	if _, err := svc.Create(context.Background(), importRequest()); err == nil {
		t.Fatal("Create succeeded despite a refusing pacer")
	}
	if len(*imported) != 0 {
		t.Fatalf("HistoryImported events = %d, want 0", len(*imported))
	}
}

// The bytes an import read from the source are charged to the importing tenant's
// storage dimension (SPEC-0011 AC9, PRD §6 G8).
func TestImportChargesSourceBytesToTheTenant(t *testing.T) {
	meter := newCountingMeter()
	store := newStubImportStore()
	svc, _, _, _ := newTestImportService(store, &stubGitImporter{}, &stubHistoryImporter{
		counts: map[string]int64{"merge_requests": 1}, sourceBytes: 4096,
	})
	svc.meter = meter

	if _, err := svc.Create(context.Background(), importRequest()); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if got := meter.bytes["tenant-a/repo-a"]; got != 4096 {
		t.Fatalf("charged bytes = %d, want 4096", got)
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
