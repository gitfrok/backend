// The evidence-pack idempotency race fix, witnessed (SPEC-0032 AC1): the
// idempotency key is RESERVED under the service mutex before any side
// effect, so concurrent duplicates wait on the first writer and replay its
// outcome — exactly one PDP decision, exactly one trail append, exactly one
// pack. A rolled-back reservation (denied decision or failed append)
// releases the key so a later retry starts fresh.
package app

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gitfrok/backend/modules/audit/api"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
)

// countingPDP answers as configured and counts decisions atomically so a
// concurrent hammer can prove how many it took. When block is non-nil,
// Decide waits on it after announcing its entrance on entered, so a test
// can pin the first writer in flight while duplicates queue behind it.
type countingPDP struct {
	allow       bool
	decisions   atomic.Int64
	block       chan struct{}
	entered     chan struct{}
	enteredOnce sync.Once
}

func (p *countingPDP) Decide(_ context.Context, _ policyapi.Request) (policyapi.Decision, error) {
	p.decisions.Add(1)
	if p.block != nil {
		if p.entered != nil {
			p.enteredOnce.Do(func() { close(p.entered) })
		}
		<-p.block
	}
	return policyapi.Decision{Allowed: p.allow, DecisionID: "decision-count"}, nil
}

// countingTrail counts appends under a mutex and fails them on demand.
type countingTrail struct {
	mu      sync.Mutex
	appends int
	fail    bool
}

func (t *countingTrail) Append(_ context.Context, e api.Entry) (api.Record, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.fail {
		return api.Record{}, errors.New("trail unavailable")
	}
	t.appends++
	return api.Record{Seq: int64(t.appends), TenantID: e.TenantID, Action: e.Action,
		ActorID: e.ActorID, Hash: "hash-count", OccurredAt: e.OccurredAt}, nil
}

func (t *countingTrail) Verify(context.Context) (api.VerifyResult, error) {
	return api.VerifyResult{OK: true}, nil
}

func (t *countingTrail) Query(context.Context, api.TrailQuery) ([]api.Record, error) {
	return nil, nil
}

func (t *countingTrail) appended() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.appends
}

func idempotencyCtx() api.Context {
	return api.Context{TenantID: "tenant-a", ActorID: "u-owner", ActorRoles: []string{"owner"}, RequestID: "req-dup"}
}

func idempotencyRange() api.PackRequest {
	from := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	return api.PackRequest{RangeFrom: from, RangeTo: from.Add(24 * time.Hour)}
}

// Concurrent duplicates of one request resolve to the SAME pack: one PDP
// decision, one audit append, one registered pack — whatever the scheduling
// (SPEC-0032 AC1).
func TestConcurrentDuplicatePackRequestsProduceOnePack(t *testing.T) {
	pdp := &countingPDP{allow: true}
	trail := &countingTrail{}
	svc := New(pdp, stubBus{}, trail, nil, nil, nil)

	const n = 24
	var start sync.WaitGroup
	start.Add(1)
	var done sync.WaitGroup
	ids := make([]string, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		done.Add(1)
		go func(i int) {
			defer done.Done()
			start.Wait()
			ids[i], _, errs[i] = svc.RequestPack(context.Background(), idempotencyCtx(), idempotencyRange())
		}(i)
	}
	start.Done()
	done.Wait()

	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("duplicate %d failed: %v", i, errs[i])
		}
		if ids[i] != ids[0] || ids[i] == "" {
			t.Fatalf("duplicate %d got pack %q, first got %q — duplicates must replay one pack", i, ids[i], ids[0])
		}
	}
	if got := pdp.decisions.Load(); got != 1 {
		t.Fatalf("PDP decisions = %d, want exactly one for %d duplicates", got, n)
	}
	if got := trail.appended(); got != 1 {
		t.Fatalf("trail appends = %d, want exactly one for %d duplicates", got, n)
	}
	svc.mu.Lock()
	packs := len(svc.packs)
	svc.mu.Unlock()
	if packs != 1 {
		t.Fatalf("registered packs = %d, want exactly one", packs)
	}
}

// A denied decision rolls the reservation back: no append, no pack, and the
// key is released so a retry after the PDP turns permissive becomes the
// first writer of a fresh attempt. Duplicates queued on the in-flight
// attempt all replay the same coarse failure after a single decision.
func TestDeniedDecisionRollsBackTheReservation(t *testing.T) {
	pdp := &countingPDP{allow: false, block: make(chan struct{}), entered: make(chan struct{})}
	trail := &countingTrail{}
	svc := New(pdp, stubBus{}, trail, nil, nil, nil)

	// The first writer goes in flight and blocks inside the PDP; the
	// duplicates are launched while its reservation holds the key, so they
	// must queue on it rather than take decisions of their own.
	firstErr := make(chan error, 1)
	go func() {
		_, _, err := svc.RequestPack(context.Background(), idempotencyCtx(), idempotencyRange())
		firstErr <- err
	}()
	<-pdp.entered

	const n = 8
	var done sync.WaitGroup
	for i := 0; i < n; i++ {
		done.Add(1)
		go func() {
			defer done.Done()
			if _, _, err := svc.RequestPack(context.Background(), idempotencyCtx(), idempotencyRange()); !errors.Is(err, api.ErrPackUnavailable) {
				t.Errorf("a duplicate of a denied attempt must replay the coarse failure, got %v", err)
			}
		}()
	}
	time.Sleep(20 * time.Millisecond) // let every duplicate queue on the in-flight reservation
	close(pdp.block)

	if err := <-firstErr; !errors.Is(err, api.ErrPackUnavailable) {
		t.Fatalf("a denied attempt must be the coarse failure, got %v", err)
	}
	done.Wait()
	if got := pdp.decisions.Load(); got != 1 {
		t.Fatalf("denied duplicates took %d decisions, want one", got)
	}
	if got := trail.appended(); got != 0 {
		t.Fatalf("a denied attempt must append nothing, got %d", got)
	}

	// The key was released: the same request under an allowing PDP succeeds.
	pdp.allow = true
	packID, _, err := svc.RequestPack(context.Background(), idempotencyCtx(), idempotencyRange())
	if err != nil || packID == "" {
		t.Fatalf("a retry after rollback must start fresh and succeed, got %q err=%v", packID, err)
	}
	if got := pdp.decisions.Load(); got != 2 {
		t.Fatalf("decisions after retry = %d, want two (denied attempt + fresh retry)", got)
	}
	if got := trail.appended(); got != 1 {
		t.Fatalf("appends after retry = %d, want one", got)
	}
}

// A failed trail append rolls the reservation back the same way: the pack is
// never registered unaudited, and the key is released for a clean retry
// (SPEC-0032: an unaudited export is a worse failure than a refused one).
func TestAppendFailureRollsBackTheReservation(t *testing.T) {
	pdp := &countingPDP{allow: true}
	trail := &countingTrail{fail: true}
	svc := New(pdp, stubBus{}, trail, nil, nil, nil)

	if _, _, err := svc.RequestPack(context.Background(), idempotencyCtx(), idempotencyRange()); err == nil {
		t.Fatal("a failed append must refuse the pack")
	}
	svc.mu.Lock()
	packs := len(svc.packs)
	svc.mu.Unlock()
	if packs != 0 {
		t.Fatalf("a failed append must register no pack, got %d", packs)
	}

	trail.mu.Lock()
	trail.fail = false
	trail.mu.Unlock()
	packID, _, err := svc.RequestPack(context.Background(), idempotencyCtx(), idempotencyRange())
	if err != nil || packID == "" {
		t.Fatalf("a retry after a rolled-back append must succeed, got %q err=%v", packID, err)
	}
	if got := trail.appended(); got != 1 {
		t.Fatalf("appends = %d, want exactly one from the successful retry", got)
	}
}
