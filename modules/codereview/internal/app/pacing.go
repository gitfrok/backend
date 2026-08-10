package app

import (
	"context"
	"sync"
	"time"
)

// Pacer throttles import work. An import is background work sharing a plane
// with interactive git and web traffic, and SPEC-0011 AC9 puts the priority
// plainly: the import slows down before the traffic does. Every import step
// asks first, and a refusal stops the import rather than letting it run
// unthrottled.
type Pacer interface {
	// Wait blocks until this step may proceed, or returns the reason it may not
	// (a cancelled context, a closed budget).
	Wait(ctx context.Context) error
}

// NoPacer permits every step. It is the pacer a build gets when pacing is not
// configured: an unpaced import is a load problem, whereas an import that
// silently blocks is an outage.
type NoPacer struct{}

// Wait permits the step.
func (NoPacer) Wait(context.Context) error { return nil }

// IntervalPacer spaces import steps by a minimum interval. It is deliberately
// the simplest shape that satisfies AC9: one knob, no burst credit to reason
// about, and a step that is late costs nothing.
type IntervalPacer struct {
	interval time.Duration

	mu   sync.Mutex
	last time.Time

	// now and sleep are injected so pacing is tested on a clock rather than by
	// waiting on a real one.
	now   func() time.Time
	sleep func(ctx context.Context, d time.Duration) error
}

// NewIntervalPacer returns a pacer that lets one import step through per
// interval. A non-positive interval paces nothing.
func NewIntervalPacer(interval time.Duration) *IntervalPacer {
	return &IntervalPacer{interval: interval, now: time.Now, sleep: sleepCtx}
}

// Wait blocks until the interval since the previous step has elapsed.
func (p *IntervalPacer) Wait(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if p.interval <= 0 {
		return nil
	}

	p.mu.Lock()
	wait := time.Duration(0)
	if !p.last.IsZero() {
		if elapsed := p.now().Sub(p.last); elapsed < p.interval {
			wait = p.interval - elapsed
		}
	}
	// The slot is claimed before releasing the lock, so concurrent imports queue
	// behind each other instead of all sleeping the same remainder and then
	// proceeding together.
	p.last = p.now().Add(wait)
	p.mu.Unlock()

	if wait <= 0 {
		return nil
	}
	return p.sleep(ctx, wait)
}

// sleepCtx sleeps unless the context ends first.
func sleepCtx(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
