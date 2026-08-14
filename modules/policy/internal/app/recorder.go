// The asynchronous decision recorder (M12 / SPEC-0029 AC1).
//
// Recording a decision is moved OFF Decide's synchronous path: a bounded queue and one worker
// append to the store while the caller already holds the decision. The availability semantics
// this buys are the MVP-RUNBOOK operational contract for the policy plane, and they differ by
// mode:
//
//   - ENFORCED decisions are fail-closed at admission: when the queue is full, Decide refuses
//     exactly as it did when a synchronous append failed — SPEC-0029 AC1 requires every enforced
//     decision to be recorded, and the honest answer to "cannot guarantee that" is an error, not
//     an unrecorded allow. A store failure INSIDE the worker, by contrast, can no longer fail the
//     decision (it already returned): it is counted and logged. That gap is bounded by the queue
//     depth plus the worker, and it is what the runbook's "decision record lag" alert watches.
//   - DRY_RUN records are droppable under backpressure: a would-be decision is not evidence the
//     same way an enforced one is, so under pressure it is dropped, counted, and logged rather
//     than making the dry-run fail or the enforced path wait.
package app

import (
	"context"
	"errors"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gitfrok/backend/modules/policy/api"
	"github.com/gitfrok/backend/platform/tenancy"
)

// recorderBufferSize bounds how many decision records may wait for the store. Under normal
// operation the worker drains faster than decisions arrive; the buffer absorbs bursts, and a
// sustained overflow is the signal the store is down — surfaced fail-closed for ENFORCED
// decisions, as a drop counter for DRY_RUN ones.
const recorderBufferSize = 256

// ErrRecorderFull is the fail-closed admission refusal: the recorder cannot take one more
// record right now. For an ENFORCED decision this is Decide's "was not recorded" error — the
// caller that only checks errors denies, exactly as it did under synchronous appends.
var ErrRecorderFull = errors.New("policy: decision recorder is saturated")

var errRecorderStopped = errors.New("policy: decision recorder is stopped")

// recordJob is one queued append.
type recordJob struct {
	rec api.Record
	// enforced marks records the spec requires durable: saturated, they fail the decision
	// instead of being dropped.
	enforced bool
	// done, when non-nil, is closed once this job is applied — the flush barrier tests wait
	// on to observe queued records in the store.
	done chan struct{}
}

// asyncRecorder is the bounded queue plus its single worker.
type asyncRecorder struct {
	store  RecordStore
	jobs   chan recordJob
	buffer int

	// dropped counts DRY_RUN records shed under backpressure; failed counts records the store
	// refused inside the worker. Both are the recorder's telemetry surface (M12).
	dropped atomic.Int64
	failed  atomic.Int64

	mu      sync.RWMutex // guards close(jobs) against concurrent enqueues
	stopped bool
	done    chan struct{}
}

func newAsyncRecorder(store RecordStore, buffer int) *asyncRecorder {
	if buffer <= 0 {
		buffer = recorderBufferSize
	}
	r := &asyncRecorder{store: store, jobs: make(chan recordJob, buffer), buffer: buffer, done: make(chan struct{})}
	go r.run()
	return r
}

// enqueue admits one record. A full queue refuses an enforced record (ErrRecorderFull) and
// drops a droppable one — counted and logged, never silently.
func (r *asyncRecorder) enqueue(job recordJob) error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.stopped {
		return errRecorderStopped
	}
	select {
	case r.jobs <- job:
		return nil
	default:
	}
	if job.enforced {
		return ErrRecorderFull
	}
	n := r.dropped.Add(1)
	log.Printf("policy: dropped %s decision record %s under recorder backpressure (dropped=%d)",
		job.rec.Mode, job.rec.DecisionID, n)
	return nil
}

// flush blocks until every record enqueued before it has been applied to the store. Tests use
// it to observe the asynchronous appends; production paths never wait on it.
func (r *asyncRecorder) flush() {
	barrier := recordJob{done: make(chan struct{})}
	r.mu.RLock()
	if r.stopped {
		r.mu.RUnlock()
		return
	}
	// A blocking send is deliberate: the barrier must land behind everything already queued,
	// and a flush that could skip the queue would be a flush that proves nothing.
	r.jobs <- barrier
	r.mu.RUnlock()
	<-barrier.done
}

// Stop drains the queue and stops the worker. After it returns, every admitted record has
// reached the store (or been counted as failed): a clean shutdown loses no enforced decision.
func (r *asyncRecorder) Stop() {
	r.mu.Lock()
	if r.stopped {
		r.mu.Unlock()
		return
	}
	r.stopped = true
	close(r.jobs)
	r.mu.Unlock()
	<-r.done
}

func (r *asyncRecorder) run() {
	defer close(r.done)
	for job := range r.jobs {
		r.apply(job)
	}
}

func (r *asyncRecorder) apply(job recordJob) {
	if job.done != nil {
		defer close(job.done)
	}
	if job.rec.DecisionID == "" {
		return // a flush barrier carries no record
	}
	// The request context has done its job by the time the worker runs; the append pins its
	// own tenant scope — the record's own TenantID, a server-produced value.
	ctx, cancel := context.WithTimeout(tenancy.WithTenant(context.Background(), tenancy.ID(job.rec.TenantID)), 30*time.Second)
	defer cancel()
	if err := r.store.Append(ctx, job.rec); err != nil {
		n := r.failed.Add(1)
		log.Printf("policy: decision record %s failed to append asynchronously (failed=%d): %v",
			job.rec.DecisionID, n, err)
	}
}
