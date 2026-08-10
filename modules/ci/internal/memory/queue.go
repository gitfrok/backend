// Package memory holds dev/in-memory adapters for the CI context.
package memory

import (
	"context"
	"sync"
)

// Queue is a best-effort in-process queue for dev and tests. It records the most
// recent enqueue/cancel calls so tests can assert dispatch ordering. Production uses
// the KEDA-backed queue, which surfaces queued-depth as the KEDA scaler metric (SPEC-0020 AC3).
type Queue struct {
	mu        sync.Mutex
	enqueued  []string
	cancelled []string
	order     []string
	pending   map[string]bool
}

func NewQueue() *Queue {
	return &Queue{pending: map[string]bool{}}
}

func (q *Queue) Enqueue(_ context.Context, jobID string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.enqueued = append(q.enqueued, jobID)
	if !q.pending[jobID] {
		q.order = append(q.order, jobID)
	}
	q.pending[jobID] = true
	return nil
}

// Claim removes and returns the oldest still-pending job ID. A cancelled job is
// no longer pending, so it is skipped and never dispatched.
func (q *Queue) Claim(_ context.Context) (string, bool, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for len(q.order) > 0 {
		id := q.order[0]
		q.order = q.order[1:]
		if q.pending[id] {
			delete(q.pending, id)
			return id, true, nil
		}
	}
	return "", false, nil
}

// Depth is the number of jobs awaiting dispatch — the value KEDA scales on.
func (q *Queue) Depth(_ context.Context) (int64, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return int64(len(q.pending)), nil
}

func (q *Queue) Cancel(_ context.Context, jobID string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.cancelled = append(q.cancelled, jobID)
	delete(q.pending, jobID)
	return nil
}

func (q *Queue) Pending() []string {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make([]string, 0, len(q.pending))
	for id := range q.pending {
		out = append(out, id)
	}
	return out
}

func (q *Queue) Enqueued() []string {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := append([]string(nil), q.enqueued...)
	return out
}

func (q *Queue) Cancelled() []string {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := append([]string(nil), q.cancelled...)
	return out
}
