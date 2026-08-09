package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/gitfrok/backend/modules/ci/api"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
	repoapi "github.com/gitfrok/backend/modules/repository/api"
	"github.com/gitfrok/backend/platform/bus"
)

func TestEnqueueRefUpdateIsIdempotentAndQueuesOneImmutableJob(t *testing.T) {
	store := newMemoryStore()
	queue := &recordingQueue{}
	events := bus.NewInProcess()
	var queued []api.CIJobQueued
	bus.SubscribeTyped(events, func(_ context.Context, event api.CIJobQueued) error { queued = append(queued, event); return nil })
	svc := New(store, queue, sourceOK{"sha-a", "config-a"}, allowPDP{}, events, WithIDs(sequence("job-a", "event-a", "event-b")), WithClock(fixedClock))
	req := api.EnqueueRequest{Context: api.Context{TenantID: "tenant-a", RepositoryID: "repo-a", ActorID: "actor-a", ActorRoles: []string{"member"}, RequestID: "request-a"}, Ref: "refs/heads/main", CommitSHA: "sha-a", SourceEventID: "event-1", Trigger: api.TriggerRefUpdated}

	first, err := svc.Enqueue(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	second, err := svc.Enqueue(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != "job-a" || second.ID != first.ID || first.ConfigurationDigest != "config-a" || first.State != api.JobQueued {
		t.Fatalf("jobs = %+v %+v", first, second)
	}
	if got := queue.enqueued; len(got) != 1 || got[0] != first.ID || len(queued) != 1 {
		t.Fatalf("queue=%v events=%v", got, queued)
	}
}

func TestEnqueueRejectsMismatchedRevisionBeforeQueueWrite(t *testing.T) {
	store := newMemoryStore()
	queue := &recordingQueue{}
	svc := New(store, queue, sourceErr{errors.New("mismatch")}, allowPDP{}, bus.NewInProcess())
	_, err := svc.Enqueue(context.Background(), api.EnqueueRequest{Context: api.Context{TenantID: "tenant-a", RepositoryID: "repo-a", ActorID: "actor-a", RequestID: "request-a"}, Ref: "refs/heads/main", CommitSHA: "wrong", SourceEventID: "event-1", Trigger: api.TriggerRefUpdated})
	if !errors.Is(err, ErrDenied) || len(queue.enqueued) != 0 || store.count() != 0 {
		t.Fatalf("err=%v queue=%v store=%d", err, queue.enqueued, store.count())
	}
}

func TestCancelQueuedJobIsTenantScopedAndNeverLaunches(t *testing.T) {
	store := newMemoryStore()
	queue := &recordingQueue{}
	svc := New(store, queue, sourceOK{"sha-a", "config-a"}, allowPDP{}, bus.NewInProcess(), WithIDs(sequence("job-a", "event-a", "event-b")), WithClock(fixedClock))
	job, err := svc.Enqueue(context.Background(), api.EnqueueRequest{Context: api.Context{TenantID: "tenant-a", RepositoryID: "repo-a", ActorID: "actor-a", RequestID: "request-a"}, Ref: "refs/heads/main", CommitSHA: "sha-a", SourceEventID: "event-1", Trigger: api.TriggerRefUpdated})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Cancel(context.Background(), api.Context{TenantID: "tenant-b", RepositoryID: "repo-a", ActorID: "actor-b", RequestID: "request-b"}, job.ID); !errors.Is(err, ErrDenied) {
		t.Fatalf("cross tenant cancel = %v", err)
	}
	cancelled, err := svc.Cancel(context.Background(), api.Context{TenantID: "tenant-a", RepositoryID: "repo-a", ActorID: "actor-a", RequestID: "request-a"}, job.ID)
	if err != nil || cancelled.State != api.JobCancelled || len(queue.cancelled) != 1 || queue.cancelled[0] != job.ID {
		t.Fatalf("job=%+v err=%v cancelled=%v", cancelled, err, queue.cancelled)
	}
}

func TestRefUpdatedSubscriberQueuesVerifiedEventOnce(t *testing.T) {
	store := newMemoryStore()
	queue := &recordingQueue{}
	events := bus.NewInProcess()
	svc := New(store, queue, sourceOK{"sha-a", "config-a"}, allowPDP{}, events, WithIDs(sequence("job-a", "event-a", "discarded-id")), WithClock(fixedClock))
	svc.SubscribeRefUpdates(events)
	event := repoapi.RefUpdated{EventID: "ref-event-1", TenantID: "tenant-a", RepoID: "repo-a", Ref: "refs/heads/main", NewSha: "sha-a", ActorID: "actor-a", ActorRoles: []string{"member"}}
	if err := events.Publish(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	if err := events.Publish(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	if store.count() != 1 || len(queue.enqueued) != 1 {
		t.Fatalf("jobs=%d queue=%v", store.count(), queue.enqueued)
	}
}

type sourceOK struct{ sha, digest string }

func (s sourceOK) Validate(context.Context, string, string, string, string) (string, error) {
	return s.digest, nil
}

type sourceErr struct{ err error }

func (s sourceErr) Validate(context.Context, string, string, string, string) (string, error) {
	return "", s.err
}

type allowPDP struct{}

func (allowPDP) Decide(context.Context, policyapi.Request) (policyapi.Decision, error) {
	return policyapi.Decision{Allowed: true}, nil
}

type recordingQueue struct{ enqueued, cancelled []string }

func (q *recordingQueue) Enqueue(_ context.Context, id string) error {
	q.enqueued = append(q.enqueued, id)
	return nil
}
func (q *recordingQueue) Cancel(_ context.Context, id string) error {
	q.cancelled = append(q.cancelled, id)
	return nil
}
func fixedClock() time.Time { return time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC) }
func sequence(values ...string) func() string {
	index := 0
	return func() string { value := values[index]; index++; return value }
}
