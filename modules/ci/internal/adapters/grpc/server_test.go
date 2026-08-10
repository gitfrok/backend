package grpc

import (
	"context"
	"testing"
	"time"

	civ1 "github.com/gitfrok/backend/gen/proto/ci/v1"
	"github.com/gitfrok/backend/modules/ci/api"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type fakeJobs struct {
	api.Jobs
	queued []api.EnqueueRequest
}

func (f *fakeJobs) Enqueue(_ context.Context, req api.EnqueueRequest) (api.Job, error) {
	f.queued = append(f.queued, req)
	return api.Job{ID: "job-1", AttemptID: "att-1", TenantID: req.TenantID, RepositoryID: req.RepositoryID, Ref: req.Ref, CommitSHA: req.CommitSHA, State: api.JobQueued, QueuedAt: time.Now()}, nil
}
func (f *fakeJobs) Get(_ context.Context, ctx api.Context, _ string) (api.Job, error) {
	return api.Job{ID: "job-1", AttemptID: "att-1", TenantID: ctx.TenantID, State: api.JobQueued}, nil
}
func (f *fakeJobs) Cancel(_ context.Context, ctx api.Context, _ string) (api.Job, error) {
	if ctx.TenantID != "tenant-a" {
		return api.Job{}, api.ErrDenied
	}
	return api.Job{ID: "job-1", State: api.JobCancelled}, nil
}

func newTestServer(t *testing.T) (*Server, *fakeJobs) {
	t.Helper()
	fj := &fakeJobs{}
	return NewServer(fj), fj
}

func validContext() *civ1.JobContext {
	return &civ1.JobContext{TenantId: "tenant-a", RepositoryId: "repo-a", ActorId: "actor-a", RequestId: "req-1"}
}

func TestEnqueueJobAcceptsValidRequest(t *testing.T) {
	s, fj := newTestServer(t)
	resp, err := s.EnqueueJob(t.Context(), &civ1.EnqueueJobRequest{
		Context:     validContext(),
		Ref:         "refs/heads/main",
		CommitSha:   "sha-a",
		TriggerKind: civ1.JobTriggerKind_JOB_TRIGGER_KIND_MANUAL,
	})
	if err != nil {
		t.Fatalf("EnqueueJob: %v", err)
	}
	if resp.GetJob().GetJobId() != "job-1" {
		t.Fatalf("job id = %q", resp.GetJob().GetJobId())
	}
	if len(fj.queued) != 1 || fj.queued[0].CommitSHA != "sha-a" {
		t.Fatalf("queued = %+v", fj.queued)
	}
}

func TestEnqueueJobDeniesMissingContext(t *testing.T) {
	s, _ := newTestServer(t)
	_, err := s.EnqueueJob(t.Context(), &civ1.EnqueueJobRequest{Ref: "refs/heads/main"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("missing context error = %v, want denied", err)
	}
}

func TestCancelJobCrossTenantIsDenied(t *testing.T) {
	s, _ := newTestServer(t)
	_, err := s.CancelJob(t.Context(), &civ1.CancelJobRequest{
		Context: &civ1.JobContext{TenantId: "tenant-b", RepositoryId: "repo-a", ActorId: "actor-b", RequestId: "req-1"},
		JobId:   "job-1",
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("cross-tenant cancel = %v, want denied", err)
	}
}
