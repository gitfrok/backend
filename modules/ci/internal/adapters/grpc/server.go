// Package grpc adapts the CI/CD in-process surface to its additive gRPC contract
// (SPEC-0020). It carries only verified identity context; no caller can assert
// tenant, actor, roles, or an authorization result.
package grpc

import (
	"context"
	"time"

	civ1 "github.com/gitfrok/backend/gen/proto/ci/v1"
	"github.com/gitfrok/backend/modules/ci/api"
	"github.com/gitfrok/backend/platform/tenancy"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Server is the gRPC adapter for the CI/Jobs port.
type Server struct {
	civ1.UnimplementedCIJobServiceServer
	jobs api.Jobs
}

func NewServer(jobs api.Jobs) *Server { return &Server{jobs: jobs} }

// denyTenantMismatch returns a coarse denial that does not distinguish cross-tenant
// from non-existent state (SPEC-0020 AC6).
func denial() error {
	return status.Error(codes.PermissionDenied, "ci job unavailable")
}

func (s *Server) EnqueueJob(ctx context.Context, req *civ1.EnqueueJobRequest) (*civ1.EnqueueJobResponse, error) {
	in, err := intoEnqueueRequest(req)
	if err != nil {
		return nil, denial()
	}
	job, err := s.jobs.Enqueue(ctx, in)
	if err != nil {
		return nil, denial()
	}
	return &civ1.EnqueueJobResponse{Job: toCIJobProto(job)}, nil
}

func (s *Server) GetJob(ctx context.Context, req *civ1.GetJobRequest) (*civ1.GetJobResponse, error) {
	ctx, in, err := intoContext(ctx, req.GetContext())
	if err != nil {
		return nil, denial()
	}
	job, err := s.jobs.Get(ctx, in, req.GetJobId())
	if err != nil {
		return nil, denial()
	}
	return &civ1.GetJobResponse{Job: toCIJobProto(job)}, nil
}

func (s *Server) CancelJob(ctx context.Context, req *civ1.CancelJobRequest) (*civ1.CancelJobResponse, error) {
	ctx, in, err := intoContext(ctx, req.GetContext())
	if err != nil {
		return nil, denial()
	}
	job, err := s.jobs.Cancel(ctx, in, req.GetJobId())
	if err != nil {
		return nil, denial()
	}
	return &civ1.CancelJobResponse{Job: toCIJobProto(job)}, nil
}

func intoEnqueueRequest(req *civ1.EnqueueJobRequest) (api.EnqueueRequest, error) {
	if req == nil || req.GetContext() == nil {
		return api.EnqueueRequest{}, errMalformed
	}
	ctx := req.GetContext()
	in := api.EnqueueRequest{
		Context:       api.Context{TenantID: ctx.GetTenantId(), RepositoryID: ctx.GetRepositoryId(), ActorID: ctx.GetActorId(), ActorRoles: append([]string(nil), ctx.GetActorRoles()...), RequestID: ctx.GetRequestId()},
		Ref:           req.GetRef(),
		CommitSHA:     req.GetCommitSha(),
		Trigger:       triggerKind(req.GetTriggerKind()),
		SourceEventID: req.GetSourceEventId(),
	}
	if in.TenantID == "" || in.RepositoryID == "" || in.ActorID == "" || in.RequestID == "" {
		return api.EnqueueRequest{}, errMalformed
	}
	return in, nil
}

func intoContext(ctx context.Context, c *civ1.JobContext) (context.Context, api.Context, error) {
	if c == nil || c.GetTenantId() == "" || c.GetRepositoryId() == "" || c.GetActorId() == "" || c.GetRequestId() == "" {
		return ctx, api.Context{}, errMalformed
	}
	scoped := tenancy.WithTenant(ctx, tenancy.ID(c.GetTenantId()))
	in := api.Context{TenantID: c.GetTenantId(), RepositoryID: c.GetRepositoryId(), ActorID: c.GetActorId(), ActorRoles: append([]string(nil), c.GetActorRoles()...), RequestID: c.GetRequestId()}
	return scoped, in, nil
}

func triggerKind(k civ1.JobTriggerKind) api.TriggerKind {
	switch k {
	case civ1.JobTriggerKind_JOB_TRIGGER_KIND_REF_UPDATED:
		return api.TriggerRefUpdated
	case civ1.JobTriggerKind_JOB_TRIGGER_KIND_MANUAL:
		return api.TriggerManual
	default:
		return ""
	}
}

func toCIJobProto(j api.Job) *civ1.CIJob {
	return &civ1.CIJob{
		JobId: j.ID, AttemptId: j.AttemptID,
		TenantId: j.TenantID, RepositoryId: j.RepositoryID,
		Ref: j.Ref, CommitSha: j.CommitSHA,
		TriggerKind:         triggerKindProto(j.Trigger),
		State:               stateProto(j.State),
		QueuedAt:            ts(j.QueuedAt),
		StartedAt:           tsPtr(j.StartedAt),
		FinishedAt:          tsPtr(j.FinishedAt),
		ConfigurationDigest: j.ConfigurationDigest,
		OutcomeSummary:      j.OutcomeSummary,
	}
}

func triggerKindProto(t api.TriggerKind) civ1.JobTriggerKind {
	if t == api.TriggerRefUpdated {
		return civ1.JobTriggerKind_JOB_TRIGGER_KIND_REF_UPDATED
	}
	return civ1.JobTriggerKind_JOB_TRIGGER_KIND_MANUAL
}

func stateProto(s api.JobState) civ1.JobState {
	switch s {
	case api.JobQueued:
		return civ1.JobState_JOB_STATE_QUEUED
	case api.JobRunning:
		return civ1.JobState_JOB_STATE_RUNNING
	case api.JobSucceeded:
		return civ1.JobState_JOB_STATE_SUCCEEDED
	case api.JobFailed:
		return civ1.JobState_JOB_STATE_FAILED
	case api.JobCancelled:
		return civ1.JobState_JOB_STATE_CANCELLED
	default:
		return civ1.JobState_JOB_STATE_UNSPECIFIED
	}
}

func ts(t time.Time) *timestamppb.Timestamp { return timestamppb.New(t) }
func tsPtr(t *time.Time) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return timestamppb.New(*t)
}

var errMalformed = status.Error(codes.InvalidArgument, "malformed request")
