// Package grpc adapts the Code Review in-process surface to its additive gRPC
// contract (SPEC-0019). It carries only verified identity context: no caller can
// assert a tenant, an actor, its roles, an approval count, a protection result,
// or an authorization outcome, because none of them is expressible on the wire.
package grpc

import (
	"context"
	"slices"

	codereviewv1 "github.com/gitfrok/backend/gen/proto/codereview/v1"
	"github.com/gitfrok/backend/modules/codereview/api"
	"github.com/gitfrok/backend/platform/tenancy"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Server is the gRPC adapter for the merge-request port.
type Server struct {
	codereviewv1.UnimplementedMergeRequestServiceServer
	requests api.MergeRequests
}

func NewServer(requests api.MergeRequests) *Server { return &Server{requests: requests} }

// denial is the one refusal this surface returns. It does not distinguish a
// missing merge request from one in another tenant, so the surface cannot be used
// to enumerate either (SPEC-0019 AC2).
func denial() error {
	return status.Error(codes.PermissionDenied, "merge request unavailable")
}

func (s *Server) CreateMergeRequest(ctx context.Context, req *codereviewv1.CreateMergeRequestRequest) (*codereviewv1.CreateMergeRequestResponse, error) {
	ctx, principal, err := intoContext(ctx, req.GetContext())
	if err != nil {
		return nil, denial()
	}
	mr, err := s.requests.Open(ctx, api.OpenRequest{
		Context:   principal,
		SourceRef: req.GetSourceRef(), TargetRef: req.GetTargetRef(),
		Title: req.GetTitle(), Description: req.GetDescription(),
		Draft: req.GetDraft(),
	})
	if err != nil {
		return nil, denial()
	}
	return &codereviewv1.CreateMergeRequestResponse{MergeRequest: toProto(mr)}, nil
}

func (s *Server) GetMergeRequest(ctx context.Context, req *codereviewv1.GetMergeRequestRequest) (*codereviewv1.GetMergeRequestResponse, error) {
	ctx, principal, err := intoContext(ctx, req.GetContext())
	if err != nil {
		return nil, denial()
	}
	mr, err := s.requests.Get(ctx, principal, req.GetMergeRequestId())
	if err != nil {
		return nil, denial()
	}
	return &codereviewv1.GetMergeRequestResponse{MergeRequest: toProto(mr)}, nil
}

func (s *Server) SubmitReview(ctx context.Context, req *codereviewv1.SubmitReviewRequest) (*codereviewv1.SubmitReviewResponse, error) {
	ctx, principal, err := intoContext(ctx, req.GetContext())
	if err != nil {
		return nil, denial()
	}
	mr, err := s.requests.Review(ctx, api.ReviewRequest{
		Context:         principal,
		MergeRequestID:  req.GetMergeRequestId(),
		Disposition:     disposition(req.GetDisposition()),
		Comment:         req.GetComment(),
		HeadRevision:    req.GetHeadRevision(),
		ExpectedVersion: req.GetExpectedVersion(),
	})
	if err != nil {
		return nil, denial()
	}
	return &codereviewv1.SubmitReviewResponse{MergeRequest: toProto(mr)}, nil
}

func (s *Server) MergeMergeRequest(ctx context.Context, req *codereviewv1.MergeMergeRequestRequest) (*codereviewv1.MergeMergeRequestResponse, error) {
	ctx, principal, err := intoContext(ctx, req.GetContext())
	if err != nil {
		return nil, denial()
	}
	mr, err := s.requests.Merge(ctx, api.MergeRequestCommand{
		Context:         principal,
		MergeRequestID:  req.GetMergeRequestId(),
		ExpectedVersion: req.GetExpectedVersion(),
	})
	if err != nil {
		return nil, denial()
	}
	return &codereviewv1.MergeMergeRequestResponse{MergeRequest: toProto(mr)}, nil
}

// MarkMergeRequestReady is the draft's one door out (ADR-0087, SPEC-0064). The
// refusal shape matches the rest of this surface: a coarse denial that does not
// distinguish a missing merge request from one in another tenant or the wrong
// state.
func (s *Server) MarkMergeRequestReady(ctx context.Context, req *codereviewv1.MarkMergeRequestReadyRequest) (*codereviewv1.MarkMergeRequestReadyResponse, error) {
	ctx, principal, err := intoContext(ctx, req.GetContext())
	if err != nil {
		return nil, denial()
	}
	mr, err := s.requests.MarkReady(ctx, api.ReadyRequest{
		Context:         principal,
		MergeRequestID:  req.GetMergeRequestId(),
		ExpectedVersion: req.GetExpectedVersion(),
	})
	if err != nil {
		return nil, denial()
	}
	return &codereviewv1.MarkMergeRequestReadyResponse{MergeRequest: toProto(mr)}, nil
}

func (s *Server) SetBranchProtection(ctx context.Context, req *codereviewv1.SetBranchProtectionRequest) (*codereviewv1.SetBranchProtectionResponse, error) {
	ctx, principal, err := intoContext(ctx, req.GetContext())
	if err != nil {
		return nil, denial()
	}
	protection, err := s.requests.SetProtection(ctx, api.ProtectionRequest{
		Context:           principal,
		TargetRef:         req.GetTargetRef(),
		RequiredApprovals: req.GetRequiredApprovals(),
		ExpectedVersion:   req.GetExpectedVersion(),
	})
	if err != nil {
		return nil, denial()
	}
	return &codereviewv1.SetBranchProtectionResponse{BranchProtection: &codereviewv1.BranchProtection{
		TenantId: protection.TenantID, RepositoryId: protection.RepositoryID,
		TargetRef: protection.TargetRef, RequiredApprovals: protection.RequiredApprovals,
		Version: protection.Version,
	}}, nil
}

// intoContext scopes the call to its tenant and carries the verified principal
// through. An incomplete context is a coarse denial rather than a partial call.
func intoContext(ctx context.Context, c *codereviewv1.ReviewCommandContext) (context.Context, api.Context, error) {
	if c == nil || c.GetTenantId() == "" || c.GetRepositoryId() == "" || c.GetActorId() == "" || c.GetRequestId() == "" {
		return ctx, api.Context{}, errMalformed
	}
	scoped := tenancy.WithTenant(ctx, tenancy.ID(c.GetTenantId()))
	return scoped, api.Context{
		TenantID: c.GetTenantId(), RepositoryID: c.GetRepositoryId(),
		ActorID: c.GetActorId(), RequestID: c.GetRequestId(),
		ActorRoles: slices.Clone(c.GetActorRoles()),
	}, nil
}

func disposition(d codereviewv1.ReviewDisposition) api.Disposition {
	switch d {
	case codereviewv1.ReviewDisposition_REVIEW_DISPOSITION_APPROVE:
		return api.DispositionApprove
	case codereviewv1.ReviewDisposition_REVIEW_DISPOSITION_REQUEST_CHANGES:
		return api.DispositionRequestChanges
	case codereviewv1.ReviewDisposition_REVIEW_DISPOSITION_COMMENT:
		return api.DispositionComment
	default:
		return ""
	}
}

func stateProto(state api.State) codereviewv1.MergeRequestState {
	switch state {
	case api.StateOpen:
		return codereviewv1.MergeRequestState_MERGE_REQUEST_STATE_OPEN
	case api.StateClosed:
		return codereviewv1.MergeRequestState_MERGE_REQUEST_STATE_CLOSED
	case api.StateMerged:
		return codereviewv1.MergeRequestState_MERGE_REQUEST_STATE_MERGED
	case api.StateDraft:
		return codereviewv1.MergeRequestState_MERGE_REQUEST_STATE_DRAFT
	default:
		return codereviewv1.MergeRequestState_MERGE_REQUEST_STATE_UNSPECIFIED
	}
}

// toProto carries only what the contract defines. The target revision this
// context tracks is deliberately absent: it is internal merge-safety state, not
// something a browser or a BFF has any use for.
func toProto(mr api.MergeRequest) *codereviewv1.MergeRequest {
	return &codereviewv1.MergeRequest{
		MergeRequestId: mr.ID, TenantId: mr.TenantID, RepositoryId: mr.RepositoryID,
		SourceRef: mr.SourceRef, TargetRef: mr.TargetRef,
		Title: mr.Title, Description: mr.Description,
		CreatorId: mr.CreatorID, State: stateProto(mr.State),
		HeadRevision: mr.HeadRevision,
		CreatedAt:    timestamppb.New(mr.CreatedAt), UpdatedAt: timestamppb.New(mr.UpdatedAt),
		Version:        mr.Version,
		ExternalIssues: externalIssuesProto(mr.ExternalIssues),
	}
}

type malformed struct{}

func (malformed) Error() string { return "codereview: malformed request" }

var errMalformed = malformed{}
