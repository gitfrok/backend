package grpc

import (
	"context"
	"errors"
	"time"

	codereviewv1 "github.com/gitfrok/backend/gen/proto/codereview/v1"
	"github.com/gitfrok/backend/modules/codereview/api"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// The gRPC door for external issue references (SPEC-0059, PR-28's accepted scope,
// ADR-0074).
//
// It shapes and forwards. There is no route here that reads a tracker, and no field
// on either request that could carry what an issue says: this product references
// issues, it does not store them.

// invalidReference is the one refusal on this surface that is not coarse.
//
// It is about the fields the caller just sent — a missing tracker, a missing key, or
// a URL that is not absolute https — which the caller already knows, so naming it
// discloses nothing. A form that fails for no stated reason is a worse product than
// one that says which field was wrong, and everything else here stays the single
// "merge request unavailable".
func invalidReference() error {
	return status.Error(codes.InvalidArgument, api.ErrInvalidExternalIssue.Error())
}

// tooManyReferences reports a merge request already carrying as many references as it
// can. Also not coarse, and for the same reason: it is a fact about the merge request
// the caller is already looking at.
func tooManyReferences() error {
	return status.Error(codes.ResourceExhausted, api.ErrTooManyExternalIssues.Error())
}

// LinkExternalIssue references an issue that lives elsewhere.
func (s *Server) LinkExternalIssue(ctx context.Context, req *codereviewv1.LinkExternalIssueRequest) (*codereviewv1.LinkExternalIssueResponse, error) {
	ctx, principal, err := intoContext(ctx, req.GetContext())
	if err != nil {
		return nil, denial()
	}
	mr, err := s.requests.LinkExternalIssue(ctx, api.LinkExternalIssueRequest{
		Context:        principal,
		MergeRequestID: req.GetMergeRequestId(),
		Tracker:        req.GetTracker(),
		IssueKey:       req.GetIssueKey(),
		// There is no linked_by on the request: who linked it is the verified caller,
		// and a field naming one would be an unauthenticated authorship claim.
		URL: req.GetUrl(),
	})
	if err != nil {
		return nil, referenceError(err)
	}
	return &codereviewv1.LinkExternalIssueResponse{MergeRequest: toProto(mr)}, nil
}

// UnlinkExternalIssue removes a reference by tracker and key.
func (s *Server) UnlinkExternalIssue(ctx context.Context, req *codereviewv1.UnlinkExternalIssueRequest) (*codereviewv1.UnlinkExternalIssueResponse, error) {
	ctx, principal, err := intoContext(ctx, req.GetContext())
	if err != nil {
		return nil, denial()
	}
	mr, err := s.requests.UnlinkExternalIssue(ctx, api.UnlinkExternalIssueRequest{
		Context:        principal,
		MergeRequestID: req.GetMergeRequestId(),
		Tracker:        req.GetTracker(),
		IssueKey:       req.GetIssueKey(),
	})
	if err != nil {
		return nil, referenceError(err)
	}
	return &codereviewv1.UnlinkExternalIssueResponse{MergeRequest: toProto(mr)}, nil
}

// referenceError maps the two distinguished outcomes and collapses everything else.
func referenceError(err error) error {
	switch {
	case errors.Is(err, api.ErrInvalidExternalIssue):
		return invalidReference()
	case errors.Is(err, api.ErrTooManyExternalIssues):
		return tooManyReferences()
	default:
		return denial()
	}
}

// externalIssuesProto shapes the references onto the wire.
//
// linked_at is RFC 3339 rather than a Timestamp because that is what the contract's
// ExternalIssue declares — a string, matching how the release surface renders its
// instants, so a consumer reads one shape for "an instant this product recorded".
func externalIssuesProto(references []api.ExternalIssue) []*codereviewv1.ExternalIssue {
	if len(references) == 0 {
		return nil
	}
	out := make([]*codereviewv1.ExternalIssue, 0, len(references))
	for _, reference := range references {
		out = append(out, &codereviewv1.ExternalIssue{
			Tracker:  reference.Tracker,
			IssueKey: reference.IssueKey,
			Url:      reference.URL,
			LinkedBy: reference.LinkedBy,
			LinkedAt: linkedAt(reference.LinkedAt),
		})
	}
	return out
}

func linkedAt(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
