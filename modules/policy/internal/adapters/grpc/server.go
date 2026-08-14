// Package grpc serves the Policy context over contracts/proto/policy/v1.
//
// This is the PDP's cross-process door, used by the BFF — which cannot call in-process because it
// is a different repo and a different binary (invariant 22). In-process callers use the module's
// api/ package directly and never come through here.
//
// Since T-0025 (SPEC-0029, SPEC-0030) the door also serves the decision-provenance surface:
// EvaluateDryRun and GetDecision. The same asymmetry governs all three methods: a decision (or
// its absence) is a normal response, and a FAILURE to produce one is an error status — and every
// provenance value on the wire is server-produced, never copied from a request field.
package grpc

import (
	"context"
	"errors"

	policyv1 "github.com/gitfrok/backend/gen/proto/policy/v1"
	"github.com/gitfrok/backend/modules/policy/api"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Server adapts the generated service onto the module's api/ ports: the decision point, plus
// the provenance surface when the plane composes one. Keeping the two ports separate is what
// lets a plane (or a test) serve Decide alone — a PDP that only answers is still a PDP — while
// a configured plane serves the full contract.
type Server struct {
	policyv1.UnimplementedPolicyDecisionPointServer
	pdp     api.DecisionPoint
	records api.DecisionRecords // nil on a plane without a decision-record surface
}

// NewServer returns a server backed by pdp, serving the provenance RPCs from records when it
// is non-nil. A nil records is honest, not degraded: the provenance RPCs then report
// Unimplemented rather than being served by something else.
func NewServer(pdp api.DecisionPoint, records api.DecisionRecords) *Server {
	return &Server{pdp: pdp, records: records}
}

// Decide answers one authorization question.
//
// THE DISTINCTION THIS METHOD EXISTS TO PRESERVE: a denial comes back as a normal response with
// allowed=false, and a *failure to decide* comes back as an error status. They are not
// interchangeable. A PEP caches decisions, so collapsing a failure into a synthesized denial would
// write into that cache an answer no policy ever gave — and it would keep denying long after the
// PDP recovered. Equally, reporting a denial as an error would make every refusal look like an
// outage. One is the system working; the other is the system broken.
func (s *Server) Decide(ctx context.Context, req *policyv1.DecideRequest) (*policyv1.DecideResponse, error) {
	decision, err := s.pdp.Decide(ctx, requestOf(req))
	if err != nil {
		// Internal, not PermissionDenied: PermissionDenied is what a *decided* refusal would be,
		// and this is the absence of a decision. The error text is the operator's, not the
		// caller's — it says the PDP failed, never why a subject might have been refused.
		return nil, status.Error(codes.Internal, "policy decision unavailable")
	}

	return &policyv1.DecideResponse{
		Allowed:        decision.Allowed,
		Reason:         decision.Reason,
		PolicyRevision: decision.PolicyRevision,
		DecisionId:     decision.DecisionID,
		InputDigest:    decision.InputDigest,
		Mode:           modeToProto(decision.Mode),
	}, nil
}

// EvaluateDryRun replays bounded history through a candidate bundle and reports what it would
// have decided (SPEC-0029 AC2, SPEC-0030 AC3).
//
// The request names the bundle and the history; everything in the response is server-produced —
// each would-be decision carries mode=DRY_RUN and the CANDIDATE's revision, and nothing about it
// is an authorization outcome. A range that would exceed max_results is a refusal, never a
// silent truncation (SPEC-0030): the caller narrows the range instead of receiving a partial
// result that looks complete.
func (s *Server) EvaluateDryRun(ctx context.Context, req *policyv1.EvaluateDryRunRequest) (*policyv1.EvaluateDryRunResponse, error) {
	if s.records == nil {
		return nil, status.Error(codes.Unimplemented, "dry-run evaluation unavailable")
	}
	if req.GetTenantId() == "" || req.GetCandidateBundleRef() == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant and candidate bundle reference are required")
	}
	r := req.GetRange()
	decisions, err := s.records.EvaluateDryRun(ctx, api.DryRunRequest{
		TenantID:           req.GetTenantId(),
		CandidateBundleRef: req.GetCandidateBundleRef(),
		Range: api.HistoricalRange{
			Action: r.GetAction(),
			Resource: api.Resource{
				Type: r.GetResource().GetType(),
				ID:   r.GetResource().GetId(),
			},
			From: r.GetFrom().AsTime(),
			To:   r.GetTo().AsTime(),
		},
		MaxResults: int(req.GetMaxResults()),
	})
	if err != nil {
		switch {
		case errors.Is(err, api.ErrInvalidRequest):
			// Malformed or over-cap: the request is what cannot be served.
			return nil, status.Error(codes.InvalidArgument, "dry-run request refused")
		case errors.Is(err, api.ErrNoCandidateLoader):
			// This plane composes no candidate-bundle loader; the operation is unavailable
			// here, not denied.
			return nil, status.Error(codes.Unimplemented, "dry-run evaluation unavailable")
		default:
			// A candidate that fails to load or evaluate is the absence of a result, not a
			// result — same rule as Decide: never synthesize an outcome.
			return nil, status.Error(codes.Internal, "dry-run evaluation unavailable")
		}
	}

	out := &policyv1.EvaluateDryRunResponse{}
	for _, d := range decisions {
		out.Decisions = append(out.Decisions, &policyv1.DecideResponse{
			Allowed:        d.Allowed,
			Reason:         d.Reason,
			PolicyRevision: d.PolicyRevision,
			DecisionId:     d.DecisionID,
			InputDigest:    d.InputDigest,
			Mode:           modeToProto(d.Mode),
		})
	}
	return out, nil
}

// GetDecision retrieves one recorded decision by the ID the PDP assigned (SPEC-0029 AC1).
//
// The decision_id is a SELECTOR, not an assertion: the caller can only name a decision the
// server already produced. A nonexistent ID and another tenant's ID both come back as the same
// coarse shape — an absent record — so existence in another tenant cannot be probed
// (SPEC-0030 AC6).
func (s *Server) GetDecision(ctx context.Context, req *policyv1.GetDecisionRequest) (*policyv1.GetDecisionResponse, error) {
	if s.records == nil {
		return nil, status.Error(codes.Unimplemented, "decision record retrieval unavailable")
	}
	if req.GetTenantId() == "" || req.GetDecisionId() == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant and decision id are required")
	}
	rec, err := s.records.GetDecision(ctx, req.GetTenantId(), req.GetDecisionId())
	if err != nil {
		if errors.Is(err, api.ErrNotFound) {
			// Absence and denial are the same shape: a response with no record, not an error
			// status that would distinguish "not here" from "not yours" (SPEC-0001).
			return &policyv1.GetDecisionResponse{}, nil
		}
		return nil, status.Error(codes.Internal, "decision record unavailable")
	}
	return &policyv1.GetDecisionResponse{Record: recordToProto(rec)}, nil
}

// requestOf maps the wire request onto the port's request.
//
// Every getter is the generated nil-safe accessor. Proto3 message fields are pointers and a client
// may omit any of them, so a direct field read here would be a remotely-triggerable nil deref in
// the one component every authorization flows through. Absent fields become zero values and the
// policy denies them, which is the correct outcome and one that policy — not this adapter — decides.
func requestOf(req *policyv1.DecideRequest) api.Request {
	return api.Request{
		TenantID: req.GetTenantId(),
		Subject: api.Subject{
			ID:       req.GetSubject().GetId(),
			TenantID: req.GetSubject().GetTenantId(),
			Roles:    req.GetSubject().GetRoles(),
		},
		Action: req.GetAction(),
		Resource: api.Resource{
			Type: req.GetResource().GetType(),
			ID:   req.GetResource().GetId(),
		},
		Context: req.GetContext(),
	}
}

// modeToProto renders the port's mode on the wire. Only the two defined values map; anything
// else — including an empty mode from a misbehaving evaluator — renders as UNSPECIFIED rather
// than being laundered into ENFORCED.
func modeToProto(m api.Mode) policyv1.EvaluationMode {
	switch m {
	case api.ModeEnforced:
		return policyv1.EvaluationMode_EVALUATION_MODE_ENFORCED
	case api.ModeDryRun:
		return policyv1.EvaluationMode_EVALUATION_MODE_DRY_RUN
	default:
		return policyv1.EvaluationMode_EVALUATION_MODE_UNSPECIFIED
	}
}

// recordToProto maps a stored record onto its wire shape. It carries provenance and outcome,
// never the rule source: the wire message has no field for it by design (G9).
func recordToProto(r api.Record) *policyv1.DecisionRecord {
	return &policyv1.DecisionRecord{
		DecisionId:     r.DecisionID,
		PolicyRevision: r.PolicyRevision,
		InputDigest:    r.InputDigest,
		Mode:           modeToProto(r.Mode),
		TenantId:       r.TenantID,
		ActorId:        r.ActorID,
		Action:         r.Action,
		Resource: &policyv1.Resource{
			Type: r.Resource.Type,
			Id:   r.Resource.ID,
		},
		Allowed:   r.Allowed,
		DecidedAt: timestamppb.New(r.DecidedAt),
	}
}
