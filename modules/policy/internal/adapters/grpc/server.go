// Package grpc serves the Policy context over contracts/proto/policy/v1.
//
// This is the PDP's cross-process door, used by the BFF — which cannot call in-process because it
// is a different repo and a different binary (invariant 22). In-process callers use the module's
// api/ package directly and never come through here.
package grpc

import (
	"context"

	policyv1 "github.com/gitfrok/backend/gen/proto/policy/v1"
	"github.com/gitfrok/backend/modules/policy/api"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Server adapts the generated service onto the module's api/ port.
type Server struct {
	policyv1.UnimplementedPolicyDecisionPointServer
	pdp api.DecisionPoint
}

// NewServer returns a server backed by pdp.
func NewServer(pdp api.DecisionPoint) *Server { return &Server{pdp: pdp} }

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
	}, nil
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
