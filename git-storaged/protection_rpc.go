package main

import (
	"context"
	"strconv"

	gitv1 "github.com/gitfrok/backend/gen/proto/git/v1"
	codereviewapi "github.com/gitfrok/backend/modules/codereview/api"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
)

// SetProtection delivers one exact-ref branch-protection rule from Code Review
// (SPEC-0019 AC7). See the contract: Code Review owns the rules and has already
// asked its own PDP before calling this; storage applies its own PDP decision
// with server-derived context and then installs the rule in the projection the
// receive-pack path reads before it accepts a direct ref update.
//
// It is the cross-process counterpart of BranchProtectionChanged: when Code
// Review and git-storaged share a bus the event is sufficient, and when they do
// not, this call is the route by which the rule reaches the node that enforces
// direct pushes.
//
// A rule may arrive before the repository exists — protection should be in
// effect for the first push, not the second — so no repository existence check
// is performed. The rule governs the receive-pack path alone; it cannot move a
// ref, read bytes, or carry any authorization result.
func (s *Server) SetProtection(ctx context.Context, req *gitv1.SetProtectionRequest) (*gitv1.SetProtectionResponse, error) {
	principal := req.GetContext()
	targetRef := req.GetTargetRef()
	if s.protection == nil ||
		principal == nil || !validHandle(principal.GetTenantId()) || !validHandle(principal.GetRepositoryId()) ||
		principal.GetActorId() == "" || principal.GetRequestId() == "" ||
		!validBranchRef(targetRef) || req.GetRequiredApprovals() < 0 {
		return nil, unavailable()
	}

	decision, err := s.pdp.Decide(ctx, policyapi.Request{
		TenantID: principal.GetTenantId(),
		// Roles arrive only from a verified Identity&Access principal through a
		// trusted caller. They are PDP input, never a client-provided allow result.
		Subject: policyapi.Subject{
			ID:       principal.GetActorId(),
			TenantID: principal.GetTenantId(),
			Roles:    append([]string(nil), principal.GetActorRoles()...),
		},
		Action:   "repository.branch_protection.manage",
		Resource: policyapi.Resource{Type: "repository", ID: principal.GetRepositoryId()},
		Context: map[string]string{
			"request_id":         principal.GetRequestId(),
			"target_ref":         targetRef,
			"required_approvals": strconv.Itoa(int(req.GetRequiredApprovals())),
		},
	})
	if err != nil || !decision.Allowed {
		return nil, unavailable()
	}

	s.protection.Set(codereviewapi.BranchProtection{
		TenantID:          principal.GetTenantId(),
		RepositoryID:      principal.GetRepositoryId(),
		TargetRef:         targetRef,
		RequiredApprovals: req.GetRequiredApprovals(),
	})
	return &gitv1.SetProtectionResponse{}, nil
}
