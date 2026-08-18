package main

import (
	"context"

	policyapi "github.com/gitfrok/backend/modules/policy/api"
	repoapi "github.com/gitfrok/backend/modules/repository/api"
)

// repoAuthorizer adapts the PDP onto the Repository context's own Authorizer port
// (T-0053, SPEC-0052 AC4).
//
// It lives here rather than in the Repository module because that module is a leaf: everything
// depends on it and it depends on no other context, which the architecture fitness function pins
// at fan-out zero. Importing the Policy context to ask one question would invert that for one
// call, so the dependency points the other way — the composition root knows both, and the module
// asks an abstraction it owns (invariant 14, ADR-0025).
type repoAuthorizer struct {
	pdp policyapi.DecisionPoint
}

// MayRead asks whether the caller may see that a repository exists.
//
// It asks `repo.read`, the same question the browse path asks before serving a repository's
// contents, because being told a repository exists is itself a read: a caller who may not read it
// must not learn it is there (PR-24, SPEC-0001).
//
// An error is returned as an error, not as a false. The caller decides what a failed decision
// means for its own shape — List treats it as a refusal for that one repository, so an
// unavailable PDP hides repositories rather than failing the whole page (ADR-0006).
func (a repoAuthorizer) MayRead(ctx context.Context, tenantID, actorID string, roles []string, repoID string) (bool, error) {
	d, err := a.pdp.Decide(ctx, policyapi.Request{
		TenantID: tenantID,
		Subject: policyapi.Subject{
			ID:       actorID,
			TenantID: tenantID,
			Roles:    roles,
		},
		Action:   "repo.read",
		Resource: policyapi.Resource{Type: "repository", ID: repoID},
	})
	if err != nil {
		return false, err
	}
	return d.Allowed, nil
}

var _ repoapi.Authorizer = repoAuthorizer{}
