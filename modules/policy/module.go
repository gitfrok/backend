// Package policy is the Policy context's composition root (ADR-0025).
//
// See the note in modules/repository/module.go for why a module needs one: cmd/ is told to inject
// concrete implementations, but Go's internal/ rule stops it from naming what it injects.
//
// There is exactly one constructor, and no in-memory or stub variant beside it. That is deliberate.
// Every other module offers a test adapter so a caller can run without infrastructure; a PDP that
// could be constructed without a policy bundle would be a PDP that answers without consulting
// policy, and the first tired afternoon someone would wire it into something real. If a test needs
// decisions it does not care about, it should implement api.DecisionPoint itself and say so.
package policy

import (
	"fmt"

	policyv1 "github.com/gitfrok/backend/gen/proto/policy/v1"
	"github.com/gitfrok/backend/modules/policy/api"
	policygrpc "github.com/gitfrok/backend/modules/policy/internal/adapters/grpc"
	policyopa "github.com/gitfrok/backend/modules/policy/internal/adapters/opa"
	"github.com/gitfrok/backend/modules/policy/internal/app"
	"github.com/gitfrok/backend/platform/bus"
)

// NewOPADecisionPoint assembles the PDP on the OPA bundle at bundleDir, auditing its refusals to b.
//
// bundleDir is per-environment configuration (invariant 13) pointing at a copy of
// governance/policies — never a path compiled in, and never embedded, because a bundle inside this
// binary would be a second copy of rules this repo does not own (invariant 21).
//
// It returns an error rather than panicking, and the caller in cmd/ is expected to treat that as
// fatal: a plane that starts without a working PDP denies every request in the system, which
// reaches an operator as an unexplained total outage instead of a failed rollout.
func NewOPADecisionPoint(bundleDir string, b bus.Bus) (api.DecisionPoint, error) {
	evaluator, err := policyopa.New(bundleDir)
	if err != nil {
		return nil, fmt.Errorf("policy: loading bundle: %w", err)
	}
	return app.New(evaluator, b), nil
}

// NewGRPCServer exposes pdp over contracts/proto/policy/v1 for out-of-process PEPs — the BFF
// today. In-process modules take api.DecisionPoint directly and never dial this.
//
// It takes the port rather than a concrete type, so extracting Policy into its own service
// (ADR-0026) changes cmd/ and nothing else.
func NewGRPCServer(pdp api.DecisionPoint) policyv1.PolicyDecisionPointServer {
	return policygrpc.NewServer(pdp)
}
