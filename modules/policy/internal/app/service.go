// Package app orchestrates a policy decision: evaluate, and record the refusals.
//
// It holds no authorization logic of its own and must never grow any — the whole point of ADR-0006
// is that the rules live in one reviewed place, and a service layer that could soften a denial
// would make the PDP advisory. Everything here is about what happens *around* a decision.
package app

import (
	"context"
	"fmt"
	"time"

	"github.com/gitfrok/backend/modules/policy/api"
	platformaudit "github.com/gitfrok/backend/platform/audit"
	"github.com/gitfrok/backend/platform/bus"
)

// Service is the Policy context's application layer. It implements api.DecisionPoint by delegating
// to an evaluator and auditing what that evaluator refuses.
type Service struct {
	pdp api.DecisionPoint
	bus bus.Bus
	// now is injectable so the audit event's timestamp is assertable. Not a clock abstraction —
	// one function, because that is all this needs.
	now func() time.Time
}

// New wires the service onto an evaluator and the bus it audits to. Both come from the module's
// composition root, which gets them from cmd/ (ADR-0025).
func New(pdp api.DecisionPoint, b bus.Bus) *Service {
	return &Service{pdp: pdp, bus: b, now: time.Now}
}

// Decide evaluates req and audits a refusal.
//
// The decision is returned exactly as the evaluator produced it. There is no path here that turns a
// deny into an allow, and the ordering guarantees the same for failures: the audit event is
// published *after* the decision exists, so nothing about auditing can influence what was decided.
func (s *Service) Decide(ctx context.Context, req api.Request) (api.Decision, error) {
	decision, err := s.pdp.Decide(ctx, req)
	if err != nil {
		// No decision was reached, so nothing is audited: an event saying the PDP refused this
		// caller would be a false statement about a policy that never ran. The failure belongs in
		// telemetry, and the caller is denied because api.DecisionPoint says an error means denial.
		return decision, fmt.Errorf("policy: deciding %s: %w", req.Action, err)
	}

	if decision.Allowed {
		return decision, nil
	}

	event := platformaudit.PolicyDecisionDenied{
		TenantID:     req.TenantID,
		ActorID:      req.Subject.ID,
		DeniedAction: req.Action,
		// An opaque type/id reference, never the resource's contents (ADR-0007).
		Resource:       req.Resource.Type + "/" + req.Resource.ID,
		DecisionID:     decision.DecisionID,
		PolicyRevision: decision.PolicyRevision,
		OccurredAt:     s.now(),
	}

	if err := s.bus.Publish(ctx, event); err != nil {
		// The refusal already happened and stands — the decision returned is still the denial, so
		// no caller gains access from a broken bus. What is lost is the *record*, which is a G5
		// compliance gap and must not be swallowed. Returning both is the honest shape: Allowed is
		// false either way, and a caller that only checks the error still denies.
		return decision, fmt.Errorf("policy: denial of %s was not audited: %w", req.Action, err)
	}

	return decision, nil
}
