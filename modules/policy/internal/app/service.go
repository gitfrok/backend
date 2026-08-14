// Package app orchestrates policy decisions: evaluate, record, and audit.
//
// It holds no authorization logic of its own and must never grow any — the whole point of ADR-0006
// is that the rules live in one reviewed place, and a service layer that could soften a denial
// would make the PDP advisory. Everything here is about what happens *around* a decision.
//
// Since T-0025 (SPEC-0029, SPEC-0030) that also means provenance: every decision is appended to
// the record store with the deciding bundle revision, a digest over its canonicalized input, and
// its mode, and the dry-run surface replays recorded history through a candidate bundle without
// enforcing anything.
package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/gitfrok/backend/modules/policy/api"
	platformaudit "github.com/gitfrok/backend/platform/audit"
	"github.com/gitfrok/backend/platform/bus"
)

// defaultMaxResults caps a dry-run whose request names no cap of its own (SPEC-0030: bounded
// per request).
const defaultMaxResults = 100

// hardMaxResults caps the cap: a single dry-run may never produce more would-be decisions than
// this, whatever the request asks for (SPEC-0030 non-functional: bounded, batchable, isolated
// from the enforced path).
const hardMaxResults = 1000

// Service is the Policy context's application layer. It implements api.Service by delegating
// decisions to an evaluator, recording every one, and auditing what the evaluator refuses.
type Service struct {
	pdp   api.DecisionPoint
	bus   bus.Bus
	store RecordStore
	// loadCandidate resolves a candidate bundle reference onto an evaluator for dry-runs
	// (SPEC-0029 reading A). Nil on a plane that composes none — a dry-run there is a refusal,
	// not an approximation (api.ErrNoCandidateLoader).
	loadCandidate func(ctx context.Context, ref string) (api.DecisionPoint, error)
	// now is injectable so recorded timestamps are assertable. Not a clock abstraction —
	// one function, because that is all this needs.
	now func() time.Time
}

// New wires the service onto an evaluator, the bus it audits to, and the store its decisions
// are recorded in. All three come from the module's composition root (ADR-0025). A nil store is
// a composition error — a PDP that cannot record its decisions cannot satisfy SPEC-0029 AC1 —
// so it panics rather than producing a plane that answers and leaves no evidence.
func New(pdp api.DecisionPoint, b bus.Bus, store RecordStore) *Service {
	if store == nil {
		panic("policy: no decision record store — every decision must be recorded (SPEC-0029 AC1)")
	}
	return &Service{pdp: pdp, bus: b, store: store, now: time.Now}
}

// WithCandidateLoader attaches the dry-run's candidate-bundle resolver. Post-construction
// because the loader is a plane-level concern — where reviewed policy code lives on disk —
// while the service is composed before that is known.
func (s *Service) WithCandidateLoader(load func(ctx context.Context, ref string) (api.DecisionPoint, error)) *Service {
	s.loadCandidate = load
	return s
}

// Decide evaluates req, records the decision, and audits a refusal.
//
// The outcome is returned exactly as the evaluator produced it — there is no path here that
// turns a deny into an allow — and the provenance the service adds is all server-produced:
// the evaluator's decision ID and revision are carried through, the input digest is derived
// from the request itself, and the mode is ENFORCED because Decide is the enforcing path
// (SPEC-0030 AC2: no caller asserts any of it).
func (s *Service) Decide(ctx context.Context, req api.Request) (api.Decision, error) {
	decision, err := s.pdp.Decide(ctx, req)
	if err != nil {
		// No decision was reached, so nothing is recorded and nothing is audited: a record of a
		// decision the PDP never made would be a false statement. The failure belongs in
		// telemetry, and the caller is denied because api.DecisionPoint says an error means
		// denial.
		return decision, fmt.Errorf("policy: deciding %s: %w", req.Action, err)
	}

	decidedAt := s.now()
	decision.Mode = api.ModeEnforced
	decision.InputDigest = digestOf(req)

	if err := s.store.Append(ctx, recordOf(decision, req, decidedAt)); err != nil {
		// The decision stands — it already happened — but SPEC-0029 AC1 says every decision is
		// recorded and retrievable, and an unrecorded decision is a compliance gap exactly as
		// an unrecorded denial is. Surfacing the error is the honest shape: a caller that only
		// checks the error denies, and the decision's Allowed is true only for a caller that
		// knowingly accepts the recording gap.
		return decision, fmt.Errorf("policy: decision %s was not recorded: %w", decision.DecisionID, err)
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
		InputDigest:    decision.InputDigest,
		PolicyMode:     string(api.ModeEnforced),
		OccurredAt:     decidedAt,
	}
	if len(decision.ReliedUponTriage) > 0 {
		event.ReliedUponTriage = append([]string(nil), decision.ReliedUponTriage...)
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

// EvaluateDryRun replays the tenant's recorded decision history through a candidate bundle and
// reports what it *would* have decided (SPEC-0029 AC2, SPEC-0030 AC3).
//
// Every returned decision is labelled ModeDryRun and carries the CANDIDATE bundle's revision —
// the would-be deciding version — with a fresh server-assigned decision ID and a digest
// re-derived from the replayed input, which equals the original decision's digest: the replay
// asks the same question, and the digest is a function of the question alone.
func (s *Service) EvaluateDryRun(ctx context.Context, req api.DryRunRequest) ([]api.Decision, error) {
	if req.TenantID == "" || req.CandidateBundleRef == "" {
		return nil, fmt.Errorf("%w: tenant and candidate bundle reference are required", api.ErrInvalidRequest)
	}
	limit := req.MaxResults
	if limit <= 0 {
		limit = defaultMaxResults
	}
	if limit > hardMaxResults {
		return nil, fmt.Errorf("%w: max_results %d exceeds the per-request cap %d — narrow the range instead",
			api.ErrInvalidRequest, req.MaxResults, hardMaxResults)
	}
	if s.loadCandidate == nil {
		return nil, api.ErrNoCandidateLoader
	}

	candidate, err := s.loadCandidate(ctx, req.CandidateBundleRef)
	if err != nil {
		return nil, fmt.Errorf("policy: loading candidate bundle %q: %w", req.CandidateBundleRef, err)
	}

	// limit+1 entries come back so an over-cap range is detected and rejected, never truncated
	// (SPEC-0030 open question, settled on the side of honesty).
	history, err := s.store.Range(ctx, req.TenantID, req.Range, limit)
	if err != nil {
		return nil, fmt.Errorf("policy: reading decision history: %w", err)
	}
	if len(history) > limit {
		return nil, fmt.Errorf("%w: range covers more than %d decisions — narrow the range",
			api.ErrInvalidRequest, limit)
	}

	decisions := make([]api.Decision, 0, len(history))
	for i, rec := range history {
		in := requestOf(rec)
		d, err := candidate.Decide(ctx, in)
		if err != nil {
			// A candidate that cannot answer one of the replayed inputs has not produced a
			// partial dry-run result that looks complete: refuse the whole operation.
			return nil, fmt.Errorf("policy: candidate bundle evaluating decision %s: %w", rec.DecisionID, err)
		}
		// Monotonically increasing timestamps keep the would-be decisions orderable even when
		// the clock does not move between two of them.
		decidedAt := s.now().Add(time.Duration(i) * time.Microsecond)
		d.Mode = api.ModeDryRun
		d.InputDigest = digestOf(in)
		if err := s.store.Append(ctx, recordOf(d, in, decidedAt)); err != nil {
			return nil, fmt.Errorf("policy: recording dry-run decision %s: %w", d.DecisionID, err)
		}
		decisions = append(decisions, d)
	}
	return decisions, nil
}

// GetDecision retrieves one recorded decision within the tenant that made it (SPEC-0029 AC1).
// A missing ID and another tenant's ID both yield api.ErrNotFound: one coarse shape, so a
// probe cannot enumerate which decision IDs exist elsewhere (SPEC-0030 AC6).
func (s *Service) GetDecision(ctx context.Context, tenantID, decisionID string) (api.Record, error) {
	if tenantID == "" || decisionID == "" {
		return api.Record{}, fmt.Errorf("%w: tenant and decision id are required", api.ErrInvalidRequest)
	}
	rec, err := s.store.Get(ctx, tenantID, decisionID)
	if err != nil {
		if errors.Is(err, api.ErrNotFound) {
			return api.Record{}, api.ErrNotFound
		}
		return api.Record{}, fmt.Errorf("policy: reading decision %s: %w", decisionID, err)
	}
	return rec, nil
}

// recordOf assembles the stored form of one decision. Everything in it is a fact the server
// produced or a value the request carried as input; nothing is a caller claim about the outcome.
func recordOf(d api.Decision, req api.Request, decidedAt time.Time) api.Record {
	return api.Record{
		DecisionID:      d.DecisionID,
		PolicyRevision:  d.PolicyRevision,
		InputDigest:     d.InputDigest,
		Mode:            d.Mode,
		TenantID:        req.TenantID,
		ActorID:         req.Subject.ID,
		Action:          req.Action,
		Resource:        req.Resource,
		Allowed:         d.Allowed,
		Reason:          d.Reason,
		DecidedAt:       decidedAt.UTC(),
		SubjectTenantID: req.Subject.TenantID,
		SubjectRoles:    append([]string(nil), req.Subject.Roles...),
		Context:         copyContext(req.Context),
	}
}

// requestOf rebuilds the decision question a record answers — the input a dry-run replays. It
// is the inverse of recordOf, and the digest's reproducibility is what proves the round trip:
// digestOf(requestOf(rec)) equals the record's InputDigest for any recorded decision.
func requestOf(rec api.Record) api.Request {
	return api.Request{
		TenantID: rec.TenantID,
		Subject: api.Subject{
			ID:       rec.ActorID,
			TenantID: rec.SubjectTenantID,
			Roles:    append([]string(nil), rec.SubjectRoles...),
		},
		Action:   rec.Action,
		Resource: rec.Resource,
		Context:  copyContext(rec.Context),
	}
}

func copyContext(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
