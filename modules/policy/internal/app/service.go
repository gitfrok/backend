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
	"slices"
	"time"

	"github.com/gitfrok/backend/modules/policy/api"
	platformaudit "github.com/gitfrok/backend/platform/audit"
	"github.com/gitfrok/backend/platform/bus"
	"github.com/gitfrok/backend/platform/tenancy"
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
	// recorder is the bounded async queue the decision-record append runs on (M12): Decide's
	// synchronous path admits the record and returns without waiting for the store. The
	// availability semantics — fail-closed admission for ENFORCED records, droppable DRY_RUN
	// records under backpressure — are documented on asyncRecorder and in the MVP-RUNBOOK
	// operational contract they reference.
	recorder *asyncRecorder
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
	return &Service{pdp: pdp, bus: b, store: store, recorder: newAsyncRecorder(store, recorderBufferSize), now: time.Now}
}

// Close drains the recorder and stops its worker: every admitted record reaches the store (or
// is counted as failed) before the service goes away. A plane shutting down without it could
// lose queued decision records, which SPEC-0029 AC1 does not permit for enforced decisions.
func (s *Service) Close() {
	s.recorder.Stop()
}

// flushRecords blocks until every record enqueued so far has been applied to the store. Tests
// observe asynchronous appends through it; the serving paths never wait on it.
func (s *Service) flushRecords() {
	s.recorder.flush()
}

// DroppedRecords reports how many droppable (DRY_RUN) records the recorder shed under
// backpressure since startup — the M12 metric a runbook alert reads.
func (s *Service) DroppedRecords() int64 { return s.recorder.dropped.Load() }

// FailedRecords reports how many records the store refused inside the recorder's worker since
// startup. Under synchronous appends those failures failed the decision; asynchronously they
// are telemetry (MVP-RUNBOOK's decision-record-lag contract), which is exactly what this
// counter makes observable.
func (s *Service) FailedRecords() int64 { return s.recorder.failed.Load() }

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
//
// M12: the record's append runs on the bounded async recorder, not on this synchronous path —
// Decide admits the record and returns without blocking on the store. Admission stays
// fail-closed: a saturated recorder refuses an ENFORCED record exactly like a failed append
// used to, because SPEC-0029 AC1 requires every enforced decision recorded and the honest
// answer to "cannot guarantee that" is an error. An append that later fails inside the worker
// can no longer fail the decision; it is counted (FailedRecords) and logged — the
// availability trade-off the MVP-RUNBOOK operational contract documents and its
// decision-record-lag alert watches.
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

	if err := s.recorder.enqueue(recordJob{rec: recordOf(decision, req, decidedAt), enforced: true}); err != nil {
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
		event.ReliedUponTriage = slices.Clone(decision.ReliedUponTriage)
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
	// H1: the tenant whose history is replayed is validated against the authenticated tenant
	// bound in ctx before any read — a request asking for another tenant's decisions is
	// refused fail-closed, never served from the caller-supplied value alone.
	if err := guardTenant(ctx, req.TenantID); err != nil {
		return nil, err
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
		// M12: dry-run records ride the same recorder but are droppable — a would-be decision
		// is not evidence the way an enforced one is, so backpressure sheds it (counted and
		// logged) rather than failing the run or blocking the enforced path. Only a stopped
		// recorder errors here.
		if err := s.recorder.enqueue(recordJob{rec: recordOf(d, in, decidedAt), enforced: false}); err != nil {
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
	// H1: the caller-supplied tenant is validated against the authenticated tenant bound in
	// ctx before any read. The store is RLS-scoped, but invariant 1 requires tenant scoping
	// AND RLS — the guard here is the application's half, fail-closed on absence.
	if err := guardTenant(ctx, tenantID); err != nil {
		if errors.Is(err, api.ErrNotFound) {
			// A mismatched tenant is exactly as not-found as a nonexistent ID: one coarse
			// shape (SPEC-0030 AC6), so the guard never becomes a tenant-existence probe.
			return api.Record{}, api.ErrNotFound
		}
		return api.Record{}, err
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

// guardTenant is the H1 fail-closed check every decision-record read passes through: the
// tenant the request asks about must equal the tenant already bound in ctx (tenancy the door
// derived from the authenticated caller, never from this request's own fields). An absent
// binding is refused outright — a record read without a tenant scope is invariant 1's
// forbidden shape, whatever RLS would have filtered.
//
// GUARD HOOK POINT: the dataplane door cannot verify callers today (H2's recorded limit), so
// the door binds the request's tenant and this guard degenerates to a consistency check. Once
// door authentication lands, a tenant-pinning interceptor binds the AUTHENTICATED caller's
// tenant to ctx instead, and this very check becomes the enforcement that caller == tenant —
// no change needed in the reads themselves.
func guardTenant(ctx context.Context, tenantID string) error {
	bound, ok := tenancy.FromContext(ctx)
	if !ok {
		return tenancy.ErrNoTenant
	}
	if !bound.Equal(tenancy.ID(tenantID)) {
		return api.ErrNotFound
	}
	return nil
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
		SubjectRoles:    slices.Clone(req.Subject.Roles),
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
			Roles:    slices.Clone(rec.SubjectRoles),
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
