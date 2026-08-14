package app

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/gitfrok/backend/modules/policy/api"
	platformaudit "github.com/gitfrok/backend/platform/audit"
	"github.com/gitfrok/backend/platform/bus"
)

// stubPDP is the evaluator seam. The Rego rules are governance's to test and the OPA adapter is
// tested against its own fixtures; what this file is about is what the service does *around* a
// decision, so the decision itself is dictated here.
type stubPDP struct {
	decision api.Decision
	err      error
	calls    int
	lastReq  api.Request
}

func (s *stubPDP) Decide(_ context.Context, req api.Request) (api.Decision, error) {
	s.calls++
	s.lastReq = req
	return s.decision, s.err
}

// recorder collects everything published, so a test can assert on absence as well as presence.
type recorder struct {
	events []bus.Event
	err    error
}

func (r *recorder) Publish(_ context.Context, e bus.Event) error {
	r.events = append(r.events, e)
	return r.err
}

func (r *recorder) Subscribe(string, bus.Handler) {}

func allowed() api.Decision {
	return api.Decision{Allowed: true, Reason: "allowed", PolicyRevision: "rev-1", DecisionID: "01ALLOW"}
}

func denied() api.Decision {
	return api.Decision{Allowed: false, Reason: "denied", PolicyRevision: "rev-1", DecisionID: "01DENY"}
}

func request() api.Request {
	return api.Request{
		TenantID: "acme",
		Subject:  api.Subject{ID: "u-1", TenantID: "acme", Roles: []string{"reader"}},
		Action:   "repo.read",
		Resource: api.Resource{Type: "repository", ID: "repo-1"},
	}
}

func newService(pdp api.DecisionPoint, b bus.Bus) *Service {
	return newServiceWithStore(pdp, b, NewMemoryStore())
}

func newServiceWithStore(pdp api.DecisionPoint, b bus.Bus, store RecordStore) *Service {
	s := New(pdp, b, store)
	s.now = func() time.Time { return time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC) }
	return s
}

// --- the decision passes through unaltered --------------------------------------------------------

// The service must not be able to change an answer. If it could soften a denial, invariant 2 would
// hold only by convention — the PDP would be advisory.
func TestDecisionIsReturnedUnaltered(t *testing.T) {
	for _, tc := range []struct {
		name string
		want api.Decision
	}{
		{"allow", allowed()},
		{"deny", denied()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pdp := &stubPDP{decision: tc.want}
			got, err := newService(pdp, &recorder{}).Decide(t.Context(), request())
			if err != nil {
				t.Fatalf("Decide: %v", err)
			}
			// The evaluator's answer passes through verbatim; the only fields the service adds
			// are its own server-produced provenance (SPEC-0030 AC2): the mode and the digest
			// over the request it just evaluated. No caller supplies either.
			want := tc.want
			want.Mode = api.ModeEnforced
			want.InputDigest = digestOf(request())
			if !reflect.DeepEqual(got, want) {
				t.Errorf("Decide() = %+v, want %+v", got, want)
			}
		})
	}
}

func TestRequestReachesTheEvaluatorUnaltered(t *testing.T) {
	pdp := &stubPDP{decision: allowed()}
	req := request()
	if _, err := newService(pdp, &recorder{}).Decide(t.Context(), req); err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if pdp.calls != 1 {
		t.Fatalf("evaluator called %d times, want exactly 1", pdp.calls)
	}
	if pdp.lastReq.TenantID != req.TenantID || pdp.lastReq.Action != req.Action ||
		pdp.lastReq.Subject.ID != req.Subject.ID {
		t.Errorf("evaluator saw %+v, want %+v", pdp.lastReq, req)
	}
}

// --- G5: denials are audited, allows are not --------------------------------------------------------

func TestDenialEmitsAnAuditEvent(t *testing.T) {
	rec := &recorder{}
	if _, err := newService(&stubPDP{decision: denied()}, rec).Decide(t.Context(), request()); err != nil {
		t.Fatalf("Decide: %v", err)
	}

	if len(rec.events) != 1 {
		t.Fatalf("published %d events, want 1", len(rec.events))
	}
	got, ok := rec.events[0].(platformaudit.PolicyDecisionDenied)
	if !ok {
		t.Fatalf("published %T, want PolicyDecisionDenied", rec.events[0])
	}
	if got.TenantID != "acme" || got.ActorID != "u-1" || got.DeniedAction != "repo.read" {
		t.Errorf("event = %+v, want the request's tenant, actor and action", got)
	}
	// Without these two a denial cannot be reproduced or correlated later.
	if got.DecisionID != "01DENY" {
		t.Errorf("DecisionID = %q, want the decision's own id", got.DecisionID)
	}
	if got.PolicyRevision != "rev-1" {
		t.Errorf("PolicyRevision = %q, want the revision that produced the refusal", got.PolicyRevision)
	}
	if got.EventName() != platformaudit.EventAudit {
		t.Errorf("EventName = %q, want the audit contract's full name", got.EventName())
	}
}

// Auditing every allow would put a write on the hot path of every authorized request and bury the
// refusals, which are what an investigation looks for.
func TestAllowEmitsNothing(t *testing.T) {
	rec := &recorder{}
	if _, err := newService(&stubPDP{decision: allowed()}, rec).Decide(t.Context(), request()); err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if len(rec.events) != 0 {
		t.Errorf("an allowed decision published %d events, want none: %+v", len(rec.events), rec.events)
	}
}

// The audit event must not carry the policy's reason. The reason given to a caller is coarse by
// design, and a trail that named the failing rule would rebuild the oracle that coarseness closes.
func TestAuditEventCarriesNoPolicyText(t *testing.T) {
	rec := &recorder{}
	d := denied()
	d.Reason = "denied: subject lacks role owner on repo-1"
	if _, err := newService(&stubPDP{decision: d}, rec).Decide(t.Context(), request()); err != nil {
		t.Fatalf("Decide: %v", err)
	}
	got := rec.events[0].(platformaudit.PolicyDecisionDenied)
	if got.Resource != "repository/repo-1" {
		t.Errorf("Resource = %q, want an opaque type/id reference", got.Resource)
	}
	// A struct with no reason field cannot carry one; this pins that as intentional rather than
	// something to be "fixed" by a later well-meaning addition.
	if _, hasReason := any(got).(interface{ GetReason() string }); hasReason {
		t.Error("the audit event exposes a reason; policy text must not reach the trail")
	}
}

// --- failure modes never widen access ----------------------------------------------------------------

// An evaluator failure means no decision was reached. Nothing is audited — "the PDP refused you"
// would be a false statement — and the caller is denied.
func TestEvaluatorErrorDeniesAndAuditsNothing(t *testing.T) {
	rec := &recorder{}
	boom := errors.New("bundle exploded")
	got, err := newService(&stubPDP{err: boom}, rec).Decide(t.Context(), request())

	if !errors.Is(err, boom) {
		t.Errorf("error = %v, want it to wrap the evaluator's", err)
	}
	if got.Allowed {
		t.Error("an evaluator failure produced Allowed=true")
	}
	if len(rec.events) != 0 {
		t.Errorf("an evaluator failure audited %d events; nothing was decided", len(rec.events))
	}
}

// A failed audit publish must not turn a denial into an allow. The refusal already happened and
// stands; what is lost is the record of it, so the error is surfaced rather than swallowed.
func TestAuditFailureStillDenies(t *testing.T) {
	rec := &recorder{err: errors.New("bus down")}
	got, err := newService(&stubPDP{decision: denied()}, rec).Decide(t.Context(), request())

	if err == nil {
		t.Error("a dropped audit event was silent; an unrecorded denial is a compliance gap (G5)")
	}
	if got.Allowed {
		t.Fatal("a failed audit publish flipped a denial into an allow")
	}
}

// The invariant that matters most, stated on its own: whatever goes wrong, Allowed is false.
func TestAllowedIsNeverTrueOnError(t *testing.T) {
	for _, tc := range []struct {
		name string
		pdp  *stubPDP
		rec  *recorder
	}{
		{"evaluator error", &stubPDP{err: errors.New("x")}, &recorder{}},
		{"audit error on denial", &stubPDP{decision: denied()}, &recorder{err: errors.New("x")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := newService(tc.pdp, tc.rec).Decide(t.Context(), request())
			if err == nil {
				t.Fatal("expected an error")
			}
			if got.Allowed {
				t.Error("Allowed=true alongside an error")
			}
		})
	}
}

// --- T-0025: every decision is recorded with server-produced provenance ----------------------

// SPEC-0029 AC1: a decision that happened must be retrievable afterwards, allowed or denied,
// with the provenance it was made under.
func TestEveryDecisionIsRecorded(t *testing.T) {
	for _, tc := range []struct {
		name     string
		decision api.Decision
	}{
		{"allow", allowed()},
		{"deny", denied()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc := newService(&stubPDP{decision: tc.decision}, &recorder{})
			req := request()
			if _, err := svc.Decide(t.Context(), req); err != nil {
				t.Fatalf("Decide: %v", err)
			}
			rec, err := svc.GetDecision(t.Context(), req.TenantID, tc.decision.DecisionID)
			if err != nil {
				t.Fatalf("GetDecision: %v", err)
			}
			if rec.Mode != api.ModeEnforced {
				t.Errorf("Mode = %q, want ENFORCED for a Decide-produced record", rec.Mode)
			}
			if rec.InputDigest != digestOf(req) {
				t.Errorf("InputDigest = %q, want the digest over the recorded input", rec.InputDigest)
			}
			if rec.PolicyRevision != tc.decision.PolicyRevision || rec.Allowed != tc.decision.Allowed ||
				rec.Action != req.Action || rec.TenantID != req.TenantID {
				t.Errorf("record = %+v, want the decision's outcome over the request", rec)
			}
		})
	}
}

// The recorded input digest is reproducible from the recorded input itself: re-deriving it from
// the record's question must land on the stored value, or an auditor could not prove which
// input a decision answered (SPEC-0030).
func TestRecordedDigestIsReDerivableFromTheRecord(t *testing.T) {
	svc := newService(&stubPDP{decision: allowed()}, &recorder{})
	req := request()
	req.Context = map[string]string{"protocol": "https", "origin": "web"}
	if _, err := svc.Decide(t.Context(), req); err != nil {
		t.Fatalf("Decide: %v", err)
	}
	rec, err := svc.GetDecision(t.Context(), req.TenantID, allowed().DecisionID)
	if err != nil {
		t.Fatalf("GetDecision: %v", err)
	}
	if got := digestOf(requestOf(rec)); got != rec.InputDigest {
		t.Errorf("re-derived digest %q, want the recorded %q", got, rec.InputDigest)
	}
}

// An evaluator failure records nothing: a record of a decision the PDP never made would be a
// false statement in the evidence trail.
func TestEvaluatorErrorRecordsNothing(t *testing.T) {
	svc := newService(&stubPDP{err: errors.New("bundle exploded")}, &recorder{})
	if _, err := svc.Decide(t.Context(), request()); err == nil {
		t.Fatal("expected an error")
	}
	if _, err := svc.GetDecision(t.Context(), "acme", "anything"); !errors.Is(err, api.ErrNotFound) {
		t.Errorf("GetDecision = %v, want ErrNotFound: a failed decision leaves no record", err)
	}
}

// Retrieval is tenant-scoped and coarse: another tenant's ID and a nonexistent ID are the same
// not-found (SPEC-0030 AC6).
func TestGetDecisionIsCoarseNotFound(t *testing.T) {
	svc := newService(&stubPDP{decision: allowed()}, &recorder{})
	if _, err := svc.Decide(t.Context(), request()); err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if _, err := svc.GetDecision(t.Context(), "other-tenant", allowed().DecisionID); !errors.Is(err, api.ErrNotFound) {
		t.Errorf("cross-tenant GetDecision = %v, want ErrNotFound", err)
	}
	if _, err := svc.GetDecision(t.Context(), "acme", "no-such-id"); !errors.Is(err, api.ErrNotFound) {
		t.Errorf("nonexistent GetDecision = %v, want the same ErrNotFound", err)
	}
}

// --- T-0025: dry-run evaluation --------------------------------------------------------------

// countingPDP is the candidate-bundle seam for dry-runs: it answers every replayed input with
// the dictated decision, assigning each a fresh decision ID the way a real PDP would.
type countingPDP struct {
	decision api.Decision
	err      error
	calls    int
	lastReqs []api.Request
}

func (s *countingPDP) Decide(_ context.Context, req api.Request) (api.Decision, error) {
	s.calls++
	s.lastReqs = append(s.lastReqs, req)
	if s.err != nil {
		return api.Decision{}, s.err
	}
	d := s.decision
	d.DecisionID = fmt.Sprintf("01DRY%04d", s.calls)
	return d, nil
}

// The dry-run's core claim (SPEC-0029 AC2): recorded enforced inputs are replayed through the
// CANDIDATE bundle, each would-be decision labelled DRY_RUN under the candidate's revision, and
// the digest re-derives the original — same question, same digest.
func TestDryRunReplaysEnforcedHistoryThroughTheCandidate(t *testing.T) {
	// Two enforced decisions form the history the dry-run replays.
	rec := &recorder{}
	pdp := &stubPDP{decision: allowed()}
	svc := newService(pdp, rec)
	candidate := &countingPDP{decision: api.Decision{Allowed: false, Reason: "denied", PolicyRevision: "rev-candidate"}}
	svc.WithCandidateLoader(func(_ context.Context, ref string) (api.DecisionPoint, error) {
		if ref != "candidate/bundle" {
			t.Errorf("loader ref = %q, want the request's candidate reference", ref)
		}
		return candidate, nil
	})
	for i, action := range []string{"repo.read", "merge_request.merge"} {
		req := request()
		req.Action = action
		// A real PDP assigns every decision a fresh ID; the stub needs one told to.
		pdp.decision.DecisionID = fmt.Sprintf("01ENF%04d", i)
		if _, err := svc.Decide(t.Context(), req); err != nil {
			t.Fatalf("Decide: %v", err)
		}
	}

	got, err := svc.EvaluateDryRun(t.Context(), api.DryRunRequest{
		TenantID:           "acme",
		CandidateBundleRef: "candidate/bundle",
	})
	if err != nil {
		t.Fatalf("EvaluateDryRun: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("EvaluateDryRun returned %d decisions, want one per enforced record", len(got))
	}
	// Oldest first, replayed with the recorded inputs.
	if candidate.lastReqs[0].Action != "repo.read" || candidate.lastReqs[1].Action != "merge_request.merge" {
		t.Errorf("replayed actions %v, want the recorded history oldest first", candidate.lastReqs)
	}
	for i, d := range got {
		if d.Mode != api.ModeDryRun {
			t.Errorf("decision %d Mode = %q, want DRY_RUN", i, d.Mode)
		}
		if d.PolicyRevision != "rev-candidate" {
			t.Errorf("decision %d PolicyRevision = %q, want the CANDIDATE's revision", i, d.PolicyRevision)
		}
		if d.InputDigest != digestOf(candidate.lastReqs[i]) {
			t.Errorf("decision %d InputDigest = %q, want the original input's digest", i, d.InputDigest)
		}
	}

	// The would-be decisions are recorded as DRY_RUN... and never replayed by a later dry-run:
	// history is the enforced record, not a simulation of one.
	if _, err := svc.EvaluateDryRun(t.Context(), api.DryRunRequest{
		TenantID: "acme", CandidateBundleRef: "candidate/bundle",
	}); err != nil {
		t.Fatalf("second EvaluateDryRun: %v", err)
	}
	if candidate.calls != 4 {
		t.Errorf("candidate evaluated %d inputs across two dry-runs, want 2+2: dry-run records are never replayed", candidate.calls)
	}

	// A dry-run writes no enforcement and audits nothing — even its denials are not audit
	// events: only enforced refusals are (G5).
	if len(rec.events) != 0 {
		t.Errorf("dry-run published %d audit events, want none: %+v", len(rec.events), rec.events)
	}
}

// A range that would exceed its cap is rejected, never silently truncated (SPEC-0030).
func TestDryRunOverCapIsRejected(t *testing.T) {
	pdp := &stubPDP{decision: allowed()}
	svc := newService(pdp, &recorder{})
	svc.WithCandidateLoader(func(_ context.Context, _ string) (api.DecisionPoint, error) {
		return &countingPDP{decision: allowed()}, nil
	})
	for i := 0; i < 3; i++ {
		req := request()
		req.Resource.ID = fmt.Sprintf("repo-%d", i)
		pdp.decision.DecisionID = fmt.Sprintf("01ENF%04d", i)
		if _, err := svc.Decide(t.Context(), req); err != nil {
			t.Fatalf("Decide: %v", err)
		}
	}
	_, err := svc.EvaluateDryRun(t.Context(), api.DryRunRequest{
		TenantID: "acme", CandidateBundleRef: "candidate", MaxResults: 2,
	})
	if !errors.Is(err, api.ErrInvalidRequest) {
		t.Errorf("over-cap dry-run = %v, want ErrInvalidRequest: a partial result must never look complete", err)
	}
}

// The cap itself is capped: a single dry-run may never ask for more than the hard maximum.
func TestDryRunMaxResultsBeyondHardCapIsRejected(t *testing.T) {
	loaded := false
	svc := newService(&stubPDP{decision: allowed()}, &recorder{})
	svc.WithCandidateLoader(func(_ context.Context, _ string) (api.DecisionPoint, error) {
		loaded = true
		return &countingPDP{}, nil
	})
	_, err := svc.EvaluateDryRun(t.Context(), api.DryRunRequest{
		TenantID: "acme", CandidateBundleRef: "candidate", MaxResults: 1001,
	})
	if !errors.Is(err, api.ErrInvalidRequest) {
		t.Errorf("MaxResults=1001 = %v, want ErrInvalidRequest", err)
	}
	if loaded {
		t.Error("an over-hard-cap request still loaded its candidate bundle")
	}
}

// A plane without a candidate-bundle loader refuses dry-runs outright: results computed from
// anything but the named candidate would be a lie about that candidate.
func TestDryRunWithoutLoaderIsARefusal(t *testing.T) {
	svc := newService(&stubPDP{decision: allowed()}, &recorder{})
	_, err := svc.EvaluateDryRun(t.Context(), api.DryRunRequest{
		TenantID: "acme", CandidateBundleRef: "candidate",
	})
	if !errors.Is(err, api.ErrNoCandidateLoader) {
		t.Errorf("loaderless dry-run = %v, want ErrNoCandidateLoader", err)
	}
}

// A candidate that cannot answer one replayed input refuses the whole operation — never a
// partial dry-run that looks complete.
func TestDryRunCandidateFailureRefusesTheWholeRun(t *testing.T) {
	svc := newService(&stubPDP{decision: allowed()}, &recorder{})
	svc.WithCandidateLoader(func(_ context.Context, _ string) (api.DecisionPoint, error) {
		return &countingPDP{err: errors.New("candidate exploded")}, nil
	})
	if _, err := svc.Decide(t.Context(), request()); err != nil {
		t.Fatalf("Decide: %v", err)
	}
	_, err := svc.EvaluateDryRun(t.Context(), api.DryRunRequest{
		TenantID: "acme", CandidateBundleRef: "candidate",
	})
	if err == nil {
		t.Fatal("a failing candidate produced a dry-run result")
	}
}

// The service satisfies the full port it is injected as: decision point plus provenance.
var _ api.Service = (*Service)(nil)
