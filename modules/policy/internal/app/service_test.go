package app

import (
	"context"
	"errors"
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
	s := New(pdp, b)
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
			if got != tc.want {
				t.Errorf("Decide() = %+v, want %+v", got, tc.want)
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

// The service satisfies the port it is injected as.
var _ api.DecisionPoint = (*Service)(nil)
