// The T-0027 follow-up hook, witnessed at the seam it lives on: decide()
// composing Identity & Access's grant facts into every evidence.pack.read
// decision an auditor principal makes (SPEC-0033 AC7). These tests pin the
// composition contract the merged policy's conjuncts rely on — which facts
// reach the PDP under which key, when the source is read, and how absence
// and failure close — without a policy engine in the room: the PDP is a
// recorder, and the questions it receives ARE the assertion.
package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/gitfrok/backend/modules/audit/api"
	identityapi "github.com/gitfrok/backend/modules/identity/api"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
	platformaudit "github.com/gitfrok/backend/platform/audit"
	"github.com/gitfrok/backend/platform/bus"
)

var factsNow = time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)

// stubPDP records every request it receives and answers as configured.
type stubPDP struct {
	allow    bool
	err      error
	requests []policyapi.Request
}

func (s *stubPDP) Decide(_ context.Context, req policyapi.Request) (policyapi.Decision, error) {
	s.requests = append(s.requests, req)
	return policyapi.Decision{Allowed: s.allow, DecisionID: "decision-stub"}, s.err
}

// stubGrants is the facts source, recording every fresh read.
type stubGrants struct {
	calls    int
	facts    identityapi.GrantDecisionFacts
	ok       bool
	err      error
	lastCtx  context.Context
	lastPack string
}

func (s *stubGrants) GrantFacts(ctx context.Context, auditorPrincipalID, packID string) (identityapi.GrantDecisionFacts, bool, error) {
	s.calls++
	s.lastCtx, s.lastPack = ctx, packID
	return s.facts, s.ok, s.err
}

// The remaining AuditorGrants surface is not on this seam's path; the stubs
// refuse it loudly if the hook ever reaches for more than decision facts.
func (s *stubGrants) IssueGrant(context.Context, identityapi.GrantContext, identityapi.GrantIssue) (identityapi.AuditorGrant, error) {
	panic("the pack-read hook must only read decision facts")
}

func (s *stubGrants) RevokeGrant(context.Context, identityapi.GrantContext, string) (identityapi.AuditorGrant, error) {
	panic("the pack-read hook must only read decision facts")
}

func (s *stubGrants) ListGrants(context.Context, identityapi.GrantContext, string) ([]identityapi.AuditorGrant, error) {
	panic("the pack-read hook must only read decision facts")
}

func (s *stubGrants) GrantTransitions(context.Context, string, time.Time, time.Time, string) ([]identityapi.GrantTransition, error) {
	panic("the pack-read hook must only read decision facts")
}

// stubTrail accepts the generation record and assembles nothing.
type stubTrail struct{ seq int64 }

func (s *stubTrail) Append(_ context.Context, e api.Entry) (api.Record, error) {
	s.seq++
	return api.Record{Seq: s.seq, TenantID: e.TenantID, Action: e.Action, ActorID: e.ActorID,
		Hash: "hash-stub", OccurredAt: e.OccurredAt}, nil
}

func (s *stubTrail) Verify(context.Context) (api.VerifyResult, error) {
	return api.VerifyResult{Checked: s.seq, OK: true}, nil
}

func (s *stubTrail) Query(context.Context, api.TrailQuery) ([]api.Record, bool, error) {
	return nil, false, nil
}

type stubBus struct{}

func (stubBus) Publish(context.Context, bus.Event) error { return nil }
func (stubBus) Subscribe(string, bus.Handler)            {}

// newFixture assembles the service on the recording PDP, ready with one
// READY pack the decisions below ask about. Generation always happens under
// an ALLOWING PDP; a test that wants denials flips pdp.allow after this
// returns.
func newFixture(t *testing.T, pdp *stubPDP, grants identityapi.AuditorGrants) *Service {
	t.Helper()
	pdp.allow = true
	svc := New(pdp, stubBus{}, &stubTrail{}, nil, nil, grants)
	svc.now = func() time.Time { return factsNow }

	owner := api.Context{TenantID: "tenant-a", ActorID: "u-owner", ActorRoles: []string{"owner"}, RequestID: "req-gen"}
	from, to := factsNow.Add(-time.Hour), factsNow.Add(time.Hour)
	packID, _, err := svc.RequestPack(context.Background(), owner, api.PackRequest{RangeFrom: from, RangeTo: to})
	if err != nil {
		t.Fatalf("pack generation under the stub PDP: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		st, err := svc.PackStatus(context.Background(), owner, packID)
		if err != nil {
			t.Fatalf("pack status: %v", err)
		}
		if st.State == api.PackReady {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("pack never became READY under the stub trail")
		}
		time.Sleep(time.Millisecond)
	}
	pdp.requests = nil // forget the owner's decisions; the tests read the auditor's.
	return svc
}

func activeFacts(packID string) identityapi.GrantDecisionFacts {
	return identityapi.GrantDecisionFacts{
		GrantID:   "grant-1",
		State:     identityapi.GrantActive,
		TenantID:  "tenant-a",
		ExpiresAt: factsNow.Add(time.Hour),
		RangeFrom: factsNow.Add(-2 * time.Hour),
		RangeTo:   factsNow.Add(2 * time.Hour),
		Packs:     []string{packID},
	}
}

func auditorCtx(requestID string) api.Context {
	return api.Context{TenantID: "tenant-a", ActorID: "p-auditor", ActorRoles: []string{"auditor"}, RequestID: requestID}
}

// The hook's composition contract: an ACTIVE grant's facts arrive under
// exactly the keys the merged policy's conjuncts read, with the pack's own
// range and the decision instant alongside them.
func TestAuditorPackReadComposesActiveGrantFactsIntoTheDecision(t *testing.T) {
	pdp := &stubPDP{allow: true}
	grants := &stubGrants{}
	svc := newFixture(t, pdp, grants)
	packID := packIDOf(t, svc)

	grants.facts, grants.ok = activeFacts(packID), true
	if _, err := svc.GetPack(context.Background(), auditorCtx("req-read-1"), packID); err != nil {
		t.Fatalf("an ACTIVE grant's read must be allowed, got %v", err)
	}
	if grants.calls != 1 || grants.lastPack != packID {
		t.Fatalf("facts read = calls=%d pack=%q, want one fresh read of %q", grants.calls, grants.lastPack, packID)
	}

	req := pdp.requests[len(pdp.requests)-1]
	if req.Action != platformaudit.ActionEvidencePackRead || req.Resource.Type != "evidence_pack" || req.Resource.ID != packID {
		t.Fatalf("decision asked = %+v", req)
	}
	want := map[string]string{
		"auditor_grant_id":         "grant-1",
		"auditor_grant_state":      "ACTIVE",
		"auditor_grant_tenant":     "tenant-a",
		"auditor_grant_expires_at": factsNow.Add(time.Hour).UTC().Format(time.RFC3339Nano),
		"auditor_grant_range_from": factsNow.Add(-2 * time.Hour).UTC().Format(time.RFC3339Nano),
		"auditor_grant_range_to":   factsNow.Add(2 * time.Hour).UTC().Format(time.RFC3339Nano),
		"auditor_grant_packs":      packID,
		"decision_time":            factsNow.UTC().Format(time.RFC3339Nano),
	}
	for k, v := range want {
		if req.Context[k] != v {
			t.Errorf("context[%q] = %q, want %q", k, req.Context[k], v)
		}
	}
	// The pack's own bounds travel under the range keys the policy compares.
	if req.Context["pack_range_from"] != req.Context["range_from"] || req.Context["pack_range_to"] != req.Context["range_to"] ||
		req.Context["pack_range_from"] == "" {
		t.Errorf("pack range facts = from=%q to=%q, want the pack's own bounds", req.Context["pack_range_from"], req.Context["pack_range_to"])
	}
}

// REVOKED and EXPIRED states are facts the hook passes through unaltered —
// the policy's conjuncts deny on them; the hook must never filter, rewrite
// or short-circuit them away from the decision.
func TestAuditorPackReadPassesRevokedAndExpiredStatesThrough(t *testing.T) {
	for _, state := range []identityapi.GrantState{identityapi.GrantRevoked, identityapi.GrantExpired} {
		t.Run(string(state), func(t *testing.T) {
			pdp := &stubPDP{} // the policy denies; the stub mirrors it
			grants := &stubGrants{}
			svc := newFixture(t, pdp, grants)
			pdp.allow = false
			packID := packIDOf(t, svc)

			grants.facts, grants.ok = activeFacts(packID), true
			grants.facts.State = state
			if _, err := svc.GetPack(context.Background(), auditorCtx("req-read-2"), packID); !errors.Is(err, api.ErrPackUnavailable) {
				t.Fatalf("a %s grant's read must be the coarse denial, got %v", state, err)
			}
			req := pdp.requests[len(pdp.requests)-1]
			if req.Context["auditor_grant_state"] != string(state) {
				t.Fatalf("the %s state must reach the decision unaltered, got %q", state, req.Context["auditor_grant_state"])
			}
		})
	}
}

// A factless principal still reaches the PDP — no facts, no grant keys — so
// deny-by-default denies and the denial is recorded by the policy surface.
func TestFactlessAuditorStillReachesThePDPWithoutGrantFacts(t *testing.T) {
	pdp := &stubPDP{} // deny-by-default: the stub mirrors the policy
	grants := &stubGrants{ok: false}
	svc := newFixture(t, pdp, grants)
	pdp.allow = false
	packID := packIDOf(t, svc)

	if _, err := svc.GetPack(context.Background(), auditorCtx("req-read-3"), packID); !errors.Is(err, api.ErrPackUnavailable) {
		t.Fatalf("a factless auditor must be denied, got %v", err)
	}
	if len(pdp.requests) != 1 {
		t.Fatalf("the factless decision must still be asked of the PDP, got %d requests", len(pdp.requests))
	}
	for k := range pdp.requests[0].Context {
		if len(k) > len("auditor_grant") && k[:len("auditor_grant")] == "auditor_grant" {
			t.Fatalf("a factless decision must carry no grant facts, found %q", k)
		}
	}
}

// Fail-closed: a failing facts source refuses the decision before the PDP is
// ever asked — no decision is fabricated from absent facts.
func TestAuditorPackReadFailsClosedWhenTheFactsSourceErrors(t *testing.T) {
	pdp := &stubPDP{allow: true} // even a permissive PDP must never be reached
	grants := &stubGrants{err: errors.New("identity surface down")}
	svc := newFixture(t, pdp, grants)
	packID := packIDOf(t, svc)

	if _, err := svc.GetPack(context.Background(), auditorCtx("req-read-4"), packID); !errors.Is(err, api.ErrPackUnavailable) {
		t.Fatalf("a failing facts source must refuse, got %v", err)
	}
	if len(pdp.requests) != 0 {
		t.Fatalf("the PDP must not be asked when the facts source fails, got %d requests", len(pdp.requests))
	}
}

// Fail-closed: a plane composing no grants surface has no facts an auditor
// can read under, so every auditor pack read is the coarse denial.
func TestAuditorPackReadFailsClosedWithoutAGrantsSurface(t *testing.T) {
	pdp := &stubPDP{allow: true}
	svc := newFixture(t, pdp, nil)
	packID := packIDOf(t, svc)

	if _, err := svc.GetPack(context.Background(), auditorCtx("req-read-5"), packID); !errors.Is(err, api.ErrPackUnavailable) {
		t.Fatalf("no grants surface must refuse auditor reads, got %v", err)
	}
	if len(pdp.requests) != 0 {
		t.Fatalf("the PDP must not be asked when no grants surface exists, got %d requests", len(pdp.requests))
	}
}

// Member principals are untouched by the hook: no facts read, no grant keys,
// the role-table decision exactly as before T-0027.
func TestMemberPackReadIsUnaffectedByTheFactsHook(t *testing.T) {
	pdp := &stubPDP{allow: true}
	grants := &stubGrants{}
	svc := newFixture(t, pdp, grants)
	packID := packIDOf(t, svc)

	member := api.Context{TenantID: "tenant-a", ActorID: "u-member", ActorRoles: []string{"member"}, RequestID: "req-member"}
	if _, err := svc.GetPack(context.Background(), member, packID); err != nil {
		t.Fatalf("a member's read must be unaffected, got %v", err)
	}
	if grants.calls != 0 {
		t.Fatalf("the hook must never read facts for a member principal, got %d reads", grants.calls)
	}
	for k := range pdp.requests[len(pdp.requests)-1].Context {
		if len(k) > len("auditor_grant") && k[:len("auditor_grant")] == "auditor_grant" {
			t.Fatalf("a member's decision must carry no grant facts, found %q", k)
		}
	}
}

// Freshness (SPEC-0033 AC7): every decision request reads the facts again —
// a second read after revocation composes the REVOKED facts, not a memory of
// the first decision's ACTIVE ones.
func TestGrantFactsAreReadFreshOnEveryDecision(t *testing.T) {
	pdp := &stubPDP{allow: true}
	grants := &stubGrants{}
	svc := newFixture(t, pdp, grants)
	packID := packIDOf(t, svc)

	grants.facts, grants.ok = activeFacts(packID), true
	if _, err := svc.GetPack(context.Background(), auditorCtx("req-read-6"), packID); err != nil {
		t.Fatalf("first read under ACTIVE facts: %v", err)
	}
	// The grant is revoked; the facts source now answers with the new state.
	grants.facts.State = identityapi.GrantRevoked
	pdp.allow = false
	if _, err := svc.GetPack(context.Background(), auditorCtx("req-read-7"), packID); !errors.Is(err, api.ErrPackUnavailable) {
		t.Fatalf("the second read must compose the REVOKED facts fresh, got %v", err)
	}
	if grants.calls != 2 {
		t.Fatalf("facts reads = %d, want one per decision — caching is the bug SPEC-0033 AC7 forbids", grants.calls)
	}
	if got := pdp.requests[len(pdp.requests)-1].Context["auditor_grant_state"]; got != "REVOKED" {
		t.Fatalf("the second decision saw state %q, want the fresh REVOKED fact", got)
	}
}

// packIDOf returns the one pack the fixture generated.
func packIDOf(t *testing.T, svc *Service) string {
	t.Helper()
	svc.mu.Lock()
	defer svc.mu.Unlock()
	for id := range svc.packs {
		return id
	}
	t.Fatal("fixture holds no pack")
	return ""
}
