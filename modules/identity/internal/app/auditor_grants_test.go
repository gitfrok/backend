package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gitfrok/backend/modules/identity/api"
	"github.com/gitfrok/backend/modules/identity/internal/adapters/memory"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
	"github.com/gitfrok/backend/platform/bus"
	"github.com/gitfrok/backend/platform/tenancy"
)

// SPEC-0033 acceptance tests for the grant lifecycle service, over the
// in-memory store with a controllable clock: issuing, revoking and expiry
// recognition must each be a PDP decision followed by exactly one immutable
// audit record, one witnessed transition and one bus event.

// --- fakes -----------------------------------------------------------------

type fakePDP struct {
	decision policyapi.Decision
	err      error
	requests []policyapi.Request
}

func (p *fakePDP) Decide(_ context.Context, req policyapi.Request) (policyapi.Decision, error) {
	p.requests = append(p.requests, req)
	return p.decision, p.err
}

type fakeTrail struct {
	records []api.GrantWitnessEntry
	fail    bool
}

func (l *fakeTrail) AppendGrantRecord(_ context.Context, e api.GrantWitnessEntry) (api.GrantWitnessRecord, error) {
	if l.fail {
		return api.GrantWitnessRecord{}, errors.New("witness unavailable")
	}
	l.records = append(l.records, e)
	return api.GrantWitnessRecord{
		Seq:  int64(len(l.records)),
		Hash: fmt.Sprintf("hash-%d", len(l.records)),
	}, nil
}

type recordingBus struct{ events []bus.Event }

func (b *recordingBus) Publish(_ context.Context, e bus.Event) error {
	b.events = append(b.events, e)
	return nil
}

func (b *recordingBus) Subscribe(string, bus.Handler) {}

// --- fixtures ---------------------------------------------------------------

var testNow = time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)

type fixture struct {
	service *Service
	pdp     *fakePDP
	trail   *fakeTrail
	events  *recordingBus
	store   *memory.GrantStore
	clock   *time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	pdp := &fakePDP{decision: policyapi.Decision{Allowed: true, DecisionID: "dec-1"}}
	trail := &fakeTrail{}
	events := &recordingBus{}
	store := memory.NewGrantStore()
	clock := testNow
	svc := New(pdp, events, trail, store)
	svc.now = func() time.Time { return clock }
	return &fixture{service: svc, pdp: pdp, trail: trail, events: events, store: store, clock: &clock}
}

func ownerCtx(tenant, actor string) context.Context {
	return api.WithPrincipal(tenancy.WithTenant(context.Background(), tenancy.ID(tenant)),
		api.Principal{TenantID: tenant, ActorID: actor, Roles: []string{"owner"}})
}

func validIssue() api.GrantIssue {
	return api.GrantIssue{
		AuditorPrincipalID: "auditor-1",
		RangeFrom:          testNow.Add(-72 * time.Hour),
		RangeTo:            testNow.Add(-time.Hour),
		PackIDs:            []string{"pack-1"},
		ExpiresAt:          testNow.Add(time.Hour),
	}
}

// --- issue ------------------------------------------------------------------

func TestIssueGrantAuthorizesAuditsAndWitnesses(t *testing.T) {
	f := newFixture(t)
	grant, err := f.service.IssueGrant(ownerCtx("tenant-a", "admin-a"),
		api.GrantContext{RequestID: "req-1"}, validIssue())
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if grant.GrantID == "" || grant.TenantID != "tenant-a" || grant.State != api.GrantActive {
		t.Fatalf("grant = %+v, want server-assigned ID, tenant scope and ACTIVE state", grant)
	}
	if grant.GrantedBy != "admin-a" {
		t.Fatalf("GrantedBy = %q, want the acting admin", grant.GrantedBy)
	}

	// The decision must be auditor.grant.manage asked about the TENANT, with
	// the scope as server-derived context (governance/policies vocabulary).
	if len(f.pdp.requests) != 1 {
		t.Fatalf("PDP requests = %d, want 1", len(f.pdp.requests))
	}
	req := f.pdp.requests[0]
	if req.Action != "auditor.grant.manage" || req.Resource.Type != "tenant" || req.Resource.ID != "tenant-a" {
		t.Fatalf("PDP request = %+v, want auditor.grant.manage about tenant-a", req)
	}
	if req.Context["pack_ids"] != "pack-1" || req.Context["auditor_principal_id"] != "auditor-1" {
		t.Fatalf("PDP context = %v, want the grant scope", req.Context)
	}

	// AC4: exactly one immutable audit record naming the granting admin and
	// the auditor principal, first-party provenance.
	if len(f.trail.records) != 1 {
		t.Fatalf("trail records = %d, want 1", len(f.trail.records))
	}
	entry := f.trail.records[0]
	if entry.Action != "identity.auditor_grant.issued" || entry.ActorID != "admin-a" {
		t.Fatalf("audit entry = %+v", entry)
	}
	if entry.Detail["auditor_principal_id"] != "auditor-1" || entry.Detail["granted_by"] != "admin-a" {
		t.Fatalf("audit detail = %v, want the AC4 pairing named", entry.Detail)
	}
	if entry.Resource != "auditor_grant/"+grant.GrantID {
		t.Fatalf("audit resource = %q, want auditor_grant/<grant>", entry.Resource)
	}

	// The ISSUED transition cites the chain position of that record.
	transitions, err := f.service.GrantTransitions(ownerCtx("tenant-a", "admin-a"), "tenant-a", time.Time{}, time.Time{}, "")
	if err != nil {
		t.Fatalf("transitions: %v", err)
	}
	if len(transitions) != 1 || transitions[0].Kind != api.GrantIssued ||
		transitions[0].ChainSeq != 1 || transitions[0].RecordHash != "hash-1" ||
		transitions[0].ActorID != "admin-a" || transitions[0].DecisionID != "dec-1" {
		t.Fatalf("transitions = %+v", transitions)
	}

	// The lifecycle is announced on the bus under the contracts event name.
	if len(f.events.events) != 1 || f.events.events[0].EventName() != api.EventAuditorGrantIssued {
		t.Fatalf("events = %v, want one %s", f.events.events, api.EventAuditorGrantIssued)
	}
}

func TestIssueGrantDenialIsTheOneCoarseShape(t *testing.T) {
	for name, setup := range map[string]func(*fixture){
		"PDP denies":      func(f *fixture) { f.pdp.decision.Allowed = false },
		"PDP unreachable": func(f *fixture) { f.pdp.err = errors.New("down") },
		"malformed scope": func(f *fixture) {},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			setup(f)
			req := validIssue()
			if name == "malformed scope" {
				req.ExpiresAt = time.Time{}
			}
			_, err := f.service.IssueGrant(ownerCtx("tenant-a", "admin-a"), api.GrantContext{RequestID: "req-1"}, req)
			if !errors.Is(err, api.ErrGrantUnavailable) {
				t.Fatalf("error = %v, want %v", err, api.ErrGrantUnavailable)
			}
			if len(f.trail.records) != 0 || len(f.events.events) != 0 {
				t.Fatalf("a refused issue audited %d records and published %d events", len(f.trail.records), len(f.events.events))
			}
		})
	}
}

func TestIssueGrantReplaysIdempotently(t *testing.T) {
	f := newFixture(t)
	first, err := f.service.IssueGrant(ownerCtx("tenant-a", "admin-a"), api.GrantContext{RequestID: "req-1"}, validIssue())
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	replayed, err := f.service.IssueGrant(ownerCtx("tenant-a", "admin-a"), api.GrantContext{RequestID: "req-1"}, validIssue())
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if replayed.GrantID != first.GrantID {
		t.Fatalf("replay issued a second grant %q, want %q", replayed.GrantID, first.GrantID)
	}
	if len(f.pdp.requests) != 1 || len(f.trail.records) != 1 || len(f.events.events) != 1 {
		t.Fatalf("replay re-authorized/audited/announced: pdp=%d trail=%d events=%d",
			len(f.pdp.requests), len(f.trail.records), len(f.events.events))
	}
	// A different request ID under the same tenant is a distinct grant.
	other, err := f.service.IssueGrant(ownerCtx("tenant-a", "admin-a"), api.GrantContext{RequestID: "req-2"}, validIssue())
	if err != nil || other.GrantID == first.GrantID {
		t.Fatalf("second request ID should issue a distinct grant: %v %q", err, other.GrantID)
	}
}

func TestIssueGrantWithoutAuditTrailIsRefused(t *testing.T) {
	f := newFixture(t)
	f.trail.fail = true
	if _, err := f.service.IssueGrant(ownerCtx("tenant-a", "admin-a"), api.GrantContext{RequestID: "req-1"}, validIssue()); !errors.Is(err, api.ErrGrantUnavailable) {
		t.Fatalf("error = %v, want %v — an unrecorded grant is worse than a refused one", err, api.ErrGrantUnavailable)
	}
	// M9: the chain never states the grant was issued — no audit record, no
	// ISSUED transition, no event. The store row that holds the request-ID
	// slot is stored but NOT issued.
	if len(f.trail.records) != 0 || len(f.events.events) != 0 {
		t.Fatalf("an unaudited issue witnessed %d records and %d events", len(f.trail.records), len(f.events.events))
	}
	transitions, _ := f.store.Transitions(context.Background(), "tenant-a", time.Time{}, time.Time{}, "")
	if len(transitions) != 0 {
		t.Fatalf("an unaudited issue recorded transitions: %+v", transitions)
	}
	// And the unissued row must never authorize: facts are absent and the
	// grant never lists.
	if _, ok, err := f.service.GrantFacts(tenancy.WithTenant(context.Background(), "tenant-a"), "auditor-1", "pack-1"); err != nil || ok {
		t.Fatalf("an unissued row served facts: ok=%v err=%v", ok, err)
	}
	if listed, _ := f.service.ListGrants(ownerCtx("tenant-a", "admin-a"), api.GrantContext{}, ""); len(listed) != 0 {
		t.Fatalf("an unissued row listed: %+v", listed)
	}

	// A retry with the same request ID completes the leftover row — exactly
	// one grant, exactly one issued record, never a second grant.
	f.trail.fail = false
	completed, err := f.service.IssueGrant(ownerCtx("tenant-a", "admin-a"), api.GrantContext{RequestID: "req-1"}, validIssue())
	if err != nil {
		t.Fatalf("retry after healing: %v", err)
	}
	if len(f.trail.records) != 1 || len(f.events.events) != 1 {
		t.Fatalf("completion issued %d records and %d events, want one each", len(f.trail.records), len(f.events.events))
	}
	grants, _ := f.store.List(context.Background(), "tenant-a", "")
	if len(grants) != 1 || grants[0].GrantID != completed.GrantID {
		t.Fatalf("store rows = %+v, want exactly the completed grant", grants)
	}
}

// failingInsertStore lets a test fail the durable insert: the M9 guarantee
// is that a failed insert leaves no immutable auditor.grant.issued record.
type failingInsertStore struct {
	*memory.GrantStore
	fail bool
}

func (s *failingInsertStore) Insert(ctx context.Context, g api.AuditorGrant, requestID string) error {
	if s.fail {
		return errors.New("store unavailable")
	}
	return s.GrantStore.Insert(ctx, g, requestID)
}

func TestFailedInsertLeavesNoIssuedRecord(t *testing.T) {
	pdp := &fakePDP{decision: policyapi.Decision{Allowed: true, DecisionID: "dec-1"}}
	trail := &fakeTrail{}
	events := &recordingBus{}
	store := &failingInsertStore{GrantStore: memory.NewGrantStore(), fail: true}
	svc := New(pdp, events, trail, store)
	svc.now = func() time.Time { return testNow }

	if _, err := svc.IssueGrant(ownerCtx("tenant-a", "admin-a"), api.GrantContext{RequestID: "req-1"}, validIssue()); !errors.Is(err, api.ErrGrantUnavailable) {
		t.Fatalf("error = %v, want %v", err, api.ErrGrantUnavailable)
	}
	if len(trail.records) != 0 || len(events.events) != 0 {
		t.Fatalf("a failed insert left %d audit records and %d events", len(trail.records), len(events.events))
	}
	if transitions, _ := store.Transitions(context.Background(), "tenant-a", time.Time{}, time.Time{}, ""); len(transitions) != 0 {
		t.Fatalf("a failed insert recorded transitions: %+v", transitions)
	}
	if grants, _ := store.List(context.Background(), "tenant-a", ""); len(grants) != 0 {
		t.Fatalf("a failed insert stored %d grants", len(grants))
	}

	// Once the store heals, the same request ID issues cleanly — and the
	// chain then shows exactly one issued record for it.
	store.fail = false
	if _, err := svc.IssueGrant(ownerCtx("tenant-a", "admin-a"), api.GrantContext{RequestID: "req-1"}, validIssue()); err != nil {
		t.Fatalf("issue after healing: %v", err)
	}
	if len(trail.records) != 1 || len(events.events) != 1 {
		t.Fatalf("healed issue witnessed %d records and %d events, want one each", len(trail.records), len(events.events))
	}
}

// Concurrent duplicates of one request ID serialize on one reservation: one
// decision, one audit record, one grant — every caller sees the same grant.
func TestConcurrentDuplicateIssueSerializesOnOneReservation(t *testing.T) {
	f := newFixture(t)
	const n = 8
	grants := make([]api.AuditorGrant, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			grants[i], errs[i] = f.service.IssueGrant(ownerCtx("tenant-a", "admin-a"),
				api.GrantContext{RequestID: "req-race"}, validIssue())
		}(i)
	}
	wg.Wait()
	for i := 0; i < n; i++ {
		if errs[i] != nil || grants[i].GrantID != grants[0].GrantID || grants[0].GrantID == "" {
			t.Fatalf("caller %d saw grant %q err %v, want the one shared grant", i, grants[i].GrantID, errs[i])
		}
	}
	if len(f.pdp.requests) != 1 || len(f.trail.records) != 1 || len(f.events.events) != 1 {
		t.Fatalf("concurrent duplicates decided/audited/announced more than once: pdp=%d trail=%d events=%d",
			len(f.pdp.requests), len(f.trail.records), len(f.events.events))
	}
}

func TestLifecycleRequiresVerifiedTenantAndPrincipal(t *testing.T) {
	f := newFixture(t)
	if _, err := f.service.IssueGrant(context.Background(), api.GrantContext{}, validIssue()); err == nil {
		t.Fatal("issue without a tenant context succeeded")
	}
	if _, err := f.service.IssueGrant(tenancy.WithTenant(context.Background(), "tenant-a"), api.GrantContext{}, validIssue()); err == nil {
		t.Fatal("issue without a principal succeeded")
	}
	if _, err := f.service.IssueGrant(
		api.WithPrincipal(tenancy.WithTenant(context.Background(), "tenant-a"), api.Principal{TenantID: "tenant-b", ActorID: "a"}),
		api.GrantContext{}, validIssue()); err == nil {
		t.Fatal("issue with a cross-tenant principal succeeded")
	}
	if len(f.pdp.requests) != 0 {
		t.Fatal("an unverified request reached the PDP")
	}
}

// --- revoke -----------------------------------------------------------------

func TestRevokeGrantAuditsAndTakesEffectImmediately(t *testing.T) {
	f := newFixture(t)
	grant, err := f.service.IssueGrant(ownerCtx("tenant-a", "admin-a"), api.GrantContext{RequestID: "req-1"}, validIssue())
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	revoked, err := f.service.RevokeGrant(ownerCtx("tenant-a", "admin-b"), api.GrantContext{RequestID: "req-2"}, grant.GrantID)
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if revoked.State != api.GrantRevoked || revoked.RevokedAt.IsZero() {
		t.Fatalf("revoked grant = %+v, want REVOKED with a revocation instant", revoked)
	}

	// AC4: the revocation record names the revoking admin AND the issuing
	// admin AND the auditor principal.
	if len(f.trail.records) != 2 {
		t.Fatalf("trail records = %d, want 2", len(f.trail.records))
	}
	entry := f.trail.records[1]
	if entry.Action != "identity.auditor_grant.revoked" || entry.ActorID != "admin-b" {
		t.Fatalf("revoke audit entry = %+v", entry)
	}
	if entry.Detail["granted_by"] != "admin-a" || entry.Detail["auditor_principal_id"] != "auditor-1" {
		t.Fatalf("revoke audit detail = %v, want the full AC4 naming", entry.Detail)
	}

	// The decision-time facts now answer REVOKED — that is the immediacy AC7
	// requires: there is no cached decision to outlive the revocation.
	facts, ok, err := f.service.GrantFacts(tenancy.WithTenant(context.Background(), "tenant-a"), "auditor-1", "pack-1")
	if err != nil || !ok {
		t.Fatalf("facts: %v ok=%v", err, ok)
	}
	if facts.State != api.GrantRevoked {
		t.Fatalf("facts state = %s, want REVOKED", facts.State)
	}
}

func TestRevokeGrantCoarseDenials(t *testing.T) {
	f := newFixture(t)
	grant, err := f.service.IssueGrant(ownerCtx("tenant-a", "admin-a"), api.GrantContext{RequestID: "req-1"}, validIssue())
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	for name, call := range map[string]func() error{
		"nonexistent grant": func() error {
			_, err := f.service.RevokeGrant(ownerCtx("tenant-a", "admin-a"), api.GrantContext{}, "missing")
			return err
		},
		"empty grant ID": func() error {
			_, err := f.service.RevokeGrant(ownerCtx("tenant-a", "admin-a"), api.GrantContext{}, "")
			return err
		},
		"cross-tenant grant": func() error {
			_, err := f.service.RevokeGrant(ownerCtx("tenant-b", "admin-b"), api.GrantContext{}, grant.GrantID)
			return err
		},
		"already revoked": func() error {
			if _, err := f.service.RevokeGrant(ownerCtx("tenant-a", "admin-a"), api.GrantContext{}, grant.GrantID); err != nil {
				return err
			}
			_, err := f.service.RevokeGrant(ownerCtx("tenant-a", "admin-a"), api.GrantContext{}, grant.GrantID)
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := call(); !errors.Is(err, api.ErrGrantUnavailable) {
				t.Fatalf("error = %v, want %v", err, api.ErrGrantUnavailable)
			}
		})
	}
}

// --- expiry -----------------------------------------------------------------

func TestExpiryIsRecognizedWithoutOperatorAction(t *testing.T) {
	f := newFixture(t)
	grant, err := f.service.IssueGrant(ownerCtx("tenant-a", "admin-a"), api.GrantContext{RequestID: "req-1"}, validIssue())
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	// The clock passes the expiry; no operator acts.
	*f.clock = grant.ExpiresAt.Add(time.Second)

	listed, err := f.service.ListGrants(ownerCtx("tenant-a", "admin-a"), api.GrantContext{}, "")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(listed) != 1 || listed[0].State != api.GrantExpired {
		t.Fatalf("listed = %+v, want one EXPIRED grant", listed)
	}

	// The expiry was witnessed exactly once: one audit record with NO actor
	// (the platform itself expired it), one transition, one event.
	if len(f.trail.records) != 2 {
		t.Fatalf("trail records = %d, want 2", len(f.trail.records))
	}
	entry := f.trail.records[1]
	if entry.Action != "identity.auditor_grant.expired" || entry.ActorID != "" {
		t.Fatalf("expiry audit entry = %+v, want no actor", entry)
	}
	if entry.Detail["granted_by"] != "admin-a" || entry.Detail["auditor_principal_id"] != "auditor-1" {
		t.Fatalf("expiry audit detail = %v, want the AC4 pairing still named", entry.Detail)
	}

	// A second read recognizes nothing new.
	if _, err := f.service.ListGrants(ownerCtx("tenant-a", "admin-a"), api.GrantContext{}, ""); err != nil {
		t.Fatalf("second list: %v", err)
	}
	if len(f.trail.records) != 2 || len(f.events.events) != 2 {
		t.Fatalf("expiry witnessed twice: trail=%d events=%d", len(f.trail.records), len(f.events.events))
	}
	if f.events.events[1].EventName() != api.EventAuditorGrantExpired {
		t.Fatalf("second event = %s, want %s", f.events.events[1].EventName(), api.EventAuditorGrantExpired)
	}
}

// --- facts & transitions ----------------------------------------------------

func TestGrantFactsPreferAnActiveGrantAndFailClosedOnAbsence(t *testing.T) {
	f := newFixture(t)
	_, err := f.service.IssueGrant(ownerCtx("tenant-a", "admin-a"), api.GrantContext{RequestID: "req-1"}, validIssue())
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	ctx := tenancy.WithTenant(context.Background(), "tenant-a")

	facts, ok, err := f.service.GrantFacts(ctx, "auditor-1", "pack-1")
	if err != nil || !ok {
		t.Fatalf("facts: %v ok=%v", err, ok)
	}
	if facts.State != api.GrantActive || facts.TenantID != "tenant-a" || len(facts.Packs) != 1 || facts.Packs[0] != "pack-1" {
		t.Fatalf("facts = %+v", facts)
	}

	// A pack the grant does not name yields absent facts — the decision fails
	// closed on absence (SPEC-0033).
	if _, ok, err := f.service.GrantFacts(ctx, "auditor-1", "pack-2"); err != nil || ok {
		t.Fatalf("unnamed pack facts = ok=%v err=%v, want absent", ok, err)
	}
	// Another tenant never sees the grant.
	if _, ok, err := f.service.GrantFacts(tenancy.WithTenant(context.Background(), "tenant-b"), "auditor-1", "pack-1"); err != nil || ok {
		t.Fatalf("cross-tenant facts = ok=%v err=%v, want absent", ok, err)
	}
}

// SPEC-0033 AC1/AC8 (L16): the grant's repository scope travels with the
// facts so the policy CAN compare a grant's scope against the pack's. The
// reviewed rego bundle does not consume the fact yet — wiring a rule is a
// governance-first contract change — but the fact itself must be complete.
func TestGrantFactsCarryTheRepositoryScope(t *testing.T) {
	f := newFixture(t)
	req := validIssue()
	req.RepositoryID = "repo-7"
	if _, err := f.service.IssueGrant(ownerCtx("tenant-a", "admin-a"), api.GrantContext{RequestID: "req-1"}, req); err != nil {
		t.Fatalf("issue: %v", err)
	}
	facts, ok, err := f.service.GrantFacts(tenancy.WithTenant(context.Background(), "tenant-a"), "auditor-1", "pack-1")
	if err != nil || !ok {
		t.Fatalf("facts: %v ok=%v", err, ok)
	}
	if facts.RepositoryID != "repo-7" {
		t.Fatalf("facts.RepositoryID = %q, want the grant's issued scope", facts.RepositoryID)
	}

	// A tenant-wide grant with the later expiry governs and reports the
	// empty scope as issued.
	req2 := validIssue()
	req2.ExpiresAt = testNow.Add(2 * time.Hour)
	if _, err := f.service.IssueGrant(ownerCtx("tenant-a", "admin-a"), api.GrantContext{RequestID: "req-2"}, req2); err != nil {
		t.Fatalf("issue tenant-wide grant: %v", err)
	}
	facts, ok, err = f.service.GrantFacts(tenancy.WithTenant(context.Background(), "tenant-a"), "auditor-1", "pack-1")
	if err != nil || !ok || facts.RepositoryID != "" {
		t.Fatalf("tenant-wide facts = %+v ok=%v err=%v, want empty repository scope", facts, ok, err)
	}
}

func TestGrantTransitionsScopeByRangeAndRepository(t *testing.T) {
	f := newFixture(t)
	req := validIssue()
	req.RepositoryID = "repo-1"
	if _, err := f.service.IssueGrant(ownerCtx("tenant-a", "admin-a"), api.GrantContext{RequestID: "req-1"}, req); err != nil {
		t.Fatalf("issue repo grant: %v", err)
	}
	*f.clock = testNow.Add(time.Minute)
	req2 := validIssue()
	req2.RepositoryID = "repo-2"
	if _, err := f.service.IssueGrant(ownerCtx("tenant-a", "admin-a"), api.GrantContext{RequestID: "req-2"}, req2); err != nil {
		t.Fatalf("issue second grant: %v", err)
	}
	ctx := ownerCtx("tenant-a", "admin-a")

	// Narrowing by repository keeps that repository's transitions and the
	// tenant-wide grants (empty repository scope covers them all).
	only, err := f.service.GrantTransitions(ctx, "tenant-a", time.Time{}, time.Time{}, "repo-1")
	if err != nil {
		t.Fatalf("transitions: %v", err)
	}
	if len(only) != 1 || only[0].RepositoryID != "repo-1" {
		t.Fatalf("repo-filtered transitions = %+v", only)
	}

	// A tenant mismatch is the same coarse shape as anything else.
	if _, err := f.service.GrantTransitions(ctx, "tenant-b", time.Time{}, time.Time{}, ""); !errors.Is(err, api.ErrGrantUnavailable) {
		t.Fatalf("mismatch error = %v, want %v", err, api.ErrGrantUnavailable)
	}
}

func TestNewRefusesMissingDependencies(t *testing.T) {
	pdp := &fakePDP{}
	trail := &fakeTrail{}
	store := memory.NewGrantStore()
	for name, build := range map[string]func(){
		"no PDP":   func() { New(nil, &recordingBus{}, trail, store) },
		"no trail": func() { New(pdp, &recordingBus{}, nil, store) },
		"no store": func() { New(pdp, &recordingBus{}, trail, nil) },
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("New accepted a missing dependency")
				}
			}()
			build()
		})
	}
}

// The context vocabulary the PDP sees must stay the vocabulary the merged
// Rego reviews: no field the policy does not know about.
func TestDecisionContextVocabulary(t *testing.T) {
	f := newFixture(t)
	if _, err := f.service.IssueGrant(ownerCtx("tenant-a", "admin-a"), api.GrantContext{RequestID: "req-1"}, validIssue()); err != nil {
		t.Fatalf("issue: %v", err)
	}
	allowed := map[string]bool{
		"request_id": true, "auditor_principal_id": true, "range_from": true,
		"range_to": true, "repository_id": true, "pack_ids": true, "expires_at": true,
	}
	for key := range f.pdp.requests[0].Context {
		if !allowed[key] {
			t.Fatalf("decision context key %q is not in the reviewed vocabulary", key)
		}
	}
	if !strings.Contains(f.pdp.requests[0].Context["range_from"], "2026-08-11") {
		t.Fatalf("range_from not RFC3339: %q", f.pdp.requests[0].Context["range_from"])
	}
}
