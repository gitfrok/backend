// Package app tests drive the residency service against SPEC-0040's acceptance criteria:
// server-recorded declarations (AC1), witnessed refusals with both placements (AC2),
// visible contradiction state (AC3), declaration changes with effective times (AC6), and
// coarse, tenant-isolated denials (SPEC-0001, AC8's store half).
package app

import (
	"context"
	"errors"
	"testing"
	"time"

	policyapi "github.com/gitfrok/backend/modules/policy/api"
	"github.com/gitfrok/backend/modules/residency/api"
	"github.com/gitfrok/backend/modules/residency/internal/adapters/memory"
	platformaudit "github.com/gitfrok/backend/platform/audit"
	"github.com/gitfrok/backend/platform/tenancy"
)

// fakeWitness captures every entry the service asks to persist, assigning chain positions
// in append order — the composition root's trail adapter does the same for real.
type fakeWitness struct {
	entries []api.WitnessEntry
	seq     int64
	err     error
}

func (w *fakeWitness) AppendResidencyRecord(_ context.Context, e api.WitnessEntry) (api.WitnessRecord, error) {
	if w.err != nil {
		return api.WitnessRecord{}, w.err
	}
	w.seq++
	w.entries = append(w.entries, e)
	return api.WitnessRecord{Seq: w.seq, Hash: "hash-" + e.Action}, nil
}

// fakePDP answers every decision the same way and records the request it was asked.
type fakePDP struct {
	allow bool
	err   error
	got   policyapi.Request
}

func (p *fakePDP) Decide(_ context.Context, req policyapi.Request) (policyapi.Decision, error) {
	p.got = req
	if p.err != nil {
		return policyapi.Decision{}, p.err
	}
	return policyapi.Decision{Allowed: p.allow, DecisionID: "decision-1"}, nil
}

type fixture struct {
	svc     *Service
	pdp     *fakePDP
	wit     *fakeWitness
	now     time.Time
	clock   func() time.Time
	advance func(d time.Duration)
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{now: time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)}
	f.clock = func() time.Time { return f.now }
	f.advance = func(d time.Duration) { f.now = f.now.Add(d) }
	f.pdp = &fakePDP{allow: true}
	f.wit = &fakeWitness{}
	f.svc = New(f.pdp, f.wit, memory.New(), api.Config{
		DetectionWindow:   5 * time.Minute,
		MaxReportInterval: 24 * time.Hour,
		Now:               f.clock,
	}, nil)
	return f
}

// scopedCtx is a request context carrying the tenant scope an authenticated caller has.
func scopedCtx(tenantID string) context.Context {
	return tenancy.WithTenant(context.Background(), tenancy.ID(tenantID))
}

// TestDeclareIsServerRecorded is SPEC-0040 AC1: the declaration is control-plane state —
// the effective time is the server's clock, the actor is the decision's subject, and the
// record cites the chain position the witness assigned. The api surface itself admits no
// caller-supplied timestamp: Declare takes cloud and region and nothing else.
func TestDeclareIsServerRecorded(t *testing.T) {
	f := newFixture(t)
	decl, err := f.svc.Declare(scopedCtx("acme"), "acme", "owner-1", []string{"owner"}, "gke", "europe-west1")
	if err != nil {
		t.Fatalf("declare: %v", err)
	}
	if !decl.EffectiveAt.Equal(f.now) {
		t.Fatalf("effective time = %v, want server clock %v", decl.EffectiveAt, f.now)
	}
	if decl.ActorID != "owner-1" || decl.Cloud != "gke" || decl.Region != "europe-west1" {
		t.Fatalf("declaration fields wrong: %+v", decl)
	}
	if decl.ChainSeq != 1 || decl.RecordHash == "" {
		t.Fatalf("declaration must cite its witness record, got %+v", decl)
	}
	if len(f.wit.entries) != 1 {
		t.Fatalf("expected exactly one witnessed record, got %d", len(f.wit.entries))
	}
	e := f.wit.entries[0]
	if e.Action != platformaudit.ActionResidencyDeclarationSet || e.ActorID != "owner-1" || e.Denied {
		t.Fatalf("witness entry wrong: %+v", e)
	}
	if e.Detail[platformaudit.DetailResidencyPinnedCloud] != "gke" ||
		e.Detail[platformaudit.DetailResidencyPinnedRegion] != "europe-west1" {
		t.Fatalf("witness detail must carry the pinned placement: %+v", e.Detail)
	}
	if _, ok := e.Detail[platformaudit.DetailResidencyPreviousCloud]; ok {
		t.Fatalf("a first declaration has no previous pinning: %+v", e.Detail)
	}
	if f.pdp.got.Action != platformaudit.ActionResidencyDeclarationSet ||
		f.pdp.got.Resource.Type != "tenant" || f.pdp.got.Resource.ID != "acme" {
		t.Fatalf("the PDP must be asked residency.declaration.set about the tenant, got %+v", f.pdp.got)
	}
	// The declaration is readable as the one in force.
	got, ok, err := f.svc.Declaration(scopedCtx("acme"), "acme")
	if err != nil || !ok || got != decl {
		t.Fatalf("declaration read = %+v,%v,%v; want the declared one", got, ok, err)
	}
}

// TestDeclareRefusalIsWitnessed is SPEC-0043 AC1: a refused declaration appends exactly
// one immutable audit record — DENIED, naming the verified actor, the attempted pinning
// and the one it would have replaced — for both coarse shapes, a PDP denial and an
// unreachable PDP. Refusals are the more investigation-relevant half (G5); nothing is
// stored.
func TestDeclareRefusalIsWitnessed(t *testing.T) {
	for _, tc := range []struct {
		name string
		pdp  *fakePDP
	}{{"denied", &fakePDP{allow: false}}, {"unreachable", &fakePDP{err: errors.New("opa down")}}} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			// A replacement attempt: the refusal must name the pinning in force it
			// would have replaced, on the same record (SPEC-0043 AC1).
			if _, err := f.svc.Declare(scopedCtx("acme"), "acme", "owner-1", []string{"owner"}, "gke", "europe-west1"); err != nil {
				t.Fatalf("seed declare: %v", err)
			}
			f.advance(time.Hour)
			f.pdp.allow = tc.pdp.allow
			f.pdp.err = tc.pdp.err
			_, err := f.svc.Declare(scopedCtx("acme"), "acme", "member-9", []string{"member"}, "aws", "us-east1")
			if !errors.Is(err, api.ErrResidencyUnavailable) {
				t.Fatalf("err = %v, want the coarse ErrResidencyUnavailable", err)
			}
			if len(f.wit.entries) != 2 {
				t.Fatalf("exactly one record per act: want 2 entries (seed + refusal), got %d", len(f.wit.entries))
			}
			e := f.wit.entries[1]
			if e.Action != platformaudit.ActionResidencyDeclarationSet || !e.Denied || e.ActorID != "member-9" {
				t.Fatalf("the refusal record must be a DENIED declaration naming the actor: %+v", e)
			}
			if e.Resource != "tenant/acme" || !e.OccurredAt.Equal(f.now) {
				t.Fatalf("the refusal record is about the tenant at server time: %+v", e)
			}
			if e.Detail[platformaudit.DetailResidencyPinnedCloud] != "aws" ||
				e.Detail[platformaudit.DetailResidencyPinnedRegion] != "us-east1" ||
				e.Detail[platformaudit.DetailResidencyPreviousCloud] != "gke" ||
				e.Detail[platformaudit.DetailResidencyPreviousRegion] != "europe-west1" {
				t.Fatalf("the refusal record names attempted AND previous pinning: %+v", e.Detail)
			}
			got, ok, err := f.svc.Declaration(scopedCtx("acme"), "acme")
			if err != nil || !ok || got.Cloud != "gke" {
				t.Fatalf("a refused declaration stores nothing: %+v,%v,%v", got, ok, err)
			}
		})
	}
}

// TestDeclareRefusalWithoutPreviousOmitsIt: the first attempt of a tenant that declared
// nothing is refused with the same record shape and no previous keys — absence of a
// declaration is not an error (SPEC-0001).
func TestDeclareRefusalWithoutPreviousOmitsIt(t *testing.T) {
	f := newFixture(t)
	f.pdp.allow = false
	if _, err := f.svc.Declare(scopedCtx("acme"), "acme", "member-9", []string{"member"}, "aws", "us-east1"); !errors.Is(err, api.ErrResidencyUnavailable) {
		t.Fatalf("err = %v, want the coarse denial", err)
	}
	if len(f.wit.entries) != 1 {
		t.Fatalf("want exactly one refusal record, got %d", len(f.wit.entries))
	}
	e := f.wit.entries[0]
	if !e.Denied {
		t.Fatalf("record must be DENIED: %+v", e)
	}
	if _, ok := e.Detail[platformaudit.DetailResidencyPreviousCloud]; ok {
		t.Fatalf("no declaration in force means no previous keys: %+v", e.Detail)
	}
}

// TestDeclareMalformedIsCoarse: empty tenant, actor, cloud or region is the same coarse
// denial as any other failure (SPEC-0001) — nothing to enumerate.
func TestDeclareMalformedIsCoarse(t *testing.T) {
	cases := []struct{ tenant, actor, cloud, region string }{
		{"", "owner-1", "gke", "europe-west1"},
		{"acme", "", "gke", "europe-west1"},
		{"acme", "owner-1", "", "europe-west1"},
		{"acme", "owner-1", "gke", ""},
	}
	for _, tc := range cases {
		f := newFixture(t)
		_, err := f.svc.Declare(scopedCtx(tc.tenant), tc.tenant, tc.actor, []string{"owner"}, tc.cloud, tc.region)
		if !errors.Is(err, api.ErrResidencyUnavailable) {
			t.Fatalf("declare(%+v) err = %v, want coarse denial", tc, err)
		}
	}
}

// TestDeclarationChangeKeepsEffectiveTimes is SPEC-0040 AC6: a change is a second record
// with its own effective time, never a flattening of the first.
func TestDeclarationChangeKeepsEffectiveTimes(t *testing.T) {
	f := newFixture(t)
	first, err := f.svc.Declare(scopedCtx("acme"), "acme", "owner-1", []string{"owner"}, "gke", "europe-west1")
	if err != nil {
		t.Fatalf("first declare: %v", err)
	}
	f.advance(48 * time.Hour)
	second, err := f.svc.Declare(scopedCtx("acme"), "acme", "owner-1", []string{"owner"}, "aws", "eu-central-1")
	if err != nil {
		t.Fatalf("second declare: %v", err)
	}
	if first.EffectiveAt.Equal(second.EffectiveAt) {
		t.Fatal("the change must carry its own effective time, not the first declaration's")
	}
	if !second.EffectiveAt.Equal(f.now) {
		t.Fatalf("change effective time = %v, want %v", second.EffectiveAt, f.now)
	}
	if len(f.wit.entries) != 2 {
		t.Fatalf("both declarations stay on the record: want 2 entries, got %d", len(f.wit.entries))
	}
	if f.wit.entries[0].OccurredAt.Equal(f.wit.entries[1].OccurredAt) {
		t.Fatal("the witnessed change keeps its own time — the pack shows a change, not the current value")
	}
	// SPEC-0043 AC1: the replacement record names previous AND new pinning, so a
	// compliance reader re-derives the change from the one record.
	e := f.wit.entries[1]
	if e.Detail[platformaudit.DetailResidencyPreviousCloud] != "gke" ||
		e.Detail[platformaudit.DetailResidencyPreviousRegion] != "europe-west1" ||
		e.Detail[platformaudit.DetailResidencyPinnedCloud] != "aws" ||
		e.Detail[platformaudit.DetailResidencyPinnedRegion] != "eu-central-1" {
		t.Fatalf("a replacement names previous and new pinning on the one record: %+v", e.Detail)
	}
	got, ok, err := f.svc.Declaration(scopedCtx("acme"), "acme")
	if err != nil || !ok || got.Cloud != "aws" || got.Region != "eu-central-1" {
		t.Fatalf("declaration in force = %+v,%v,%v; want the change", got, ok, err)
	}
}

// TestObservePlacementAdmitted is the observation half of AC4: a placement matching the
// declaration in force is witnessed with BOTH placements — pinned and observed.
func TestObservePlacementAdmitted(t *testing.T) {
	f := newFixture(t)
	if _, err := f.svc.Declare(scopedCtx("acme"), "acme", "owner-1", []string{"owner"}, "gke", "europe-west1"); err != nil {
		t.Fatalf("declare: %v", err)
	}
	if err := f.svc.ObservePlacement(scopedCtx("acme"), "acme", "plane-1", "gke", "europe-west1"); err != nil {
		t.Fatalf("observe matching placement: %v", err)
	}
	e := f.wit.entries[len(f.wit.entries)-1]
	if e.Action != platformaudit.ActionResidencyPlacementObserved || e.Denied {
		t.Fatalf("observation entry wrong: %+v", e)
	}
	if e.Detail[platformaudit.DetailResidencyPinnedCloud] != "gke" ||
		e.Detail[platformaudit.DetailResidencyObservedCloud] != "gke" ||
		e.Detail[platformaudit.DetailResidencyObservedRegion] != "europe-west1" {
		t.Fatalf("an observation carries both placements: %+v", e.Detail)
	}
}

// TestObservePlacementRefusedWithBothPlacements is SPEC-0040 AC2 (and AC1's second half):
// a placement outside the declaration is refused, the refusal is witnessed with the
// declared AND the attempted placement, and the attempt never redefines the declaration.
func TestObservePlacementRefusedWithBothPlacements(t *testing.T) {
	f := newFixture(t)
	decl, err := f.svc.Declare(scopedCtx("acme"), "acme", "owner-1", []string{"owner"}, "gke", "europe-west1")
	if err != nil {
		t.Fatalf("declare: %v", err)
	}
	err = f.svc.ObservePlacement(scopedCtx("acme"), "acme", "plane-1", "aws", "us-east1")
	if !errors.Is(err, api.ErrPlacementRefused) {
		t.Fatalf("err = %v, want ErrPlacementRefused", err)
	}
	e := f.wit.entries[len(f.wit.entries)-1]
	if e.Action != platformaudit.ActionResidencyPlacementRefused || !e.Denied {
		t.Fatalf("the refusal must be witnessed as denied: %+v", e)
	}
	if e.Detail[platformaudit.DetailResidencyPinnedCloud] != "gke" ||
		e.Detail[platformaudit.DetailResidencyPinnedRegion] != "europe-west1" ||
		e.Detail[platformaudit.DetailResidencyObservedCloud] != "aws" ||
		e.Detail[platformaudit.DetailResidencyObservedRegion] != "us-east1" {
		t.Fatalf("the refusal carries declared AND attempted placements: %+v", e.Detail)
	}
	// The attempt is a violation, not a redefinition.
	got, ok, err := f.svc.Declaration(scopedCtx("acme"), "acme")
	if err != nil || !ok || got != decl {
		t.Fatalf("declaration after refused attempt = %+v,%v,%v; want unchanged %+v", got, ok, err, decl)
	}
}

// TestObservePlacementUndeclaredTenant: with no declaration in force, placement is
// unconstrained — observed and recorded, pinned facts empty.
func TestObservePlacementUndeclaredTenant(t *testing.T) {
	f := newFixture(t)
	if err := f.svc.ObservePlacement(scopedCtx("acme"), "acme", "plane-1", "aws", "us-east1"); err != nil {
		t.Fatalf("observe without declaration: %v", err)
	}
	e := f.wit.entries[len(f.wit.entries)-1]
	if e.Action != platformaudit.ActionResidencyPlacementObserved {
		t.Fatalf("entry = %+v, want an admitted observation", e)
	}
	if e.Detail[platformaudit.DetailResidencyPinnedCloud] != "" {
		t.Fatalf("no declaration means no pinned facts: %+v", e.Detail)
	}
}

// TestContradictionAtDeclarationRaisesViolation is SPEC-0040 AC3: a declaration taking
// effect against an already-observed placement raises a visible violation state before
// Declare returns — detection is synchronous, inside any configured detection window, and
// the window is configuration the fixture supplied, not a compiled-in constant.
func TestContradictionAtDeclarationRaisesViolation(t *testing.T) {
	f := newFixture(t)
	if err := f.svc.ObservePlacement(scopedCtx("acme"), "acme", "plane-1", "aws", "us-east1"); err != nil {
		t.Fatalf("observe: %v", err)
	}
	if _, err := f.svc.Declare(scopedCtx("acme"), "acme", "owner-1", []string{"owner"}, "gke", "europe-west1"); err != nil {
		t.Fatalf("declare: %v", err)
	}
	var violation *api.WitnessEntry
	for i := range f.wit.entries {
		if f.wit.entries[i].Action == platformaudit.ActionResidencyPlacementContradiction {
			violation = &f.wit.entries[i]
		}
	}
	if violation == nil {
		t.Fatal("a contradicting observed placement must raise a witnessed violation state")
	}
	if !violation.Denied || violation.Resource != "data_plane/plane-1" {
		t.Fatalf("violation record wrong: %+v", *violation)
	}
	if violation.Detail[platformaudit.DetailResidencyPinnedCloud] != "gke" ||
		violation.Detail[platformaudit.DetailResidencyObservedCloud] != "aws" {
		t.Fatalf("violation carries both placements: %+v", violation.Detail)
	}
}

// TestCrossTenantIsolationIsCoarse is AC8's store half and SPEC-0001: tenant B sees
// nothing of tenant A's residency, and the denial is indistinguishable from an absent
// declaration.
func TestCrossTenantIsolationIsCoarse(t *testing.T) {
	f := newFixture(t)
	if _, err := f.svc.Declare(scopedCtx("acme"), "acme", "owner-1", []string{"owner"}, "gke", "europe-west1"); err != nil {
		t.Fatalf("declare: %v", err)
	}
	if err := f.svc.ObservePlacement(scopedCtx("acme"), "acme", "plane-1", "gke", "europe-west1"); err != nil {
		t.Fatalf("observe: %v", err)
	}
	// Tenant B reads A's declaration under its own scope: the same coarse shape as an
	// undeclared tenant.
	if _, ok, err := f.svc.Declaration(scopedCtx("globex"), "acme"); !errors.Is(err, api.ErrResidencyUnavailable) || ok {
		t.Fatalf("cross-tenant read = %v,%v; want the coarse denial", ok, err)
	}
	// Tenant B's scope admits no observation of A's plane.
	if err := f.svc.ObservePlacement(scopedCtx("globex"), "acme", "plane-1", "gke", "europe-west1"); !errors.Is(err, api.ErrResidencyUnavailable) {
		t.Fatalf("cross-tenant observation = %v, want the coarse denial", err)
	}
	// An undeclared tenant is indistinguishable from a cross-tenant probe.
	if _, ok, err := f.svc.Declaration(scopedCtx("nobody"), "nobody"); err != nil || ok {
		t.Fatalf("absent declaration = %v,%v; want ok=false, no error", ok, err)
	}
}

// TestUnwitnessedActsFailClosed: a witness that cannot take a record fails the whole act —
// an unrecorded declaration or an unrecorded refusal is a worse failure than a refused one.
func TestUnwitnessedActsFailClosed(t *testing.T) {
	f := newFixture(t)
	f.wit.err = errors.New("trail down")
	if _, err := f.svc.Declare(scopedCtx("acme"), "acme", "owner-1", []string{"owner"}, "gke", "europe-west1"); !errors.Is(err, api.ErrResidencyUnavailable) {
		t.Fatalf("declare with dead witness = %v, want coarse failure", err)
	}
	if _, ok, err := f.svc.Declaration(scopedCtx("acme"), "acme"); err != nil || ok {
		t.Fatalf("an unwitnessed declaration stores nothing: ok=%v err=%v", ok, err)
	}
}

// TestEnforcementTieBreaksOnChainSeqForSameInstantReplace is T-0039's hardening through
// the gate: two replacements effective at the SAME service instant resolve to the later
// chain position (DeclarationAt's deterministic tie-break), and the placement enforcement
// consumes exactly that declaration — the replace the trail witnessed last is the one the
// gate enforces first.
func TestEnforcementTieBreaksOnChainSeqForSameInstantReplace(t *testing.T) {
	f := newFixture(t)
	// Two declarations at the one instant — the clock never advances between them.
	if _, err := f.svc.Declare(scopedCtx("acme"), "acme", "owner-1", []string{"owner"}, "gke", "europe-west1"); err != nil {
		t.Fatalf("first declare: %v", err)
	}
	if _, err := f.svc.Declare(scopedCtx("acme"), "acme", "owner-1", []string{"owner"}, "aws", "us-east1"); err != nil {
		t.Fatalf("same-instant replace: %v", err)
	}
	// The later chain position (the aws replace) is in force: its placement admits...
	if err := f.svc.ObservePlacement(scopedCtx("acme"), "acme", "plane-1", "aws", "us-east1"); err != nil {
		t.Fatalf("the replaced-into placement must be admitted: %v", err)
	}
	// ...and the superseded pinning's placement is refused.
	if err := f.svc.ObservePlacement(scopedCtx("acme"), "acme", "plane-2", "gke", "europe-west1"); !errors.Is(err, api.ErrPlacementRefused) {
		t.Fatalf("the superseded pinning's placement = %v, want the witnessed refusal", err)
	}
	got, ok, err := f.svc.Declaration(scopedCtx("acme"), "acme")
	if err != nil || !ok || got.Cloud != "aws" || got.ChainSeq != 2 {
		t.Fatalf("the read path tie-breaks the same way: %+v (ok %v, err %v), want aws at chain seq 2", got, ok, err)
	}
}

// failStore is a residency store whose every path fails — the composition's shape for a
// durable store that is down.
type failStore struct{ err error }

func (s failStore) PutDeclaration(context.Context, api.Declaration) error { return s.err }
func (s failStore) DeclarationAt(context.Context, string, time.Time) (api.Declaration, bool, error) {
	return api.Declaration{}, false, s.err
}
func (s failStore) PutObservation(context.Context, string, string, string, string) error {
	return s.err
}
func (s failStore) ObservedPlacements(context.Context, string) ([]api.ObservedPlacement, error) {
	return nil, s.err
}

// TestUnavailableStoreRefusesNeverAdmits is SPEC-0043 AC4's unavailable half: a residency
// store the gate cannot read is the coarse failure, and the placement path turns it into a
// REFUSAL — an unavailable constraint never admits work (fail closed, invariant 2's
// enforcement posture). The enrolment path renders this as the same coarse DENIED it
// renders an explicit residency refusal (agent service, no parallel error channel).
func TestUnavailableStoreRefusesNeverAdmits(t *testing.T) {
	f := newFixture(t)
	svc := New(f.pdp, f.wit, failStore{err: errors.New("store down")}, api.Config{
		DetectionWindow:   5 * time.Minute,
		MaxReportInterval: 24 * time.Hour,
		Now:               f.clock,
	}, nil)
	if err := svc.ObservePlacement(scopedCtx("acme"), "acme", "plane-1", "gke", "europe-west1"); !errors.Is(err, api.ErrResidencyUnavailable) {
		t.Fatalf("placement against an unreadable constraint = %v, want the coarse failure the gate refuses on", err)
	}
	if _, err := svc.Declare(scopedCtx("acme"), "acme", "owner-1", []string{"owner"}, "gke", "europe-west1"); !errors.Is(err, api.ErrResidencyUnavailable) {
		t.Fatalf("declare against an unreadable constraint = %v, want the coarse failure", err)
	}
}
