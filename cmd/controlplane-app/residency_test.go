package main

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/gitfrok/backend/modules/agent"
	agentapi "github.com/gitfrok/backend/modules/agent/api"
	"github.com/gitfrok/backend/modules/audit"
	auditapi "github.com/gitfrok/backend/modules/audit/api"
	identityapi "github.com/gitfrok/backend/modules/identity/api"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
	"github.com/gitfrok/backend/modules/residency"
	residencyapi "github.com/gitfrok/backend/modules/residency/api"
	platformaudit "github.com/gitfrok/backend/platform/audit"
	"github.com/gitfrok/backend/platform/bus"
	"github.com/gitfrok/backend/platform/tenancy"
)

// allowPDP authorizes every decision: the composition test asserts the WIRING, not the
// policy — the policy vocabulary has its own governance and PDP tests.
type allowPDP struct{}

func (allowPDP) Decide(context.Context, policyapi.Request) (policyapi.Decision, error) {
	return policyapi.Decision{Allowed: true}, nil
}

// composedResidency wires exactly what startAgentDoor composes for the residency seam —
// trail, witness, Residency context, gate attach — minus the gRPC listener.
func composedResidency(t *testing.T) (*agent.Service, residencyapi.Service, auditapi.TrailStore) {
	t.Helper()
	b := bus.NewInProcess()
	ca, err := agent.NewDevCA("test-residency-ca", time.Now)
	if err != nil {
		t.Fatalf("dev ca: %v", err)
	}
	cfg := agentapi.Config{
		CertLifetime:          time.Hour,
		RotationLead:          20 * time.Minute,
		RotationRetryInterval: time.Minute,
		StaleAfter:            5 * time.Minute,
		TokenMaxLifetime:      24 * time.Hour,
		HeartbeatInterval:     30 * time.Second,
		ClockSkewLeeway:       5 * time.Minute,
		Now:                   time.Now,
	}
	svc := agent.New(allowPDP{}, b, ca, cfg, func(string, ...any) {})
	trail := audit.NewMemoryTrail()
	resSvc := residency.New(allowPDP{}, residencyTrailWitness{trail}, residencyapi.Config{
		DetectionWindow:   time.Hour,
		MaxReportInterval: time.Hour,
		Now:               time.Now,
	}, func(string, ...any) {})
	if !agent.AttachPlacementGate(svc, residencyPlacementGate{svc: resSvc}) {
		t.Fatalf("AttachPlacementGate reported no gate sink on the composed agent surface")
	}
	return svc, resSvc, trail
}

func ownerCtx(tenant string) context.Context {
	ctx := tenancy.WithTenant(context.Background(), tenancy.ID(tenant))
	return identityapi.WithPrincipal(ctx, identityapi.Principal{TenantID: tenant, ActorID: "op-1", Roles: []string{"owner"}})
}

// The whole T-0033 flow through the composed control plane: a declaration pinned by an
// owner, a contradicting enrolment refused at the gate with BOTH placements witnessed,
// the token reusable from an allowed placement, and every fact readable back from the
// trail the evidence pack's residency section cites (SPEC-0040 AC1, AC2, AC4).
func TestResidencyCompositionRefusesAndWitnesses(t *testing.T) {
	svc, resSvc, trail := composedResidency(t)
	ctx := ownerCtx("acme")

	if _, err := resSvc.Declare(ctx, "acme", "op-1", []string{"owner"}, "gcp", "eu-west1"); err != nil {
		t.Fatalf("Declare: %v", err)
	}

	_, secret, err := svc.IssueEnrolmentToken(ctx, "acme", "op-1", time.Hour)
	if err != nil {
		t.Fatalf("IssueEnrolmentToken: %v", err)
	}

	// A placement outside the declared residency is refused coarse — and costs no token.
	_, err = svc.Enrol(context.Background(), agentapi.EnrolRequest{Token: secret, Cloud: "aws", Region: "us-east-1"})
	if refused, ok := err.(*agentapi.EnrolmentRefused); !ok || refused.Reason != agentapi.RefusalDenied {
		t.Fatalf("contradicting Enrol = %v, want coarse DENIED", err)
	}

	// The refusal is witnessed with BOTH placements on the tenant's chain.
	refused, _, err := trail.Query(ctx, auditapi.TrailQuery{Actions: []auditapi.Action{platformaudit.ActionResidencyPlacementRefused}})
	if err != nil || len(refused) != 1 {
		t.Fatalf("refused placement records = %d (err %v), want 1", len(refused), err)
	}
	detail := refused[0].Detail
	if detail[platformaudit.DetailResidencyPinnedCloud] != "gcp" || detail[platformaudit.DetailResidencyPinnedRegion] != "eu-west1" {
		t.Fatalf("refusal detail pinned = %v, want gcp/eu-west1", detail)
	}
	if detail[platformaudit.DetailResidencyObservedCloud] != "aws" || detail[platformaudit.DetailResidencyObservedRegion] != "us-east-1" {
		t.Fatalf("refusal detail observed = %v, want aws/us-east-1", detail)
	}

	// The same token enrols from the declared placement — and that placement is
	// witnessed as observed.
	enrolment, err := svc.Enrol(context.Background(), agentapi.EnrolRequest{Token: secret, Cloud: "gcp", Region: "eu-west1"})
	if err != nil {
		t.Fatalf("Enrol from declared placement: %v", err)
	}
	if enrolment.TenantID != "acme" || enrolment.DataPlaneID == "" {
		t.Fatalf("enrolment identity = %+v", enrolment.Identity)
	}
	observed, _, err := trail.Query(ctx, auditapi.TrailQuery{Actions: []auditapi.Action{platformaudit.ActionResidencyPlacementObserved}})
	if err != nil || len(observed) != 1 {
		t.Fatalf("observed placement records = %d (err %v), want 1", len(observed), err)
	}
	if observed[0].Detail[platformaudit.DetailResidencyObservedCloud] != "gcp" {
		t.Fatalf("observed detail = %v, want gcp", observed[0].Detail)
	}

	// The declaration itself is on the chain — the record the pack cites in force (AC4).
	declarations, _, err := trail.Query(ctx, auditapi.TrailQuery{Actions: []auditapi.Action{platformaudit.ActionResidencyDeclarationSet}})
	if err != nil || len(declarations) != 1 {
		t.Fatalf("declaration records = %d (err %v), want 1", len(declarations), err)
	}
}

// flakyResidencyStore is the durable store's failure shape: it serves one declaration
// while healthy and fails every path when flagged — the composition's stand-in for a
// Postgres the plane cannot read (SPEC-0043 AC4's unavailable half).
type flakyResidencyStore struct {
	mu   sync.Mutex
	fail bool
	decl residencyapi.Declaration
	has  bool
}

func (s *flakyResidencyStore) failNow() { s.mu.Lock(); defer s.mu.Unlock(); s.fail = true }
func (s *flakyResidencyStore) heal()    { s.mu.Lock(); defer s.mu.Unlock(); s.fail = false }
func (s *flakyResidencyStore) broken() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fail
}

func (s *flakyResidencyStore) PutDeclaration(_ context.Context, d residencyapi.Declaration) error {
	if s.broken() {
		return residencyapi.ErrResidencyUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.decl, s.has = d, true
	return nil
}

func (s *flakyResidencyStore) DeclarationAt(_ context.Context, _ string, _ time.Time) (residencyapi.Declaration, bool, error) {
	if s.broken() {
		return residencyapi.Declaration{}, false, residencyapi.ErrResidencyUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.decl, s.has, nil
}

func (s *flakyResidencyStore) PutObservation(context.Context, string, string, string, string) error {
	if s.broken() {
		return residencyapi.ErrResidencyUnavailable
	}
	return nil
}

func (s *flakyResidencyStore) ObservedPlacements(context.Context, string) ([]residencyapi.ObservedPlacement, error) {
	if s.broken() {
		return nil, residencyapi.ErrResidencyUnavailable
	}
	return nil, nil
}

var _ residency.Store = (*flakyResidencyStore)(nil)

// TestResidencyGateUnavailableRefusesCoarseAndKeepsToken is SPEC-0043 AC4: an UNAVAILABLE
// residency target refuses enrolment exactly like a contradicting one — the same coarse
// DENIED shape as shipped, the token unspent, and the refusal audited — because the gate
// consults the durable effective-dated store and an unreadable constraint refuses, never
// admits. The retry from the SAME token after recovery proves the refusal cost nothing.
func TestResidencyGateUnavailableRefusesCoarseAndKeepsToken(t *testing.T) {
	b := bus.NewInProcess()
	ca, err := agent.NewDevCA("test-residency-unavailable-ca", time.Now)
	if err != nil {
		t.Fatalf("dev ca: %v", err)
	}
	cfg := agentapi.Config{
		CertLifetime:          time.Hour,
		RotationLead:          20 * time.Minute,
		RotationRetryInterval: time.Minute,
		StaleAfter:            5 * time.Minute,
		TokenMaxLifetime:      24 * time.Hour,
		HeartbeatInterval:     30 * time.Second,
		ClockSkewLeeway:       5 * time.Minute,
		Now:                   time.Now,
	}
	svc := agent.New(allowPDP{}, b, ca, cfg, func(string, ...any) {})
	var enrolments []platformaudit.AgentEnrolment
	b.Subscribe(platformaudit.EventAudit, func(_ context.Context, e bus.Event) error {
		if en, ok := e.(platformaudit.AgentEnrolment); ok {
			enrolments = append(enrolments, en)
		}
		return nil
	})
	trail := audit.NewMemoryTrail()
	store := &flakyResidencyStore{}
	resSvc := residency.NewWithStore(allowPDP{}, residencyTrailWitness{trail}, store, residencyapi.Config{
		DetectionWindow:   time.Hour,
		MaxReportInterval: time.Hour,
		Now:               time.Now,
	}, func(string, ...any) {})
	if !agent.AttachPlacementGate(svc, residencyPlacementGate{svc: resSvc}) {
		t.Fatalf("AttachPlacementGate reported no gate sink on the composed agent surface")
	}
	ctx := ownerCtx("acme")

	if _, err := resSvc.Declare(ctx, "acme", "op-1", []string{"owner"}, "gcp", "eu-west1"); err != nil {
		t.Fatalf("Declare: %v", err)
	}
	_, secret, err := svc.IssueEnrolmentToken(ctx, "acme", "op-1", time.Hour)
	if err != nil {
		t.Fatalf("IssueEnrolmentToken: %v", err)
	}

	// The durable store goes down: even the DECLARED placement refuses — coarse, like
	// every other residency refusal.
	store.failNow()
	_, err = svc.Enrol(context.Background(), agentapi.EnrolRequest{Token: secret, Cloud: "gcp", Region: "eu-west1"})
	if refused, ok := err.(*agentapi.EnrolmentRefused); !ok || refused.Reason != agentapi.RefusalDenied {
		t.Fatalf("enrolment against an unavailable residency target = %v, want coarse DENIED", err)
	}

	// Recovery: the SAME token enrols from the declared placement — the refusal spent
	// nothing (SPEC-0040 AC2's unspent-token rule extends to the unavailable case).
	store.heal()
	enrolment, err := svc.Enrol(context.Background(), agentapi.EnrolRequest{Token: secret, Cloud: "gcp", Region: "eu-west1"})
	if err != nil {
		t.Fatalf("the unspent token must enrol after recovery: %v", err)
	}
	if enrolment.TenantID != "acme" || enrolment.DataPlaneID == "" {
		t.Fatalf("enrolment identity = %+v", enrolment.Identity)
	}
	// The refusal is audited under the token's tenant as the agent's coarse enrolment
	// DENIED — one record for the unavailable-target refusal.
	denials := 0
	for _, en := range enrolments {
		if en.Outcome == "DENIED" && en.TenantID == "acme" {
			denials++
		}
	}
	if denials != 1 {
		t.Fatalf("denied enrolment records = %d, want exactly 1 (the unavailable-target refusal)", denials)
	}
}

// TestResidencyDoorConfigIsAllOrNothing is the fail-fast posture the declare door
// inherits from the Git front door (ADR-0006): an unconfigured door serves no
// surface, but an open door without a verifier key fails the rollout — a door
// that cannot verify its caller must never serve a surface that writes control
// state (SPEC-0043 AC6).
func TestResidencyDoorConfigIsAllOrNothing(t *testing.T) {
	getenv := func(m map[string]string) func(string) string {
		return func(k string) string { return m[k] }
	}
	// Unconfigured: no door, no error.
	cfg, err := loadResidencyDoorConfig(getenv(map[string]string{}))
	if err != nil || cfg.addr != "" || cfg.patKey != nil {
		t.Fatalf("unconfigured door = %+v, %v; want empty, no error", cfg, err)
	}
	// Open door with a proper key: both, as one unit.
	key := "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=" // base64 of 31+ bytes
	cfg, err = loadResidencyDoorConfig(getenv(map[string]string{
		residencyGRPCAddrEnv: "127.0.0.1:7155", patVerifierKeyEnv: key,
	}))
	if err != nil || cfg.addr != "127.0.0.1:7155" || len(cfg.patKey) < 32 {
		t.Fatalf("configured door = %+v, %v; want addr + >=32-byte key", cfg, err)
	}
	// Open door, missing/short/malformed key: the rollout fails.
	for name, kv := range map[string]string{
		"missing key": "",
		"short key":   "c2hvcnQ=",
		"not base64":  "!!!",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadResidencyDoorConfig(getenv(map[string]string{
				residencyGRPCAddrEnv: "127.0.0.1:7155", patVerifierKeyEnv: kv,
			})); err == nil {
				t.Fatalf("an open door without a usable verifier key must fail the rollout (%s)", name)
			}
		})
	}
}

// TestResidencyEvidencePackMatrixFedByDeclareSurface is T-0039's golden over the whole
// matrix with every fact fed by the surfaces that witness them: declarations set through
// the residency Declare service (the new surface, SPEC-0043), placements witnessed through
// the placement gate. The pack then cites the effective-dated replace (SPEC-0040 AC6), the
// matching observation, the refused attempt and the raised contradiction — each in its
// ResidencyFactKind vocabulary, with no silence where planes reported (SPEC-0043 AC2, AC3).
func TestResidencyEvidencePackMatrixFedByDeclareSurface(t *testing.T) {
	b := bus.NewInProcess()
	trail := audit.NewMemoryTrail()
	resSvc := residency.New(allowPDP{}, residencyTrailWitness{trail}, residencyapi.Config{
		DetectionWindow:   time.Hour,
		MaxReportInterval: time.Hour,
		Now:               time.Now,
	}, func(string, ...any) {})
	evSvc := audit.NewEvidenceService(allowPDP{}, b, trail, nil, nil, nil).WithResidencyWindow(24 * time.Hour)
	ctx := ownerCtx("acme")

	// Declare, then a matching placement, then a contradicting attempt the gate refuses —
	// all through the services that witness them.
	if _, err := resSvc.Declare(ctx, "acme", "op-1", []string{"owner"}, "gke", "europe-west1"); err != nil {
		t.Fatalf("Declare: %v", err)
	}
	if err := resSvc.ObservePlacement(ctx, "acme", "plane-1", "gke", "europe-west1"); err != nil {
		t.Fatalf("matching placement: %v", err)
	}
	if err := resSvc.ObservePlacement(ctx, "acme", "plane-1", "aws", "us-east1"); !errors.Is(err, residencyapi.ErrPlacementRefused) {
		t.Fatalf("contradicting placement = %v, want the gate's refusal", err)
	}
	// The replace: an effective-dated second declaration. It takes effect against the
	// witnessed gke placement, raising the contradiction state.
	time.Sleep(2 * time.Millisecond) // distinct effective times, like distinct acts
	if _, err := resSvc.Declare(ctx, "acme", "op-1", []string{"owner"}, "aws", "eu-central-1"); err != nil {
		t.Fatalf("replace Declare: %v", err)
	}

	// The pack cites the whole matrix off the same trail.
	owner := auditapi.Context{
		TenantID: "acme", ActorID: "op-1", ActorRoles: []string{"owner"}, RequestID: "req-residency-matrix",
	}
	packID, _, err := evSvc.RequestPack(context.Background(), owner, auditapi.PackRequest{
		RangeFrom: time.Now().Add(-time.Hour), RangeTo: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("RequestPack: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		st, err := evSvc.PackStatus(context.Background(), owner, packID)
		if err != nil {
			t.Fatalf("PackStatus: %v", err)
		}
		if st.State == auditapi.PackReady {
			break
		}
		if st.State == auditapi.PackFailed || time.Now().After(deadline) {
			t.Fatalf("pack never became READY: %+v", st)
		}
		time.Sleep(time.Millisecond)
	}
	chunks, err := evSvc.GetPack(context.Background(), owner, packID)
	if err != nil {
		t.Fatalf("GetPack: %v", err)
	}
	var sec *auditapi.Section
	for i := range chunks {
		if chunks[i].Section != nil && chunks[i].Section.Type == auditapi.SectionResidency {
			sec = chunks[i].Section
		}
	}
	if sec == nil {
		t.Fatal("the pack carries no residency section")
	}

	kinds := map[auditapi.ResidencyFactKind][]auditapi.SectionRecord{}
	for _, r := range sec.Records {
		if r.Residency == nil {
			t.Fatalf("every residency record carries its fact: %+v", r)
		}
		kinds[r.Residency.FactKind] = append(kinds[r.Residency.FactKind], r)
	}
	// AC6's rendering fed by the new surface: both declarations stay on the record in
	// chain order, each with its own effective time.
	pins := kinds[auditapi.ResidencyFactPinning]
	if len(pins) != 2 {
		t.Fatalf("the replace keeps both pinnings, got %d", len(pins))
	}
	if pins[0].Residency.PinnedCloud != "gke" || pins[1].Residency.PinnedCloud != "aws" {
		t.Fatalf("pinnings must appear in chain order: %+v", pins)
	}
	if pins[0].OccurredAt.Equal(pins[1].OccurredAt) {
		t.Fatal("the change keeps its own effective time")
	}
	for _, want := range []auditapi.ResidencyFactKind{
		auditapi.ResidencyFactPlacement, auditapi.ResidencyFactPlacementRefused,
		auditapi.ResidencyFactPlacementContradiction,
	} {
		if len(kinds[want]) == 0 {
			t.Fatalf("the section must cite a %s fact, got %v", want, kinds)
		}
	}
	for _, rec := range kinds[auditapi.ResidencyFactPlacementContradiction] {
		if rec.Allowed || rec.Residency.ObservedCloud != "gke" || rec.Residency.PinnedCloud != "aws" {
			t.Fatalf("the contradiction names the witnessed placement and the new pinning, DENIED: %+v", rec)
		}
	}
	// AC3 in the golden: the obligation window opens at the first declaration's
	// effective time, and the plane's first report lands a beat later — that beat
	// renders as the ONE named PLACEMENT_SILENT gap, never as inferred placement.
	// Everything after the first report is covered, so exactly one gap remains.
	firstReport := kinds[auditapi.ResidencyFactPlacement][0].OccurredAt
	want := auditapi.SectionGap{From: pins[0].OccurredAt, To: firstReport, Reason: auditapi.GapPlacementSilent}
	if sec.Complete || len(sec.Gaps) != 1 || sec.Gaps[0] != want {
		t.Fatalf("gaps = %+v, want exactly %+v — the declaration-to-first-report silence, named", sec.Gaps, want)
	}
}
