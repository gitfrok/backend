package main

import (
	"context"
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
