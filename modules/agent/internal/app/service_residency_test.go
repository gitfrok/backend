package app

import (
	"context"
	"errors"
	"testing"

	"github.com/gitfrok/backend/modules/agent/api"
	platformaudit "github.com/gitfrok/backend/platform/audit"
	"github.com/gitfrok/backend/platform/tenancy"
)

// fakePlacementGate records the last consultation and answers with a test knob. It stands
// in for the Residency context's placement enforcement (T-0033, SPEC-0040 AC2).
type fakePlacementGate struct {
	err        error
	calls      int
	lastTenant tenancy.ID
	lastArgs   struct{ tenant, plane, cloud, region string }
}

func (g *fakePlacementGate) CheckPlacement(ctx context.Context, tenantID, dataPlaneID, cloud, region string) error {
	g.calls++
	g.lastArgs.tenant, g.lastArgs.plane = tenantID, dataPlaneID
	g.lastArgs.cloud, g.lastArgs.region = cloud, region
	g.lastTenant, _ = tenancy.FromContext(ctx)
	return g.err
}

// --- SPEC-0040 AC2: refused placement is witnessed and costs nothing -------------------

func TestEnrolPlacementRefusedLeavesTokenUnspent(t *testing.T) {
	h := newHarness(t)
	gate := &fakePlacementGate{err: errors.New("placement refused")}
	h.svc.SetPlacementGate(gate)
	_, secret := h.issueToken(t, "acme")

	_, err := h.svc.Enrol(context.Background(), api.EnrolRequest{Token: secret, Cloud: "aws", Region: "us-east-1"})
	if got := refusedReason(t, err); got != api.RefusalDenied {
		t.Fatalf("refused placement reason = %q, want DENIED (coarse)", got)
	}
	if gate.calls != 1 {
		t.Fatalf("gate consultations = %d, want 1", gate.calls)
	}

	// The refusal is audited with the residency reason — never silent.
	records := h.bus.of(platformaudit.ActionAgentEnrolment)
	if len(records) != 1 {
		t.Fatalf("enrolment audit records = %d, want 1", len(records))
	}
	ev, ok := records[0].(platformaudit.AgentEnrolment)
	if !ok || ev.Outcome != "DENIED" || ev.Reason != "residency_placement_refused" {
		t.Fatalf("audit record = %+v, want DENIED residency_placement_refused", records[0])
	}
	if ev.DataPlaneID == "" {
		t.Fatalf("refused enrolment record carries no data-plane identity")
	}

	// The token is NOT spent on a refused placement: a retry from an allowed placement
	// succeeds with the same token (SPEC-0040 AC2).
	gate.err = nil
	enrolment, err := h.svc.Enrol(context.Background(), api.EnrolRequest{Token: secret, Cloud: "gcp", Region: "eu-west1"})
	if err != nil {
		t.Fatalf("retry Enrol after refused placement: %v", err)
	}
	if enrolment.TenantID != "acme" || enrolment.DataPlaneID == "" {
		t.Fatalf("retry enrolment identity = %+v", enrolment.Identity)
	}
}

func TestEnrolGateSeesTenantScopedPlacement(t *testing.T) {
	h := newHarness(t)
	gate := &fakePlacementGate{}
	h.svc.SetPlacementGate(gate)
	_, secret := h.issueToken(t, "acme")

	if _, err := h.svc.Enrol(context.Background(), api.EnrolRequest{Token: secret, Cloud: "gcp", Region: "eu-west1"}); err != nil {
		t.Fatalf("Enrol: %v", err)
	}
	if gate.lastArgs.tenant != "acme" || gate.lastArgs.cloud != "gcp" || gate.lastArgs.region != "eu-west1" {
		t.Fatalf("gate args = %+v, want acme/gcp/eu-west1", gate.lastArgs)
	}
	if gate.lastArgs.plane == "" {
		t.Fatalf("gate saw no data-plane identity")
	}
	if string(gate.lastTenant) != "acme" {
		t.Fatalf("gate ctx tenant = %q, want acme", gate.lastTenant)
	}
}

// An unreachable or failing gate is indistinguishable from a residency refusal: one coarse
// DENIED enrolment, fail closed (SPEC-0001).
func TestEnrolGateErrorFailsClosed(t *testing.T) {
	h := newHarness(t)
	h.svc.SetPlacementGate(&fakePlacementGate{err: errors.New("registry unavailable")})
	_, secret := h.issueToken(t, "acme")

	_, err := h.svc.Enrol(context.Background(), api.EnrolRequest{Token: secret, Cloud: "gcp", Region: "eu-west1"})
	if got := refusedReason(t, err); got != api.RefusalDenied {
		t.Fatalf("gate-error refusal reason = %q, want DENIED (coarse)", got)
	}
	if got := len(h.bus.of(platformaudit.ActionAgentEnrolment)); got != 1 {
		t.Fatalf("audit records = %d, want 1 (the refusal is never silent)", got)
	}
}
