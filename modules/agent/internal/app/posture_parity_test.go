// SPEC-0045 AC4's posture-parity half (T-0041, ADR-0065 decision 4): there
// are no per-plane product tiers. Any capability difference between the data
// planes of one tenant is a DEFECT — the fleet read fails with a named
// finding instead of rendering the difference as normal.
package app

import (
	"context"
	"strings"
	"testing"

	"github.com/gitfrok/backend/modules/agent/api"
)

// enrolPlane enrols one data plane with the given capabilities and returns
// its registry ID.
func enrolPlane(t *testing.T, h *harness, tenant string, caps []string) string {
	t.Helper()
	_, secret := h.issueToken(t, tenant)
	e, err := h.svc.Enrol(context.Background(), api.EnrolRequest{
		Token: secret, Cloud: "GKE", Region: "eu-west1", Capabilities: caps,
	})
	if err != nil {
		t.Fatalf("Enrol: %v", err)
	}
	return e.Identity.DataPlaneID
}

// TestPostureParityCapabilityDifferenceIsADefect proves the rule: two planes
// of one tenant whose capability sets differ fail the parity check, and the
// finding names the separating capability.
func TestPostureParityCapabilityDifferenceIsADefect(t *testing.T) {
	h := newHarness(t)
	enrolPlane(t, h, "acme", []string{"ci", "scan"})
	enrolPlane(t, h, "acme", []string{"ci"})

	err := h.svc.PostureParity(operatorCtx("acme", "op-1"), "acme", "op-1")
	if err == nil {
		t.Fatal("a capability difference between one tenant's planes must fail as a defect")
	}
	if !strings.Contains(err.Error(), `"scan"`) || !strings.Contains(err.Error(), "posture parity defect") {
		t.Fatalf("defect finding %q must name the separating capability", err)
	}
}

// TestPostureParityEqualCapabilitiesPass: a fleet whose planes all carry the
// same capability set — order-insensitive — is the only shape that passes.
func TestPostureParityEqualCapabilitiesPass(t *testing.T) {
	h := newHarness(t)
	enrolPlane(t, h, "acme", []string{"ci", "scan"})
	enrolPlane(t, h, "acme", []string{"scan", "ci"}) // same set, other order

	if err := h.svc.PostureParity(operatorCtx("acme", "op-1"), "acme", "op-1"); err != nil {
		t.Fatalf("equal capability sets must pass posture parity, got %v", err)
	}
}

// TestPostureParityRevokedPlaneIsOutOfFleet: a revoked plane no longer is the
// fleet, so its differing capabilities cannot produce a defect against the
// live planes.
func TestPostureParityRevokedPlaneIsOutOfFleet(t *testing.T) {
	h := newHarness(t)
	enrolPlane(t, h, "acme", []string{"ci", "scan"})
	odd := enrolPlane(t, h, "acme", []string{"ci"})

	if err := h.svc.RevokeDataPlane(operatorCtx("acme", "op-1"), "acme", "op-1", odd); err != nil {
		t.Fatalf("RevokeDataPlane: %v", err)
	}
	if err := h.svc.PostureParity(operatorCtx("acme", "op-1"), "acme", "op-1"); err != nil {
		t.Fatalf("a revoked plane is out of the fleet; parity must pass, got %v", err)
	}
}
