// The gRPC door for the admin area's fleet report (SPEC-0058 AC1, PR-31,
// ADR-0077), over contracts/proto/agent/v1's FleetReader.
//
// It is a PEP and nothing more: it authorizes nothing itself, it asks the agent
// service — which asks the PDP action agent.dataplane.read — and renders every
// refusal in one coarse shape.
//
// WHY THIS DOOR IS SHAPED UNLIKE THE ENROLMENT ONE. That door verifies a PAT and
// takes no tenant or actor field, because its caller is an operator presenting a
// credential. This caller is an org administrator reading through the BFF under a
// session, so the request carries a FleetContext — tenant, actor and roles,
// verified upstream and supplied to the PDP input, never an authorization result
// the caller asserted. It is the shape usage/v1's UsageContext has, for the same
// reason: the BFF is the verified boundary for a browser.
//
// WHAT THIS DOOR CANNOT SERVE. There is no audit read here and none in the
// package — the trail is reached through a scoped, time-boxed, revocable grant
// (SPEC-0033), and check-contracts' check 17 asserts the absence against the
// compiled descriptor. There is no per-person field either: `Last active` is
// presence telemetry about people and nothing else in this product collects any.
package grpc

import (
	"context"
	"time"

	agentpb "github.com/gitfrok/backend/gen/proto/agent/v1"
	"github.com/gitfrok/backend/modules/agent/api"
	"github.com/gitfrok/backend/platform/tenancy"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// FleetDoor serves FleetReader over the agent module's Operator port.
type FleetDoor struct {
	agentpb.UnimplementedFleetReaderServer
	op api.Operator
}

var _ agentpb.FleetReaderServer = (*FleetDoor)(nil)

// NewFleetDoor wires the door over the agent operator surface.
func NewFleetDoor(op api.Operator) *FleetDoor { return &FleetDoor{op: op} }

// fleetDenial is the one coarse refusal. Unverified, unauthorized and unavailable
// are the same answer: the difference between them is what a caller would probe
// for (SPEC-0001).
//
// A tenant with no data planes does NOT reach it — an empty fleet is a successful
// answer, because "you may see none" and "there are none" have to be
// indistinguishable, the same rule the repository list follows (SPEC-0052 AC4).
func fleetDenial() error {
	return status.Error(codes.PermissionDenied, "agent: fleet unavailable")
}

// ListFleet serves one tenant's data planes and its never-connected rows.
func (d *FleetDoor) ListFleet(ctx context.Context, req *agentpb.ListFleetRequest) (*agentpb.ListFleetResponse, error) {
	fc := req.GetContext()
	if fc == nil || fc.GetTenantId() == "" || fc.GetActorId() == "" {
		return nil, fleetDenial()
	}
	// The transaction is scoped from the verified context, never from anything
	// else in the request — there is nothing else in the request.
	ctx = tenancy.WithTenant(ctx, tenancy.ID(fc.GetTenantId()))

	rows, err := d.op.Fleet(ctx, fc.GetTenantId(), fc.GetActorId())
	if err != nil {
		return nil, fleetDenial()
	}

	out := &agentpb.ListFleetResponse{Planes: make([]*agentpb.DataPlaneReport, 0, len(rows))}
	for _, row := range rows {
		out.Planes = append(out.Planes, reportOf(row))
	}
	return out, nil
}

// reportOf shapes one fleet row onto the wire.
//
// The status travels as the Agent context derived it, including STALE — which is
// never rendered as healthy (SPEC-0038 AC8). This door does not reinterpret it:
// a door that decided a stale plane was probably fine would be making a claim the
// context refused to make.
func reportOf(row api.FleetView) *agentpb.DataPlaneReport {
	report := &agentpb.DataPlaneReport{
		Status:  string(row.Status),
		TokenId: row.TokenID,
	}
	// A token-only row has no plane record: it is a data plane somebody
	// provisioned that never came up, and every field below is genuinely absent
	// rather than zero.
	if row.Plane.ID == "" {
		return report
	}
	report.DataPlaneId = row.Plane.ID
	report.Cloud = row.Plane.Cloud
	report.Region = row.Plane.Region
	report.AgentVersion = row.Plane.AgentVersion
	report.K8SVersion = row.Plane.K8sVersion
	report.LastSeenAt = instantOrEmpty(row.Plane.LastSeenAt)
	report.EnrolledAt = instantOrEmpty(row.Plane.EnrolledAt)
	report.CertificateExpiresAt = instantOrEmpty(row.Plane.CertificateExpiresAt)
	return report
}

// instantOrEmpty renders an instant, or nothing at all when there is none.
//
// A plane that has never been heard from has no last-seen instant, and rendering
// a zero one would make it claim contact at the start of the Common Era — which a
// consumer computing an age would render as the oldest plane in the fleet rather
// than as one that has never spoken.
func instantOrEmpty(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
