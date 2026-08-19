package grpc_test

import (
	"context"
	"errors"
	"testing"
	"time"

	agentpb "github.com/gitfrok/backend/gen/proto/agent/v1"
	"github.com/gitfrok/backend/modules/agent/api"
	agentgrpc "github.com/gitfrok/backend/modules/agent/internal/adapters/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// SPEC-0058 AC1, AC6, AC7 at the door: what a fleet report carries, what it cannot
// carry, and the single refusal it renders.

var seenAt = time.Date(2026, 8, 19, 9, 0, 0, 0, time.UTC)

// fleetOperator is the Operator port as this door uses it. Only Fleet is
// implemented: the embedded interface makes the rest a compile-time promise
// nothing here calls, so a door that started calling one would fail to build
// rather than silently widening.
type fleetOperator struct {
	api.Operator
	rows       []api.FleetView
	err        error
	gotTenant  string
	gotActorID string
	calls      int
}

func (f *fleetOperator) Fleet(_ context.Context, tenantID, actorID string) ([]api.FleetView, error) {
	f.gotTenant, f.gotActorID = tenantID, actorID
	f.calls++
	return f.rows, f.err
}

func fleetRequest(tenant, actor string) *agentpb.ListFleetRequest {
	return &agentpb.ListFleetRequest{
		Context: &agentpb.FleetContext{
			TenantId: tenant, ActorId: actor, ActorRoles: []string{"owner"}, RequestId: "req-1",
		},
	}
}

// AC1: a connected plane travels with its status, its versions and the instant it
// was last heard from.
func TestListFleetCarriesTheReportAndItsAge(t *testing.T) {
	op := &fleetOperator{rows: []api.FleetView{{
		Status: api.StatusConnected,
		Plane: api.DataPlane{
			ID: "dp-1", TenantID: "t-1", Cloud: "CLOUD_GKE", Region: "eu-west-1",
			AgentVersion: "1.4.0", K8sVersion: "1.30", EnrolledAt: seenAt.Add(-72 * time.Hour),
			LastSeenAt: seenAt, CertificateExpiresAt: seenAt.Add(24 * time.Hour),
			Status: api.StatusConnected,
		},
	}}}

	got, err := agentgrpc.NewFleetDoor(op).ListFleet(context.Background(), fleetRequest("t-1", "owner-1"))
	if err != nil {
		t.Fatalf("ListFleet: %v", err)
	}
	if op.gotTenant != "t-1" || op.gotActorID != "owner-1" {
		t.Errorf("the port did not receive the verified caller: tenant=%q actor=%q", op.gotTenant, op.gotActorID)
	}
	if len(got.GetPlanes()) != 1 {
		t.Fatalf("want one plane, got %d", len(got.GetPlanes()))
	}
	plane := got.GetPlanes()[0]
	if plane.GetDataPlaneId() != "dp-1" || plane.GetStatus() != "CONNECTED" || plane.GetRegion() != "eu-west-1" {
		t.Errorf("unexpected report %+v", plane)
	}
	if plane.GetLastSeenAt() != seenAt.Format(time.RFC3339) {
		t.Errorf("the age is the field this message exists for, and it is %q", plane.GetLastSeenAt())
	}
	if plane.GetK8SVersion() != "1.30" || plane.GetAgentVersion() != "1.4.0" {
		t.Errorf("versions did not travel: %+v", plane)
	}
}

// AC1: a stale plane travels as stale. The door does not reinterpret it — a door
// that decided a stale plane was probably fine would be making a claim the Agent
// context refused to make (SPEC-0038 AC8).
func TestAStalePlaneTravelsAsStale(t *testing.T) {
	op := &fleetOperator{rows: []api.FleetView{{
		Status: api.StatusStale,
		Plane:  api.DataPlane{ID: "dp-2", Status: api.StatusStale, LastSeenAt: seenAt.Add(-96 * time.Hour)},
	}}}

	got, err := agentgrpc.NewFleetDoor(op).ListFleet(context.Background(), fleetRequest("t-1", "owner-1"))
	if err != nil {
		t.Fatalf("ListFleet: %v", err)
	}
	if s := got.GetPlanes()[0].GetStatus(); s != "STALE" {
		t.Errorf("want STALE, got %q", s)
	}
	if got.GetPlanes()[0].GetLastSeenAt() == "" {
		t.Error("a stale plane's whole point is when it was last heard from")
	}
}

// AC1: a provisioned-but-never-connected row carries its token and no instants.
//
// Rendering a zero last-seen would make it claim contact at the start of the
// Common Era, which a consumer computing an age shows as the oldest plane in the
// fleet rather than as one that has never spoken.
func TestANeverConnectedRowCarriesItsTokenAndNoInstants(t *testing.T) {
	op := &fleetOperator{rows: []api.FleetView{{
		Status: api.StatusNeverConnected, TokenID: "tok-9",
	}}}

	got, err := agentgrpc.NewFleetDoor(op).ListFleet(context.Background(), fleetRequest("t-1", "owner-1"))
	if err != nil {
		t.Fatalf("ListFleet: %v", err)
	}
	row := got.GetPlanes()[0]
	if row.GetTokenId() != "tok-9" || row.GetStatus() != "NEVER_CONNECTED" {
		t.Errorf("unexpected row %+v", row)
	}
	if row.GetLastSeenAt() != "" || row.GetEnrolledAt() != "" || row.GetCertificateExpiresAt() != "" {
		t.Errorf("a plane that never connected claims instants: %+v", row)
	}
	if row.GetDataPlaneId() != "" {
		t.Errorf("a token-only row named a data plane: %q", row.GetDataPlaneId())
	}
}

// AC7: an empty fleet is a successful answer, not a refusal. "You may see none"
// and "there are none" have to be indistinguishable.
func TestAnEmptyFleetIsASuccessfulAnswer(t *testing.T) {
	got, err := agentgrpc.NewFleetDoor(&fleetOperator{}).ListFleet(context.Background(), fleetRequest("t-1", "owner-1"))
	if err != nil {
		t.Fatalf("an empty fleet must not be a refusal: %v", err)
	}
	if len(got.GetPlanes()) != 0 {
		t.Errorf("want no planes, got %d", len(got.GetPlanes()))
	}
}

// AC7: every failure is one coarse refusal that names no cause.
func TestEveryFleetFailureIsOneCoarseRefusal(t *testing.T) {
	for name, op := range map[string]*fleetOperator{
		"refused":     {err: api.ErrNotFound},
		"unavailable": {err: errors.New("the registry fell over")},
	} {
		_, err := agentgrpc.NewFleetDoor(op).ListFleet(context.Background(), fleetRequest("t-1", "owner-1"))
		st, ok := status.FromError(err)
		if !ok || st.Code() != codes.PermissionDenied {
			t.Errorf("%s: want PermissionDenied, got %v", name, err)
		}
		if st.Message() != "agent: fleet unavailable" {
			t.Errorf("%s: the refusal names a cause: %q", name, st.Message())
		}
	}
}

// A request that names no tenant or no actor never reaches the port: there is
// nothing to authorize.
func TestAnUnverifiedFleetContextNeverReachesThePort(t *testing.T) {
	op := &fleetOperator{}
	door := agentgrpc.NewFleetDoor(op)
	for name, req := range map[string]*agentpb.ListFleetRequest{
		"no context": {},
		"no tenant":  fleetRequest("", "owner-1"),
		"no actor":   fleetRequest("t-1", ""),
	} {
		if _, err := door.ListFleet(context.Background(), req); err == nil {
			t.Errorf("%s: must be refused", name)
		}
	}
	if op.calls != 0 {
		t.Errorf("the port was reached %d times by unverified calls", op.calls)
	}
}

// AC4/AC6 from the consumer's side: the fleet messages carry no audit record and
// no person. check-contracts asserts the same against the compiled descriptor in
// governance; this asserts it where the code that would read such a field lives,
// so a stale gen/ tree cannot introduce one either.
func TestTheFleetMessagesCarryNoAuditRecordAndNoPerson(t *testing.T) {
	excluded := map[string]bool{
		"audit_records": true, "audit_log": true, "trail": true,
		"last_active": true, "member": true, "members": true, "user_email": true,
	}
	for _, m := range []proto.Message{
		&agentpb.DataPlaneReport{}, &agentpb.ListFleetRequest{},
		&agentpb.ListFleetResponse{}, &agentpb.FleetContext{},
	} {
		fields := m.ProtoReflect().Descriptor().Fields()
		for i := range fields.Len() {
			if name := string(fields.Get(i).Name()); excluded[name] {
				t.Errorf("%s carries %q — outside ADR-0077's accepted increment",
					m.ProtoReflect().Descriptor().FullName(), name)
			}
		}
	}
}

// AC4: the service has exactly one method, and it reads the fleet.
func TestFleetReaderServesOnlyTheFleet(t *testing.T) {
	sd := agentpb.File_proto_agent_v1_agent_proto.Services().ByName("FleetReader")
	if sd == nil {
		t.Fatal("FleetReader is not in the descriptor")
	}
	if n := sd.Methods().Len(); n != 1 {
		t.Fatalf("want exactly one method, got %d", n)
	}
	if got := string(sd.Methods().Get(0).Name()); got != "ListFleet" {
		t.Errorf("want ListFleet, got %q", got)
	}
}
