// Adapter tests for the UsageService gRPC door (T-0034, SPEC-0041): the RPC
// is implemented (no fall-through to Unimplemented), api <-> proto types map
// field-for-field, and errors map to the coarse gRPC shapes (SPEC-0001). The
// door is driven through the real composed service so the mapping is proven
// against an actual ledger, not a hand-shaped stub.
package grpc

import (
	"context"
	"testing"
	"time"

	usagev1 "github.com/gitfrok/backend/gen/proto/usage/v1"
	"github.com/gitfrok/backend/modules/metering/api"
	"github.com/gitfrok/backend/modules/metering/internal/adapters/memory"
	"github.com/gitfrok/backend/modules/metering/internal/app"
	"github.com/gitfrok/backend/modules/metering/internal/domain"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
	"github.com/gitfrok/backend/platform/bus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type allowPDP struct{ deny bool }

func (p *allowPDP) Decide(_ context.Context, _ policyapi.Request) (policyapi.Decision, error) {
	return policyapi.Decision{Allowed: !p.deny}, nil
}

type nopNotifier struct{}

func (nopNotifier) Notify(_ context.Context, _ api.Notice) error { return nil }

// newServer composes the real service on the in-memory store and adapts it.
func newServer(t *testing.T, pdp policyapi.DecisionPoint) (*Server, *app.Service) {
	t.Helper()
	cfg := api.Config{
		Now:      func() time.Time { return time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC) },
		GapAfter: 15 * time.Minute,
		DefaultThresholds: map[api.Dimension]api.Threshold{
			api.DimensionCIMinutes: {Notify: 80, Envelope: 100},
		},
	}
	svc := app.New(memory.New(), nopNotifier{}, bus.NewInProcess(), pdp, cfg, nil)
	return NewServer(svc), svc
}

func ctx(tenant, actor string) *usagev1.UsageContext {
	return &usagev1.UsageContext{
		TenantId: tenant, ActorId: actor, ActorRoles: []string{"owner"}, RequestId: "req-1",
	}
}

// A well-formed, authorized read returns one row per PRD §6 dimension (AC2),
// and a dimension with no telemetry renders a gap — never zero (AC3).
func TestGetUsageViewReturnsCoverageAndGaps(t *testing.T) {
	srv, _ := newServer(t, &allowPDP{})
	resp, err := srv.GetUsageView(context.Background(), &usagev1.GetUsageViewRequest{Context: ctx("tenant-a", "actor-1")})
	if err != nil {
		t.Fatalf("GetUsageView: %v", err)
	}
	if len(resp.GetDimensions()) != len(api.PRDDimensions) {
		t.Fatalf("dimensions: got %d, want one per PRD §6 dimension (%d)", len(resp.GetDimensions()), len(api.PRDDimensions))
	}
	for _, d := range resp.GetDimensions() {
		if d.GetCoverage() == usagev1.DimensionCoverage_DIMENSION_COVERAGE_DEFERRED {
			// AC2: a deferred row names its reason and never renders within-envelope.
			if d.GetDeferredReason() == "" {
				t.Fatalf("deferred %s must carry its reason", d.GetDimension())
			}
			continue
		}
		// AC3: a metered dimension with no telemetry is a gap, never a number.
		if !d.GetTelemetryGap() {
			t.Fatalf("metered %s with no telemetry must render a gap", d.GetDimension())
		}
		if d.GetCurrentValue() != 0 || d.GetWindowStart() != nil {
			t.Fatalf("gap row %s must carry no usable number", d.GetDimension())
		}
	}
}

// An authorized read reflects the ledger: a received CI-minutes counter maps
// to current_value with its recorded window (AC10).
func TestGetUsageViewMapsDerivedCounter(t *testing.T) {
	srv, svc := newServer(t, &allowPDP{})
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	w := api.Interval{Start: now.Add(-time.Hour), End: now}
	ingest := func(id string, total float64) {
		t.Helper()
		err := svc.IngestTelemetry(context.Background(), "tenant-a", "plane-1", api.Telemetry{
			MessageID: id, Window: w,
			Counters: map[string]float64{domain.MetricCIMinutes: total},
		})
		if err != nil {
			t.Fatalf("IngestTelemetry: %v", err)
		}
	}
	ingest("s1", 0)
	ingest("s2", 42)

	resp, err := srv.GetUsageView(context.Background(), &usagev1.GetUsageViewRequest{Context: ctx("tenant-a", "actor-1")})
	if err != nil {
		t.Fatalf("GetUsageView: %v", err)
	}
	var ci *usagev1.UsageDimensionView
	for _, d := range resp.GetDimensions() {
		if d.GetDimension().String() == "FAIR_USE_DIMENSION_CI_MINUTES" {
			ci = d
		}
	}
	if ci == nil {
		t.Fatal("usage view must carry a CI-minutes row")
	}
	if ci.GetTelemetryGap() {
		t.Fatal("a derived counter must not render as a gap")
	}
	if ci.GetCurrentValue() != 42 {
		t.Fatalf("current_value: got %v, want 42 (the control plane's counter)", ci.GetCurrentValue())
	}
	if ci.GetWindowStart() == nil || ci.GetWindowEnd() == nil {
		t.Fatal("a derived counter must cite the interval it was made from")
	}
}

// Malformed contexts and denied reads are the same coarse refusal (SPEC-0001):
// the wire never distinguishes unauthorized from not-found.
func TestGetUsageViewCoarseRefusals(t *testing.T) {
	srv, _ := newServer(t, &allowPDP{})
	for _, tc := range []*usagev1.UsageContext{
		nil,
		{ActorId: "a", RequestId: "r"},  // no tenant
		{TenantId: "t", RequestId: "r"}, // no actor
		{TenantId: "t", ActorId: "a"},   // no request id
	} {
		if _, err := srv.GetUsageView(context.Background(), &usagev1.GetUsageViewRequest{Context: tc}); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("malformed context %+v: got %v, want InvalidArgument", tc, err)
		}
	}

	denySrv, _ := newServer(t, &allowPDP{deny: true})
	if _, err := denySrv.GetUsageView(context.Background(), &usagev1.GetUsageViewRequest{Context: ctx("tenant-a", "actor-1")}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("denied read: got %v, want PermissionDenied", err)
	}
}
