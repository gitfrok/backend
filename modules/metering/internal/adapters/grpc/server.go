// Package grpc is the Metering context's usage door: the UsageService gRPC adapter the
// BFF calls for the tenant's fair-use usage view (T-0034, SPEC-0041). It carries only
// verified identity context; no caller can assert a counter, an envelope state, or an
// authorization result — those are ledger state and PDP answers, respectively.
package grpc

import (
	"context"
	"errors"

	agentpb "github.com/gitfrok/backend/gen/proto/agent/v1"
	usagev1 "github.com/gitfrok/backend/gen/proto/usage/v1"
	"github.com/gitfrok/backend/modules/metering/api"
	"github.com/gitfrok/backend/platform/tenancy"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Server is the gRPC adapter for the Reader port.
type Server struct {
	usagev1.UnimplementedUsageServiceServer
	reader api.Reader
}

var _ usagev1.UsageServiceServer = (*Server)(nil)

// NewServer builds the adapter over the module's Reader port.
func NewServer(reader api.Reader) *Server { return &Server{reader: reader} }

// denial is the coarse refusal (SPEC-0001): not-found, cross-tenant and
// unauthorized are indistinguishable on the wire.
func denial() error {
	return status.Error(codes.PermissionDenied, "usage: view unavailable")
}

var errMalformed = status.Error(codes.InvalidArgument, "malformed request")

// GetUsageView returns the tenant's fair-use usage view: one entry per PRD §6
// dimension (AC2), gaps where telemetry is missing — never zeros (AC3), and
// divergences carrying both numbers (AC1). The read is PDP-authorized under
// the caller's verified identity before any ledger is touched.
func (s *Server) GetUsageView(ctx context.Context, req *usagev1.GetUsageViewRequest) (*usagev1.GetUsageViewResponse, error) {
	c := req.GetContext()
	if c == nil || c.GetTenantId() == "" || c.GetActorId() == "" || c.GetRequestId() == "" {
		return nil, errMalformed
	}
	ctx = tenancy.WithTenant(ctx, tenancy.ID(c.GetTenantId()))
	view, err := s.reader.ReadUsageView(ctx, api.ViewContext{
		TenantID: c.GetTenantId(), ActorID: c.GetActorId(),
		ActorRoles: c.GetActorRoles(), RequestID: c.GetRequestId(),
	})
	if err != nil {
		if errors.Is(err, api.ErrMalformed) {
			return nil, errMalformed
		}
		return nil, denial()
	}
	return toViewProto(view), nil
}

func toViewProto(v api.View) *usagev1.GetUsageViewResponse {
	out := &usagev1.GetUsageViewResponse{GeneratedAt: timestamppb.New(v.GeneratedAt)}
	for _, row := range v.Dimensions {
		out.Dimensions = append(out.Dimensions, toDimensionProto(row))
	}
	for _, d := range v.Divergences {
		out.Divergences = append(out.Divergences, &usagev1.UsageDivergence{
			Dimension:              wireDimension(d.Dimension),
			DataPlaneId:            d.DataPlaneID,
			ControlPlaneValue:      d.ControlPlaneValue,
			DataPlaneReportedValue: d.ReportedValue,
			WindowStart:            timestamppb.New(d.Window.Start),
			WindowEnd:              timestamppb.New(d.Window.End),
		})
	}
	// SPEC-0046 AC3: the end-to-end throttle observation rides the view only
	// once the tenant has an evaluation — absence stays absent on the wire.
	if v.Throttle.Present {
		obs := &usagev1.EnvelopeThrottleObservation{
			DesiredGeneration:       v.Throttle.DesiredGeneration,
			DesiredMaxCiConcurrency: v.Throttle.DesiredMaxCIConcurrency,
			DesiredQueueDepthCap:    v.Throttle.DesiredQueueDepthCap,
			HasAppliedAck:           v.Throttle.HasAppliedAck,
		}
		if v.Throttle.HasAppliedAck {
			obs.AppliedGeneration = v.Throttle.AppliedGeneration
			obs.Applied = v.Throttle.Applied
			obs.AppliedError = v.Throttle.AppliedError
			obs.AckedAt = timestamppb.New(v.Throttle.AckedAt)
		}
		out.EnvelopeThrottle = obs
	}
	return out
}

func toDimensionProto(row api.DimensionView) *usagev1.UsageDimensionView {
	out := &usagev1.UsageDimensionView{
		Dimension:         wireDimension(row.Dimension),
		Coverage:          wireCoverage(row.Coverage),
		State:             wireState(row.State),
		Unit:              row.Unit,
		TelemetryGap:      row.TelemetryGap,
		DeferredReason:    row.DeferredReason,
		EnvelopeValue:     row.Threshold.Envelope,
		NotificationValue: row.Threshold.Notify,
	}
	// Numeric fields are meaningful only when the dimension is metered and the
	// current interval is not a gap (AC2, AC3): a deferred row or a gap row
	// carries no number the UI could mistake for zero usage.
	if row.Coverage == api.CoverageMetered && !row.TelemetryGap {
		out.CurrentValue = row.Value
		out.WindowStart = timestamppb.New(row.Window.Start)
		out.WindowEnd = timestamppb.New(row.Window.End)
		// SPEC-0046 AC2: the trend is meaningful alongside the number it
		// describes — never on a deferred or gapped row.
		out.Trend = wireTrend(row.Trend)
	}
	for _, g := range row.Gaps {
		out.Gaps = append(out.Gaps, &usagev1.UsageGap{
			WindowStart: timestamppb.New(g.Start),
			WindowEnd:   timestamppb.New(g.End),
			Reason:      "no telemetry received",
		})
	}
	return out
}

func wireDimension(d api.Dimension) agentpb.FairUseDimension {
	switch d {
	case api.DimensionSeats:
		return agentpb.FairUseDimension_FAIR_USE_DIMENSION_SEATS
	case api.DimensionRepositoryCount:
		return agentpb.FairUseDimension_FAIR_USE_DIMENSION_REPOSITORY_COUNT
	case api.DimensionRepositoryStorage:
		return agentpb.FairUseDimension_FAIR_USE_DIMENSION_REPOSITORY_STORAGE
	case api.DimensionCIMinutes:
		return agentpb.FairUseDimension_FAIR_USE_DIMENSION_CI_MINUTES
	case api.DimensionCIConcurrency:
		return agentpb.FairUseDimension_FAIR_USE_DIMENSION_CI_CONCURRENCY
	case api.DimensionScanVolume:
		return agentpb.FairUseDimension_FAIR_USE_DIMENSION_SCAN_VOLUME
	case api.DimensionIndexSize:
		return agentpb.FairUseDimension_FAIR_USE_DIMENSION_INDEX_SIZE
	case api.DimensionEgress:
		return agentpb.FairUseDimension_FAIR_USE_DIMENSION_EGRESS
	default:
		return agentpb.FairUseDimension_FAIR_USE_DIMENSION_UNSPECIFIED
	}
}

func wireCoverage(c api.Coverage) usagev1.DimensionCoverage {
	switch c {
	case api.CoverageMetered:
		return usagev1.DimensionCoverage_DIMENSION_COVERAGE_METERED
	case api.CoverageDeferred:
		return usagev1.DimensionCoverage_DIMENSION_COVERAGE_DEFERRED
	default:
		return usagev1.DimensionCoverage_DIMENSION_COVERAGE_UNSPECIFIED
	}
}

func wireState(s api.State) agentpb.EnvelopeState {
	switch s {
	case api.StateWithin:
		return agentpb.EnvelopeState_ENVELOPE_STATE_WITHIN
	case api.StateNear:
		return agentpb.EnvelopeState_ENVELOPE_STATE_NEAR
	case api.StateExceeded:
		return agentpb.EnvelopeState_ENVELOPE_STATE_EXCEEDED
	default:
		return agentpb.EnvelopeState_ENVELOPE_STATE_UNSPECIFIED
	}
}

func wireTrend(tr api.Trend) usagev1.EnvelopeTrend {
	switch tr {
	case api.TrendRising:
		return usagev1.EnvelopeTrend_ENVELOPE_TREND_RISING
	case api.TrendFalling:
		return usagev1.EnvelopeTrend_ENVELOPE_TREND_FALLING
	case api.TrendFlat:
		return usagev1.EnvelopeTrend_ENVELOPE_TREND_FLAT
	default:
		return usagev1.EnvelopeTrend_ENVELOPE_TREND_UNSPECIFIED
	}
}
