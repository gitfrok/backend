// Package metering is the Metering context's composition root (T-0034, SPEC-0041,
// ADR-0061): authoritative fair-use counters derived from telemetry RECEIVED over the
// agent channel, envelope evaluation with throttle-and-notify enforcement, and the
// customer-visible usage view.
//
// cmd/ builds the context here and never names a package under internal/ (ADR-0025).
// The store is a port; swapping the in-memory one for Postgres is a composition-line
// change (invariant 13). The Service is BOTH halves of the surface — the agent
// channel's Sink and the usage door's Reader — because they share one ledger: the
// customer and the control plane read the same counters (SPEC-0041 AC10).
package metering

import (
	"context"

	"github.com/gitfrok/backend/modules/metering/api"
	"github.com/gitfrok/backend/modules/metering/internal/adapters/grpc"
	"github.com/gitfrok/backend/modules/metering/internal/adapters/memory"
	"github.com/gitfrok/backend/modules/metering/internal/app"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
	"github.com/gitfrok/backend/platform/bus"
)

// Service is the composed context, aliased so cmd/ can hold it without naming a package
// under this module's internal/ tree.
type Service = app.Service

// GRPCServer is the module's usage door (UsageService), aliased for the same reason.
type GRPCServer = grpc.Server

// Sink is the ingestion port the agent channel forwards every TelemetrySample and
// UsageSample it RECEIVES to, aliased for the composition's convenience.
type Sink = api.Sink

// Reader is the usage-view half of the surface the gRPC door serves, aliased for the
// same reason.
type Reader = api.Reader

// EnvelopeDelivery is the AC9 seam the agent channel polls, aliased for the same reason.
type EnvelopeDelivery = api.EnvelopeDelivery

// New builds the context on the in-memory store with a notifier, the platform bus and
// the policy decision point. A durable store is future work; the store is a port, so
// that is a composition-line change (invariant 13).
func New(pdp policyapi.DecisionPoint, notifier api.Notifier, events bus.Bus, cfg api.Config, logf func(format string, args ...any)) *Service {
	return app.New(memory.New(), notifier, events, pdp, cfg, logf)
}

// NewGRPCServer adapts the Reader port to the UsageService contract the BFF calls.
func NewGRPCServer(reader api.Reader) *GRPCServer {
	return grpc.NewServer(reader)
}

// LogNotifier is the dev posture for the AC4 out-of-band half: each notice is
// written as coarse prose to the platform log. A real transport (email to the
// platform engineer) is a composition-line swap; the context cannot tell the
// difference (invariant 13).
type LogNotifier struct {
	Logf func(format string, args ...any)
}

// Notify writes one notice as coarse prose: dimension, state, value, threshold.
func (n LogNotifier) Notify(_ context.Context, notice api.Notice) error {
	n.Logf("metering notice: tenant=%s dimension=%s state=%s value=%g threshold=%g trend=%s",
		notice.TenantID, notice.Dimension, notice.State, notice.Value, notice.Threshold, notice.Trend)
	return nil
}
