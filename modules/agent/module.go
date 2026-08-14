// Package agent is the Agent context's composition root (T-0030, SPEC-0038, ADR-0060):
// enrolment tokens, the first-Connect handshake, certificate issuance and on-channel
// rotation, connection admission, the data-plane registry and the operator surface.
//
// cmd/ builds the context here and never names a package under internal/ (ADR-0025).
// Swapping stores or the certificate issuer is a change to a composition line, not to the
// context.
package agent

import (
	"time"

	"github.com/gitfrok/backend/modules/agent/api"
	agentgrpc "github.com/gitfrok/backend/modules/agent/internal/adapters/grpc"
	"github.com/gitfrok/backend/modules/agent/internal/adapters/memory"
	"github.com/gitfrok/backend/modules/agent/internal/adapters/pki"
	"github.com/gitfrok/backend/modules/agent/internal/app"
	meteringapi "github.com/gitfrok/backend/modules/metering/api"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
	"github.com/gitfrok/backend/platform/bus"
)

// Service is the composed context, aliased so cmd/ can hold it without naming a package
// under this module's internal/ tree. It is both halves of the surface: api.Gateway for
// the agent channel and api.Operator for the operator door.
type Service = app.Service

// GRPCServer is the module's gRPC door (AgentGateway), aliased for the same reason.
type GRPCServer = agentgrpc.Gateway

// DevCA is the dev/test certificate issuer, aliased so cmd/ can hold one and hand its
// trust pool to the TLS configuration.
type DevCA = pki.DevCA

// New builds the context on the in-memory stores. A Postgres adapter is future work; the
// stores are ports, so that is a composition-line change (invariant 13 of the module).
// The certificate issuer is injected: dev/test compositions pass NewDevCA, a custody-backed
// issuer is an ADR-0057 follow-up, and the context cannot tell the difference.
func New(pdp policyapi.DecisionPoint, events bus.Bus, issuer api.CertificateIssuer, cfg api.Config, logf func(format string, args ...any)) *Service {
	return app.New(pdp, events, issuer, memory.New(), memory.New(), cfg, logf)
}

// NewDevCA generates the DEV/TEST control-plane CA: an in-process key that never leaves
// the process. Production key custody is deliberately undecided (ADR-0057 follow-up) —
// this constructor is not a custody mechanism, only the absence-of-one for dev.
func NewDevCA(commonName string, now func() time.Time) (*DevCA, error) {
	return pki.NewDevCA(commonName, now)
}

// AttachPlacementGate wires the residency placement gate the enrolment path consults
// before a data plane joins its tenant's fleet (T-0033, SPEC-0040 AC2). Post-construction
// because the Residency context is composed after the agent surface; the gate is a port
// in this context's own terms, so the module graph stays acyclic (invariant 14). It
// reports false when the surface has no gate sink to attach to.
func AttachPlacementGate(svc *Service, gate api.PlacementGate) bool {
	type gateSink interface{ SetPlacementGate(api.PlacementGate) }
	sink, ok := any(svc).(gateSink)
	if !ok {
		return false
	}
	sink.SetPlacementGate(gate)
	return true
}

// NewGRPCServer adapts the Gateway port to the AgentGateway contract. poll bounds how late
// a lapsed certificate can go unnoticed; one second is ample for hour-long certificates.
func NewGRPCServer(gw api.Gateway, poll time.Duration, now func() time.Time, logf func(format string, args ...any)) *GRPCServer {
	return agentgrpc.NewGateway(gw, poll, now, logf)
}

// AttachMetering wires the metering seams onto an established gateway (T-0034,
// SPEC-0041): every TelemetrySample and UsageSample the stream RECEIVES is forwarded to
// the sink, and the newest envelope desired state is delivered and acknowledged (AC9).
// Post-construction because the Metering context is composed after the agent surface;
// both seams are ports in the metering context's own terms, so the module graph stays
// acyclic (invariant 14).
func AttachMetering(srv *GRPCServer, sink meteringapi.Sink, envelopes meteringapi.EnvelopeDelivery) {
	srv.AttachTelemetrySink(sink)
	srv.AttachEnvelopeDelivery(envelopes)
}
