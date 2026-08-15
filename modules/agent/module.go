// Package agent is the Agent context's composition root (T-0030, SPEC-0038, ADR-0060):
// enrolment tokens, the first-Connect handshake, certificate issuance and on-channel
// rotation, connection admission, the data-plane registry and the operator surface.
//
// cmd/ builds the context here and never names a package under internal/ (ADR-0025).
// Swapping stores or the certificate issuer is a change to a composition line, not to the
// context.
package agent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/gitfrok/backend/modules/agent/api"
	"github.com/gitfrok/backend/modules/agent/internal/adapters/custody"
	agentgrpc "github.com/gitfrok/backend/modules/agent/internal/adapters/grpc"
	"github.com/gitfrok/backend/modules/agent/internal/adapters/memory"
	"github.com/gitfrok/backend/modules/agent/internal/adapters/pki"
	agentpg "github.com/gitfrok/backend/modules/agent/internal/adapters/postgres"
	"github.com/gitfrok/backend/modules/agent/internal/app"
	meteringapi "github.com/gitfrok/backend/modules/metering/api"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
	"github.com/gitfrok/backend/platform/bus"
	"github.com/gitfrok/backend/platform/db"
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

// CustodyCA is the production certificate issuer: a custody-backed Issuer
// whose roots live in the custody service and whose private halves never
// enter this process (T-0040, SPEC-0044, ADR-0066). Aliased so cmd/ can
// hold one without naming a package under internal/.
type CustodyCA = custody.Issuer

// TokenStore and RegistryStore are the persistence ports, aliased so cmd/ can
// name them without reaching into internal/.
type (
	TokenStore    = app.TokenStore
	RegistryStore = app.RegistryStore
)

// New builds the context on the in-memory stores: the dev/test default
// (ADR-0062 decision 1 — the fakes stay as test doubles, never as the
// production path). A deployment that wants enrolment state to outlive the
// process composes NewWithStores with NewPostgresStores instead.
// The certificate issuer is injected: dev/test compositions pass NewDevCA,
// production compositions pass NewCustodyCA, and the context cannot tell
// the difference.
func New(pdp policyapi.DecisionPoint, events bus.Bus, issuer api.CertificateIssuer, cfg api.Config, logf func(format string, args ...any)) *Service {
	return app.New(pdp, events, issuer, memory.New(), memory.New(), cfg, logf)
}

// NewWithStores builds the context on caller-supplied stores (T-0036,
// SPEC-0042): with NewPostgresStores, a spent token stays spent across a
// kill-and-restart and the registry's staleness machine reads durable
// liveness — enrolment state becomes a property of the platform, not of the
// process (ADR-0062).
func NewWithStores(pdp policyapi.DecisionPoint, events bus.Bus, issuer api.CertificateIssuer, tokens TokenStore, registry RegistryStore, cfg api.Config, logf func(format string, args ...any)) *Service {
	return app.New(pdp, events, issuer, tokens, registry, cfg, logf)
}

// NewPostgresStores returns the durable token store and data-plane registry
// over pool. One value fills both ports: both halves live in one migration,
// one schema and one isolation story.
func NewPostgresStores(pool *db.Pool) *agentpg.Store {
	return agentpg.New(pool)
}

// NewDevCA generates the DEV/TEST control-plane CA: an in-process key that never leaves
// the process. It is reachable ONLY from dev/test compositions — the production
// composition root constructs the custody-backed issuer (NewCustodyCA) and is
// fitness-tested to reach neither this constructor nor any key-material parser
// (SPEC-0044 AC1, AC3).
func NewDevCA(commonName string, now func() time.Time) (*DevCA, error) {
	return pki.NewDevCA(commonName, now)
}

// CustodyCAConfig wires the production certificate issuer (T-0040, SPEC-0044,
// ADR-0066): the OpenBao custody service's address and transit mount, the
// Kubernetes-auth role the control plane logs in with (its projected
// service-account JWT, zero static credentials), and the bootstrap key name.
// Every value is per-environment configuration supplied by cmd/ (invariant
// 13); construction contacts nothing.
type CustodyCAConfig struct {
	OpenBaoAddress    string
	TransitMount      string // empty means "transit"
	KubernetesRole    string
	JWTFile           string // empty means the standard in-cluster projection
	KeyName           string // the bundle's first root key; empty means "agent-ca"
	AllowHTTPLoopback bool   // dev port-forward only; production never sets it
	// SnapshotFile is where the bundle's durable state lives — a file on the
	// control plane's own filesystem (Wave-3 review C1). The snapshot is a
	// tenant-less platform singleton, so no tenant-isolated store can carry
	// it honestly; a dedicated operator-configured path is its home. Required:
	// a custody CA with nowhere to persist its window crash-loops on restart.
	SnapshotFile string
	// Logf receives the composition's loud log lines — notably the re-attach
	// branch, which must never pass silently.
	Logf func(format string, args ...any)
	Now  func() time.Time
}

// NewCustodyCA builds the custody-backed issuer: an OpenBao transit signer
// authenticating via Kubernetes auth, one staged trust bundle over
// cfg.KeyName, and the Issuer over it. Failures fail the rollout — a
// gateway that starts half-wired would refuse enrolments later as an
// unexplained outage.
//
// The bundle is composed restart-proof (Wave-3 review C1): a persisted
// snapshot restores the window exactly; without one the bundle bootstraps;
// and a bootstrap that finds the key ALREADY held by custody re-attaches by
// the key's public half — fresh revision, loudly logged — instead of
// failing the rollout or staging a divergent root. Every state change is
// persisted through the bundle's change hook, so a restart always finds the
// newest window state the fleet saw.
func NewCustodyCA(cfg CustodyCAConfig) (*CustodyCA, error) {
	if cfg.OpenBaoAddress == "" {
		return nil, errors.New("agent custody: OpenBao address is required")
	}
	if cfg.SnapshotFile == "" {
		return nil, errors.New("agent custody: snapshot file path is required: the bundle's durable state " +
			"must survive a control-plane restart, and an issuer with nowhere to persist it would crash-loop on one")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	signer, err := custody.NewOpenBao(custody.Config{
		Address: cfg.OpenBaoAddress,
		Mount:   cfg.TransitMount,
		Token: custody.KubernetesAuth{
			Address:                cfg.OpenBaoAddress,
			Role:                   cfg.KubernetesRole,
			JWTFile:                cfg.JWTFile,
			AllowHTTPForLocalTests: cfg.AllowHTTPLoopback,
		},
		AllowHTTPForLocalTests: cfg.AllowHTTPLoopback,
	})
	if err != nil {
		return nil, fmt.Errorf("agent custody: %w", err)
	}
	return newCustodyCA(cfg, signer)
}

// newCustodyCA composes the issuer over an already-built signer — the seam
// the composition tests exercise with the CI custody service, exactly as the
// production path runs over OpenBao.
func newCustodyCA(cfg CustodyCAConfig, signer custody.Signer) (*CustodyCA, error) {
	store, err := custody.NewFileSnapshotStore(cfg.SnapshotFile)
	if err != nil {
		return nil, fmt.Errorf("agent custody: %w", err)
	}
	name := cfg.KeyName
	if name == "" {
		name = "agent-ca"
	}
	issuer, err := custody.ComposeIssuer(context.Background(), signer, store, name, cfg.Now, cfg.Logf)
	if err != nil {
		return nil, fmt.Errorf("agent custody: compose %q: %w", name, err)
	}
	return issuer, nil
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

// AttachCATrustBundle wires the custody rotation seam onto an established
// gateway (T-0040, SPEC-0044 AC2): every advance of the bundle's revision is
// delivered to each stream as DesiredState.ca_trust_bundle. Post-construction
// like the other seams, so a surface this binary cannot attach fails the
// rollout rather than silently withholding rotation state.
func AttachCATrustBundle(srv *GRPCServer, source api.CATrustBundleSource) {
	srv.AttachCATrustBundle(source)
}
