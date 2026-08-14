// Command controlplane-app is the single control-plane binary (invariant 19).
//
// Doors this binary can open:
//   - the health door (always),
//   - the AgentGateway door (T-0030, SPEC-0038, ADR-0060) when GITFROK_AGENT_GRPC_ADDR is
//     set: one outbound bidi stream per data plane, bootstrapped by a one-time enrolment
//     token and authenticated thereafter by control-plane-issued, on-channel-rotated
//     client certificates.
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gitfrok/backend/cmd/internal/health"
	agentv1 "github.com/gitfrok/backend/gen/proto/agent/v1"
	"github.com/gitfrok/backend/modules/agent"
	"github.com/gitfrok/backend/modules/audit"
	auditapi "github.com/gitfrok/backend/modules/audit/api"
	"github.com/gitfrok/backend/modules/policy"
	"github.com/gitfrok/backend/modules/residency"
	residencyapi "github.com/gitfrok/backend/modules/residency/api"
	"github.com/gitfrok/backend/platform/auditsink"
	"github.com/gitfrok/backend/platform/bus"
	"github.com/gitfrok/backend/platform/db"
	ggrpc "google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	listenAddrEnv = "GITFROK_LISTEN_ADDR"

	// policyBundleDirEnv names the directory holding the OPA bundle from
	// governance/policies. Per-environment configuration, never a compiled-in path
	// (invariant 13); the backend does not embed the bundle (invariant 21).
	policyBundleDirEnv = "GITFROK_POLICY_BUNDLE_DIR"

	// databaseURLEnv is the tenant-scoped application DSN. When set, the plane persists
	// its audit events onto the Postgres trail (ADR-0007 composition).
	databaseURLEnv = "GITFROK_DATABASE_URL"
)

// agentDoor is one running AgentGateway listener and everything it was composed from.
type agentDoor struct {
	server *ggrpc.Server
	pool   *db.Pool
}

func (d *agentDoor) close() {
	d.server.Stop()
	if d.pool != nil {
		d.pool.Close()
	}
}

// startAgentDoor composes and starts the gateway. Every failure here fails the rollout —
// a gateway that starts half-wired would refuse enrolments later as an unexplained outage.
func startAgentDoor(cfg agentConfig) (*agentDoor, error) {
	bundleDir := os.Getenv(policyBundleDirEnv)
	if bundleDir == "" {
		return nil, fmt.Errorf("%s is not set: every operator action on the agent surface "+
			"needs a policy decision (ADR-0006, invariant 2)", policyBundleDirEnv)
	}

	b := bus.NewInProcess()

	// The audit sink is per-environment: with GITFROK_DATABASE_URL the agent lifecycle's
	// audit events persist onto the Postgres trail; without it they are published and
	// dropped. A configured sink that cannot write is never silent.
	var pool *db.Pool
	if dsn := os.Getenv(databaseURLEnv); dsn != "" {
		p, err := db.Open(context.Background(), dsn)
		if err != nil {
			return nil, fmt.Errorf("audit database: %w", err)
		}
		auditsink.NewSink(p, b).Subscribe(b)
		pool = p
	}

	pdp, err := policy.NewOPADecisionPoint(bundleDir, b)
	if err != nil {
		if pool != nil {
			pool.Close()
		}
		return nil, fmt.Errorf("policy bundle at %s is unusable: %w", bundleDir, err)
	}

	logf := func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, "controlplane agent: "+format+"\n", args...)
	}

	// DEV/TEST CA custody: a fresh in-process key per start. Production custody is an
	// ADR-0057 follow-up and is deliberately NOT decided by this line.
	ca, err := agent.NewDevCA("gitfrok-control-plane-agent-ca", time.Now)
	if err != nil {
		return nil, fmt.Errorf("agent ca: %w", err)
	}

	svc := agent.New(pdp, b, ca, cfg.enrolment, logf)

	// Residency composition (T-0033, SPEC-0040): the witnessed placement facts the
	// evidence pack's residency section cites live on the tenant's audit trail. With
	// GITFROK_DATABASE_URL the residency witness writes the Postgres trail the audit
	// sink above feeds; without it an in-memory trail fed from the same bus. The gate
	// is attached post-construction (the Attach* pattern): a surface this binary
	// cannot attach it to fails the rollout rather than admitting placements
	// unwitnessed.
	var trail auditapi.TrailStore
	if pool != nil {
		trail = audit.NewPostgresTrail(pool)
	} else {
		trail = audit.NewMemoryTrail()
		auditsink.NewLogSink(trail).Subscribe(b)
	}
	residencySvc := residency.New(pdp, residencyTrailWitness{trail}, residencyapi.Config{
		DetectionWindow:   residencyDuration(os.Getenv, residencyDetectionWindowEnv),
		MaxReportInterval: residencyDuration(os.Getenv, residencyReportIntervalEnv),
		Now:               time.Now,
	}, logf)
	if !agent.AttachPlacementGate(svc, residencyPlacementGate{svc: residencySvc}) {
		if pool != nil {
			pool.Close()
		}
		return nil, fmt.Errorf("agent surface has no placement gate sink: residency cannot be composed")
	}

	gateway := agent.NewGRPCServer(svc, time.Second, time.Now, logf)

	serverCert, err := ca.IssueServer("agent-gateway", cfg.serverNames, time.Now(), 24*time.Hour)
	if err != nil {
		return nil, fmt.Errorf("agent gateway server certificate: %w", err)
	}
	lis, err := net.Listen("tcp", cfg.grpcAddr)
	if err != nil {
		return nil, fmt.Errorf("agent gateway listen %s: %w", cfg.grpcAddr, err)
	}
	server := ggrpc.NewServer(ggrpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{serverCert},
		// The TLS layer CARRIES client certificates without verifying them: admission —
		// chain, expiry, registration, revocation — is the app layer's decision because
		// every refusal must leave an audit record (SPEC-0038 AC5, AC7).
		ClientAuth: tls.RequestClientCert,
	})))
	agentv1.RegisterAgentGatewayServer(server, gateway)
	go func() {
		if serveErr := server.Serve(lis); serveErr != nil {
			logf("agent gateway stopped: %v", serveErr)
		}
	}()
	fmt.Printf("controlplane-app: AgentGateway listening on %s (dev CA custody)\n", cfg.grpcAddr)
	return &agentDoor{server: server, pool: pool}, nil
}

func main() {
	agentCfg, err := loadAgentConfig(os.Getenv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "controlplane agent configuration: %v\n", err)
		os.Exit(1)
	}
	if agentCfg.grpcAddr != "" {
		door, err := startAgentDoor(agentCfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "controlplane agent gateway: %v\n", err)
			os.Exit(1)
		}
		defer door.close()
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := health.Run(ctx, health.ListenAddr(os.Getenv(listenAddrEnv))); err != nil {
		fmt.Fprintf(os.Stderr, "controlplane health server: %v\n", err)
		os.Exit(1)
	}
}
