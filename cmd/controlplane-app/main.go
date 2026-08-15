// Command controlplane-app is the single control-plane binary (invariant 19).
//
// Doors this binary can open:
//   - the health door (always),
//   - the AgentGateway door (T-0030, SPEC-0038, ADR-0060) when GITFROK_AGENT_GRPC_ADDR is
//     set: one outbound bidi stream per data plane, bootstrapped by a one-time enrolment
//     token and authenticated thereafter by control-plane-issued, on-channel-rotated
//     client certificates,
//   - the UsageService door (T-0034, SPEC-0041) when GITFROK_USAGE_GRPC_ADDR is set: the
//     tenant's fair-use usage view, read from the counters the control plane derives from
//     telemetry it RECEIVES on the agent channel (ADR-0061),
//   - the EnrolmentService door (SPEC-0038 AC1) when GITFROK_ENROLMENT_GRPC_ADDR is set:
//     the operator-facing issuance door that mints the one-time token Enrol presents on a
//     data plane's first Connect, PAT-verified before any policy decision, mirroring the
//     residency Declare door (SPEC-0043, ADR-0063).
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
	residencyv1 "github.com/gitfrok/backend/gen/proto/residency/v1"
	usagev1 "github.com/gitfrok/backend/gen/proto/usage/v1"
	"github.com/gitfrok/backend/modules/agent"
	"github.com/gitfrok/backend/modules/audit"
	auditapi "github.com/gitfrok/backend/modules/audit/api"
	"github.com/gitfrok/backend/modules/identity"
	identityapi "github.com/gitfrok/backend/modules/identity/api"
	"github.com/gitfrok/backend/modules/metering"
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
	server    *ggrpc.Server
	usage     *ggrpc.Server // the UsageService door, when GITFROK_USAGE_GRPC_ADDR is set
	residency *ggrpc.Server // the residency Declare door, when GITFROK_RESIDENCY_GRPC_ADDR is set
	enrolment *ggrpc.Server // the enrolment issuance door, when GITFROK_ENROLMENT_GRPC_ADDR is set
	pool      *db.Pool
	// releaseStop ends the release trust bundle's staging-directory reconcile
	// loop with the door (T-0041, SPEC-0045 AC2). nil when distribution is
	// not configured.
	releaseStop chan struct{}
}

func (d *agentDoor) close() {
	if d.releaseStop != nil {
		close(d.releaseStop)
	}
	d.server.Stop()
	if d.usage != nil {
		d.usage.Stop()
	}
	if d.residency != nil {
		d.residency.Stop()
	}
	if d.enrolment != nil {
		d.enrolment.Stop()
	}
	if d.pool != nil {
		d.pool.Close()
	}
}

// startAgentDoor composes and starts the gateway. Every failure here fails the rollout —
// a gateway that starts half-wired would refuse enrolments later as an unexplained outage.
func startAgentDoor(cfg agentConfig, mcfg meteringConfig) (*agentDoor, error) {
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

	// CA custody (T-0040, SPEC-0044, ADR-0066): the agent door issues every
	// identity credential through the custody-backed issuer — OpenBao transit
	// keys the control plane signs digests with and never sees. The dev CA is
	// reachable ONLY from dev/test compositions; this root reads the custody
	// posture from the environment and fails the rollout without it (AC1/AC3
	// fitness in internal/arch keeps it that way).
	custodyCfg, err := loadCustodyConfig(os.Getenv)
	if err != nil {
		if pool != nil {
			pool.Close()
		}
		return nil, err
	}
	custodyCfg.Logf = logf // the re-attach branch must log loudly on the process log
	ca, err := agent.NewCustodyCA(custodyCfg)
	if err != nil {
		if pool != nil {
			pool.Close()
		}
		return nil, fmt.Errorf("agent ca custody: %w", err)
	}

	// The store selection mirrors the audit-trail branch above: with
	// GITFROK_DATABASE_URL the agent's enrolment state is durable — a spent
	// token stays spent across a kill-and-restart, staleness reads durable
	// liveness (T-0036, SPEC-0042 AC1/AC2). Without it the dev/test
	// in-memory composition stays the default (ADR-0062 decision 1).
	var svc *agent.Service
	var stores *agent.PostgresStores
	if pool != nil {
		stores = agent.NewPostgresStores(pool)
		svc = agent.NewWithStores(pdp, b, ca, stores, stores, cfg.enrolment, logf)
	} else {
		svc = agent.New(pdp, b, ca, cfg.enrolment, logf)
	}

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
	residencyCfg := residencyapi.Config{
		DetectionWindow:   residencyDuration(os.Getenv, residencyDetectionWindowEnv),
		MaxReportInterval: residencyDuration(os.Getenv, residencyReportIntervalEnv),
		Now:               time.Now,
	}
	// The store selection mirrors the agent-stores branch above: with
	// GITFROK_DATABASE_URL declarations are durable — a declaration made
	// before a kill-and-restart is exactly what the restarted plane cites,
	// and retained effective-dated history answers "in force at t"
	// (T-0037, SPEC-0042 AC3). Without it the dev/test in-memory
	// composition stays the default (ADR-0062 decision 1).
	var residencySvc *residency.Service
	if pool != nil {
		residencySvc = residency.NewWithStore(pdp, residencyTrailWitness{trail}, residency.NewPostgresStore(pool), residencyCfg, logf)
	} else {
		residencySvc = residency.New(pdp, residencyTrailWitness{trail}, residencyCfg, logf)
	}
	if !agent.AttachPlacementGate(svc, residencyPlacementGate{svc: residencySvc}) {
		if pool != nil {
			pool.Close()
		}
		return nil, fmt.Errorf("agent surface has no placement gate sink: residency cannot be composed")
	}

	gateway := agent.NewGRPCServer(svc, time.Second, time.Now, logf)

	// Rotation distribution (SPEC-0044 AC2): every advance of the custody
	// bundle's staged state — a staged root, a completed removal — is
	// delivered to each stream as DesiredState.ca_trust_bundle.
	agent.AttachCATrustBundle(gateway, ca.Bundle())

	// Release trust distribution (T-0041, SPEC-0045 AC2, ADR-0065 decision 2):
	// the versioned RELEASE trust bundle — the cosign release-signing keys of
	// ADR-0044 — rides the same reconcile channel on its OWN desired-state
	// field (release_trust_bundle), composed strictly apart from the CA bundle
	// above: different config, different snapshot file, different wire field.
	// Unconfigured is an honest absence: the additive field stays empty and
	// the door logs it loudly — never an accidental empty-bundle distribution.
	var releaseStop chan struct{}
	releaseCfg, err := loadReleaseTrustConfig(os.Getenv)
	if err != nil {
		if pool != nil {
			pool.Close()
		}
		return nil, err
	}
	if releaseCfg.enabled {
		rtb, err := agent.NewReleaseTrustBundle(agent.ReleaseTrustBundleConfig{
			SnapshotFile: releaseCfg.snapshotFile,
			SeedKeyID:    releaseCfg.seedID,
			SeedPEMFile:  releaseCfg.seedPEMFile,
			Now:          time.Now,
			Logf:         logf,
		})
		if err != nil {
			if pool != nil {
				pool.Close()
			}
			return nil, err
		}
		agent.AttachReleaseTrustBundle(gateway, rtb)
		// The applied registry records, keyed by data_plane_id, the bundle
		// revision each plane acked. Durable whenever the plane's stores are;
		// absent in the dev in-memory composition (the gateway tolerates no
		// registry).
		if stores != nil {
			agent.AttachReleaseTrustApplied(gateway, stores)
		}
		// The staged-key actuation seam: the staging directory declares the
		// desired live key set and this loop converges the bundle toward it.
		// A first pass that fails fails the rollout — a configured staging
		// directory that cannot be read or holds unparseable material is a
		// configuration error, not a runtime surprise; later passes log loudly
		// and retry, because a mid-write declaration is legitimately transient.
		if releaseCfg.stagingDir != "" {
			if err := rtb.ReconcileDir(releaseCfg.stagingDir); err != nil {
				if pool != nil {
					pool.Close()
				}
				return nil, fmt.Errorf("release trust staging directory %q is unusable at startup: %w", releaseCfg.stagingDir, err)
			}
			releaseStop = make(chan struct{})
			go func() {
				ticker := time.NewTicker(releaseCfg.reconcileEvery)
				defer ticker.Stop()
				for {
					select {
					case <-releaseStop:
						return
					case <-ticker.C:
						if err := rtb.ReconcileDir(releaseCfg.stagingDir); err != nil {
							logf("release trust: staging reconcile %q failed: %v — retried every %s", releaseCfg.stagingDir, err, releaseCfg.reconcileEvery)
						}
					}
				}
			}()
		}
		logf("release trust bundle: distribution ENABLED (snapshot %s, seed %s, staging dir %q)",
			releaseCfg.snapshotFile, orNone(releaseCfg.seedID), orNone(releaseCfg.stagingDir))
	} else {
		logf("release trust bundle: distribution NOT CONFIGURED (%s unset) — DesiredState.release_trust_bundle stays empty",
			releaseTrustSnapshotFileEnv)
	}

	// Metering composition (T-0034, SPEC-0041, ADR-0061): the control plane counts from
	// the telemetry it RECEIVES on the agent channel. The gateway forwards every
	// TelemetrySample and UsageSample to the sink and polls the newest envelope desired
	// state for delivery (AC9); the counters live in the metering context, and the same
	// ledger feeds the UsageService door below (AC10). A breach only throttles CI and
	// notifies — it never touches git (AC7) and never bills (ADR-0008).
	meteringSvc := metering.New(pdp, metering.LogNotifier{Logf: logf}, b, mcfg.cfg, logf)
	agent.AttachMetering(gateway, meteringSvc, meteringSvc)

	// The UsageService door the BFF calls for the tenant's usage view. Dev posture is
	// plaintext, exactly like the data plane's policy door; plane-to-plane mTLS is the
	// same T-0013 follow-up named there.
	var usageServer *ggrpc.Server
	if mcfg.usageAddr != "" {
		lis, err := net.Listen("tcp", mcfg.usageAddr)
		if err != nil {
			if pool != nil {
				pool.Close()
			}
			return nil, fmt.Errorf("usage service listen %s: %w", mcfg.usageAddr, err)
		}
		usageServer = ggrpc.NewServer()
		usagev1.RegisterUsageServiceServer(usageServer, metering.NewGRPCServer(meteringSvc))
		go func() {
			if serveErr := usageServer.Serve(lis); serveErr != nil {
				logf("usage service stopped: %v", serveErr)
			}
		}()
		fmt.Printf("controlplane-app: UsageService listening on %s\n", mcfg.usageAddr)
	}

	// The residency Declare admin door (T-0038, SPEC-0043, ADR-0063). It mirrors the
	// UsageService door's registration, but differs in one deliberate way: the door
	// verifies its caller through the identity seam BEFORE any policy decision — the
	// subject is a PAT-resolved principal carried in the request context, never a
	// wire claim (SPEC-0043 AC6). The verifier key is required when the door is
	// open (loadResidencyDoorConfig), and the authenticator is durable whenever the
	// plane's stores are: it resolves the credential against the same identity
	// schema the data plane issues from (ADR-0043's narrow gateway).
	rcfg, err := loadResidencyDoorConfig(os.Getenv)
	if err != nil {
		if pool != nil {
			pool.Close()
		}
		return nil, err
	}
	var residencyServer *ggrpc.Server
	if rcfg.addr != "" {
		var authenticator identityapi.Authenticator
		if pool != nil {
			authenticator = identity.NewPostgres(pool, "default", map[string][]byte{"default": rcfg.patKey}, pdp)
		} else {
			authenticator = identity.NewInMemory(rcfg.patKey, pdp)
		}
		lis, err := net.Listen("tcp", rcfg.addr)
		if err != nil {
			if pool != nil {
				pool.Close()
			}
			return nil, fmt.Errorf("residency service listen %s: %w", rcfg.addr, err)
		}
		residencyServer = ggrpc.NewServer()
		residencyv1.RegisterResidencyServiceServer(residencyServer, residency.NewGRPCServer(residencySvc, authenticator, logf))
		go func() {
			if serveErr := residencyServer.Serve(lis); serveErr != nil {
				logf("residency service stopped: %v", serveErr)
			}
		}()
		fmt.Printf("controlplane-app: ResidencyService listening on %s\n", rcfg.addr)
	}

	// The operator enrolment-token issuance door (SPEC-0038 AC1). It mirrors the
	// residency Declare door above in every boundary property: the door verifies
	// its caller through the identity seam BEFORE any policy decision — tenant and
	// actor are properties of the PAT-resolved principal carried in the request
	// context, never wire claims (ADR-0045) — and it serves EnrolmentService over
	// the same narrow gateway posture. The verifier key is required when the door
	// is open (loadEnrolmentDoorConfig), and the authenticator is durable whenever
	// the plane's stores are. The issued secret exists in exactly one response
	// (AC2): the domain stores only its hash.
	ecfg, err := loadEnrolmentDoorConfig(os.Getenv)
	if err != nil {
		if pool != nil {
			pool.Close()
		}
		return nil, err
	}
	var enrolmentServer *ggrpc.Server
	if ecfg.addr != "" {
		var enrolmentAuth identityapi.Authenticator
		if pool != nil {
			enrolmentAuth = identity.NewPostgres(pool, "default", map[string][]byte{"default": ecfg.patKey}, pdp)
		} else {
			enrolmentAuth = identity.NewInMemory(ecfg.patKey, pdp)
		}
		lis, err := net.Listen("tcp", ecfg.addr)
		if err != nil {
			if pool != nil {
				pool.Close()
			}
			return nil, fmt.Errorf("enrolment service listen %s: %w", ecfg.addr, err)
		}
		enrolmentServer = ggrpc.NewServer()
		agentv1.RegisterEnrolmentServiceServer(enrolmentServer, agent.NewEnrolmentDoor(svc, enrolmentAuth, logf))
		go func() {
			if serveErr := enrolmentServer.Serve(lis); serveErr != nil {
				logf("enrolment service stopped: %v", serveErr)
			}
		}()
		fmt.Printf("controlplane-app: EnrolmentService listening on %s\n", ecfg.addr)
	}

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
	fmt.Printf("controlplane-app: AgentGateway listening on %s (custody-backed CA)\n", cfg.grpcAddr)
	return &agentDoor{server: server, usage: usageServer, residency: residencyServer, enrolment: enrolmentServer, pool: pool, releaseStop: releaseStop}, nil
}

// orNone renders a configuration value for a log line: the value itself, or
// the word none — an unset optional is a posture, named as one.
func orNone(v string) string {
	if v == "" {
		return "none"
	}
	return v
}

func main() {
	agentCfg, err := loadAgentConfig(os.Getenv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "controlplane agent configuration: %v\n", err)
		os.Exit(1)
	}
	meteringCfg, err := loadMeteringConfig(os.Getenv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "controlplane metering configuration: %v\n", err)
		os.Exit(1)
	}
	if agentCfg.grpcAddr != "" {
		door, err := startAgentDoor(agentCfg, meteringCfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "controlplane agent gateway: %v\n", err)
			os.Exit(1)
		}
		defer door.close()
	} else if meteringCfg.usageAddr != "" {
		// The usage view reads counters derived from telemetry the agent channel
		// delivers: without the agent door there is no telemetry, and a usage door
		// that can only render gaps is a misconfiguration, not a feature.
		fmt.Fprintf(os.Stderr, "%s is set but %s is not: the usage view needs the agent channel\n",
			usageGRPCAddrEnv, agentGRPCAddrEnv)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := health.Run(ctx, health.ListenAddr(os.Getenv(listenAddrEnv))); err != nil {
		fmt.Fprintf(os.Stderr, "controlplane health server: %v\n", err)
		os.Exit(1)
	}
}
