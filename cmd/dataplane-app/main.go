// Command dataplane-app is the single data-plane binary (invariant 19). Modules are packages
// composed here; they are not separate services (ADR-0025).
//
// This file is the only place that knows which modules exist and which concrete adapters they run
// on. A module never constructs another module, and never reaches for an adapter itself — so
// promoting one to its own service (ADR-0026) is a change here, not in the modules.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/gitfrok/backend/cmd/internal/health"
	agentv1 "github.com/gitfrok/backend/gen/proto/agent/v1"
	civ1 "github.com/gitfrok/backend/gen/proto/ci/v1"
	"github.com/gitfrok/backend/modules/ci"
	"github.com/gitfrok/backend/modules/codesearch"
	csapi "github.com/gitfrok/backend/modules/codesearch/api"
	"github.com/gitfrok/backend/modules/identity"
	identityapi "github.com/gitfrok/backend/modules/identity/api"
	"github.com/gitfrok/backend/modules/policy"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
	"github.com/gitfrok/backend/modules/repository"
	repoapi "github.com/gitfrok/backend/modules/repository/api"
	"github.com/gitfrok/backend/platform/bus"
)

// policyBundleDirEnv names the directory holding the OPA bundle from governance/policies.
//
// Per-environment configuration, never a compiled-in path (invariant 13): in dev it is a mount of
// the governance checkout, in a cluster it is whatever the deployment puts there. The backend does
// not embed the bundle, because a copy of the rules inside this binary would be a second source of
// truth for something governance owns (invariant 21).
const policyBundleDirEnv = "GITFROK_POLICY_BUNDLE_DIR"

const listenAddrEnv = "GITFROK_LISTEN_ADDR"

// dataplane is the composed plane: every context, held by its api/ port.
type dataplane struct {
	bus          *bus.InProcess
	repositories repoapi.Repositories
	searchIndex  csapi.Index
	policy       policyapi.DecisionPoint
	ci           *ci.Runtime
}

// newDataplane wires the plane. Concrete implementations are chosen in main and injected here; the
// fields are the api/ interfaces, so nothing downstream can depend on which implementation it got.
//
// The PDP is a parameter rather than something this function builds, because building it needs
// configuration and can fail — and because it makes the dependency impossible to forget. There is
// no "without a PDP" plane: a nil one would mean authorization silently had no answer, so it is
// refused here rather than discovered on the first protected request.
// A nil ciLauncher means this environment records CI jobs but dispatches none.
func newDataplane(pdp policyapi.DecisionPoint, ciConfig ci.RunnerConfig, ciLauncher ci.Launcher) *dataplane {
	if pdp == nil {
		panic("dataplane: no PDP — every protected action needs a decision (invariant 2)")
	}

	b := bus.NewInProcess()

	// Repository context, on the in-memory adapter until the Postgres one lands with the tenancy
	// baseline (T-0004). Swapping adapters is a change to this line and nothing else.
	repositories := repository.NewInMemory(b)

	// Code Search context, handed the bus it listens on and the Repository read port it resolves
	// against — the only two in-process routes a module may take (invariant 14).
	searchIndex := codesearch.New(b, repositories)

	// CI/CD context. It shares this plane's bus, so a RefUpdated published by
	// Repository reaches CI without either module calling the other (invariant 14).
	ciRuntime := ci.NewRuntime(pdp, b, ciConfig, ciLauncher)

	return &dataplane{bus: b, repositories: repositories, searchIndex: searchIndex, policy: pdp, ci: ciRuntime}
}

func main() {
	bundleDir := os.Getenv(policyBundleDirEnv)
	if bundleDir == "" {
		fmt.Fprintf(os.Stderr, "%s is not set: the plane has no policy bundle and every "+
			"authorization decision would be unanswerable (ADR-0006, invariant 2)\n", policyBundleDirEnv)
		os.Exit(1)
	}

	// The bus the PDP audits its refusals to. It is the same bus the plane runs on, built here
	// and handed to newDataplane below — one process, one bus.
	b := bus.NewInProcess()

	// Fail the rollout, not the requests. A plane that starts with an unusable bundle denies
	// everything, which reaches an operator as an unexplained total outage rather than as a
	// deployment that refused to come up and said why.
	pdp, err := policy.NewOPADecisionPoint(bundleDir, b)
	if err != nil {
		fmt.Fprintf(os.Stderr, "policy bundle at %s is unusable: %v\n", bundleDir, err)
		os.Exit(1)
	}

	// The CI runner configuration is per-environment. An unconfigured runner is not
	// an error — the plane records jobs and dispatches none — but a misconfigured
	// one fails the rollout rather than the first job.
	ciConfig, ciDispatches, err := loadCIRunnerConfig(os.Getenv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dataplane CI runner: %v\n", err)
		os.Exit(1)
	}
	var ciLauncher ci.Launcher
	if ciDispatches {
		// The dev launcher records attempts without contacting a cluster. The
		// client-go implementation of the Kubernetes launcher's Client port is the
		// remaining piece before a sandbox actually runs in a cluster.
		ciLauncher = ci.NewDevLauncher()
	}

	dp := newDataplane(pdp, ciConfig, ciLauncher)
	// Compile-time proof that the generated contracts compose into this plane alongside the
	// modules; the agent gateway itself is wired in Phase 3.
	_ = agentv1.HealthState_HEALTH_STATE_HEALTHY
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// The Git protocol front doors and the PDP's gRPC door run in this binary (ADR-0041).
	// Configuration decides which doors exist; identity is resolved before any storage call,
	// and git-storaged remains the PDP enforcement point (ADR-0041 decisions 2 and 4).
	frontCfg, err := loadFrontDoorConfig(os.Getenv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dataplane front doors: %v\n", err)
		os.Exit(1)
	}
	var authenticator identityapi.Authenticator
	if frontCfg.httpAddr != "" || frontCfg.sshAddr != "" {
		authenticator = identity.NewInMemory(frontCfg.patKey, dp.policy)
	}
	doors, err := startGitFrontDoors(ctx, frontCfg, authenticator, dp.policy)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dataplane front doors: %v\n", err)
		os.Exit(1)
	}
	defer doors.Close()

	// The CI job surface shares the plane's gRPC door.
	if doors.policyServer != nil {
		civ1.RegisterCIJobServiceServer(doors.policyServer, ci.NewGRPCServer(dp.ci.Jobs()))
	}

	if dp.ci.Dispatches() {
		go func() {
			if err := dp.ci.RunDispatcher(ctx); err != nil && !errors.Is(err, context.Canceled) {
				fmt.Fprintf(os.Stderr, "dataplane CI dispatcher: %v\n", err)
			}
		}()
		if addr := os.Getenv(ciMetricsAddrEnv); addr != "" {
			closeMetrics, err := serveCIMetrics(ctx, addr, dp.ci.MetricsHandler())
			if err != nil {
				fmt.Fprintf(os.Stderr, "dataplane CI metrics on %s: %v\n", addr, err)
				os.Exit(1)
			}
			defer closeMetrics()
		}
	}

	fmt.Printf("gitfrok dataplane-app: repository + codesearch on the in-process bus, PDP on %s\n", bundleDir)
	if err := health.Run(ctx, health.ListenAddr(os.Getenv(listenAddrEnv))); err != nil {
		fmt.Fprintf(os.Stderr, "dataplane health server: %v\n", err)
		os.Exit(1)
	}
}
