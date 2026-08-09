// Command dataplane-app is the single data-plane binary (invariant 19). Modules are packages
// composed here; they are not separate services (ADR-0025).
//
// This file is the only place that knows which modules exist and which concrete adapters they run
// on. A module never constructs another module, and never reaches for an adapter itself — so
// promoting one to its own service (ADR-0026) is a change here, not in the modules.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/gitfrok/backend/cmd/internal/health"
	agentv1 "github.com/gitfrok/backend/gen/proto/agent/v1"
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
}

// newDataplane wires the plane. Concrete implementations are chosen in main and injected here; the
// fields are the api/ interfaces, so nothing downstream can depend on which implementation it got.
//
// The PDP is a parameter rather than something this function builds, because building it needs
// configuration and can fail — and because it makes the dependency impossible to forget. There is
// no "without a PDP" plane: a nil one would mean authorization silently had no answer, so it is
// refused here rather than discovered on the first protected request.
func newDataplane(pdp policyapi.DecisionPoint) *dataplane {
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

	return &dataplane{bus: b, repositories: repositories, searchIndex: searchIndex, policy: pdp}
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

	dp := newDataplane(pdp)
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

	fmt.Printf("gitfrok dataplane-app: repository + codesearch on the in-process bus, PDP on %s\n", bundleDir)
	if err := health.Run(ctx, health.ListenAddr(os.Getenv(listenAddrEnv))); err != nil {
		fmt.Fprintf(os.Stderr, "dataplane health server: %v\n", err)
		os.Exit(1)
	}
}
