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
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gitfrok/backend/cmd/internal/health"
	agentv1 "github.com/gitfrok/backend/gen/proto/agent/v1"
	civ1 "github.com/gitfrok/backend/gen/proto/ci/v1"
	codereviewv1 "github.com/gitfrok/backend/gen/proto/codereview/v1"
	gitv1 "github.com/gitfrok/backend/gen/proto/git/v1"
	identityv1 "github.com/gitfrok/backend/gen/proto/identity/v1"
	"github.com/gitfrok/backend/modules/ci"
	"github.com/gitfrok/backend/modules/codereview"
	codereviewapi "github.com/gitfrok/backend/modules/codereview/api"
	"github.com/gitfrok/backend/modules/codesearch"
	csapi "github.com/gitfrok/backend/modules/codesearch/api"
	"github.com/gitfrok/backend/modules/identity"
	identityapi "github.com/gitfrok/backend/modules/identity/api"
	"github.com/gitfrok/backend/modules/policy"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
	"github.com/gitfrok/backend/modules/repository"
	repoapi "github.com/gitfrok/backend/modules/repository/api"
	"github.com/gitfrok/backend/platform/auditsink"
	"github.com/gitfrok/backend/platform/bus"
	"github.com/gitfrok/backend/platform/db"
	"github.com/gitfrok/backend/platform/tenancy"
)

// policyBundleDirEnv names the directory holding the OPA bundle from governance/policies.
//
// Per-environment configuration, never a compiled-in path (invariant 13): in dev it is a mount of
// the governance checkout, in a cluster it is whatever the deployment puts there. The backend does
// not embed the bundle, because a copy of the rules inside this binary would be a second source of
// truth for something governance owns (invariant 21).
const policyBundleDirEnv = "GITFROK_POLICY_BUNDLE_DIR"

const listenAddrEnv = "GITFROK_LISTEN_ADDR"

// databaseURLEnv is the tenant-scoped application DSN. When set, the plane
// persists its audit events onto the Postgres trail (ADR-0007 composition).
const databaseURLEnv = "GITFROK_DATABASE_URL"

// dataplane is the composed plane: every context, held by its api/ port.
type dataplane struct {
	bus          *bus.InProcess
	repositories repoapi.Repositories
	searchIndex  csapi.Index
	policy       policyapi.DecisionPoint
	ci           *ci.Runtime
	// codeReview is composed in main once the plane has a route to Git storage.
	codeReview codereviewapi.MergeRequests
	// imports is the repository & review-history import surface (SPEC-0011),
	// composed alongside codeReview on the same route to Git storage.
	imports codereviewapi.ImportService
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

	// The audit sink is per-environment: a plane with GITFROK_DATABASE_URL
	// persists the audit events it emits (PDP refusals, RLS violations, approved
	// reviews and merges) onto the Postgres trail; without it the events are
	// published and dropped, exactly as before. A configured sink that cannot
	// write is never silent: the PDP reports an unaudited denial as an error
	// (ADR-0007). The DSN must be the gitfrok_app role — db.Open refuses a
	// superuser, because RLS must actually bind.
	if dsn := os.Getenv(databaseURLEnv); dsn != "" {
		pool, err := db.Open(context.Background(), dsn)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dataplane audit database: %v\n", err)
			os.Exit(1)
		}
		defer pool.Close()
		auditsink.NewSink(pool, b).Subscribe(b)
	}

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
		ciLauncher, err = newCILauncher(os.Getenv, ciConfig)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dataplane CI launcher: %v\n", err)
			os.Exit(1)
		}
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

	// Code Review needs a route to Git storage to complete a merge, and the plane
	// only has one when the Git doors are configured. Without it the context is not
	// composed at all, rather than composed with a merge path that cannot work.
	if doors.storageClient != nil {
		dp.codeReview = codereview.New(codereview.NewRefMover(doors.storageClient), dp.policy, dp.bus)
		// Ref updates cross the process boundary in the other direction: the
		// receive-pack path announces RefUpdated on git-storaged's bus, and this
		// plane subscribes and republishes so the repository projection, search,
		// and CI triggers light up exactly as they do in the monolith (SPEC-0015).
		watchRefUpdates(ctx, doors.storageClient, dp.bus)
		// Branch protection crosses the process boundary here. Code Review owns
		// the rules and announces each change as BranchProtectionChanged; when it
		// and git-storaged share a process the event is enough, and when they do
		// not, this forwarder is what makes the rule reach the node that enforces
		// direct pushes. git-storaged asks its own PDP for the rule with the
		// event's verified actor (git.proto SetProtection), so a change that was
		// allowed here is still not trusted there.
		bus.SubscribeTyped(dp.bus, func(ctx context.Context, e codereviewapi.BranchProtectionChanged) error {
			_, err := doors.storageClient.SetProtection(ctx, &gitv1.SetProtectionRequest{
				Context: &gitv1.RefUpdateContext{
					TenantId:     e.TenantID,
					RepositoryId: e.RepositoryID,
					ActorId:      e.ActorID,
					RequestId:    e.EventID,
					ActorRoles:   append([]string(nil), e.ActorRoles...),
				},
				TargetRef:         e.TargetRef,
				RequiredApprovals: e.RequiredApprovals,
			})
			return err
		})
		// The import surface (SPEC-0011) rides the same route to Git storage.
		// The history phase imports from GitHub or GitLab (selected by the
		// import's source_system); the git phase fetches refs.
		// One record store, shared: the importers write imported history into it
		// and a revoke tombstones the records that are actually there.
		importRecords := codereview.NewImportRecordStore()
		// One pacer for the whole import surface, so import work as a whole yields
		// to interactive traffic. The interval is per-environment configuration:
		// an unset one paces nothing, which is a load problem an operator can see,
		// whereas an import that silently blocks is an outage (SPEC-0011 AC21).
		importPacer := codereview.NewImportPacer(importPaceInterval(os.Getenv))
		dp.imports = codereview.NewImportService(
			importRecords, codereview.NewGitImporter(doors.storageClient),
			codereview.NewSourceHistoryImporter(importRecords, nil, importPacer),
			dp.policy, dp.bus, importPacer,
		)
	}

	// OIDC login, when this environment has an identity provider. Built before the
	// doors open so a misconfigured one fails the rollout rather than the first login.
	oidcConfig, oidcEnabled, err := loadOIDCConfig(os.Getenv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dataplane OIDC login: %v\n", err)
		os.Exit(1)
	}
	if oidcEnabled {
		if err := oidcConfig.Validate(); err != nil {
			fmt.Fprintf(os.Stderr, "dataplane OIDC login: %v\n", err)
			os.Exit(1)
		}
	}

	// The CI, Code Review and Identity surfaces share the plane's gRPC door.
	if doors.policyServer != nil {
		civ1.RegisterCIJobServiceServer(doors.policyServer, ci.NewGRPCServer(dp.ci.Jobs()))
		if dp.codeReview != nil {
			codereviewv1.RegisterMergeRequestServiceServer(doors.policyServer, codereview.NewGRPCServer(dp.codeReview))
		}
		if dp.imports != nil {
			codereviewv1.RegisterImportServiceServer(doors.policyServer, codereview.NewImportGRPCServer(dp.imports))
		}
		// Credential lifecycle (IssuePAT/ListPATs/RevokePAT) when this plane has
		// the Git front doors that consume credentials. The door derives the
		// tenant-scoped principal from the request, so it is only composed where
		// the door is in-cluster; a production deployment fronts it with an
		// authenticating interceptor. Every lifecycle action still passes the PDP
		// with the caller's asserted identity, exactly as in-process calls do.
		if authenticator != nil {
			identityv1.RegisterCredentialAuthenticatorServer(doors.policyServer,
				identity.NewGRPCServer(lifecycleContextAuthenticator{authenticator}))
		}
		if oidcEnabled {
			if err := identity.RegisterOIDCLogin(doors.policyServer, oidcConfig, http.DefaultClient); err != nil {
				fmt.Fprintf(os.Stderr, "dataplane OIDC login: %v\n", err)
				os.Exit(1)
			}
		}
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

// lifecycleContextAuthenticator derives the tenant-scoped principal context the
// identity lifecycle actions require from the request fields themselves. It
// exists for the in-cluster gRPC door, which carries no interceptor: the
// request is the only place the caller's identity can come from there. The PDP
// still decides every lifecycle action with that identity (identity module,
// authorizeLifecycle) — the wrapper only supplies the subject; it cannot lift a
// decision. Production deployments front the door with an authenticating
// interceptor instead of composing this wrapper.
type lifecycleContextAuthenticator struct {
	identityapi.Authenticator
}

func (a lifecycleContextAuthenticator) withLifecycleContext(ctx context.Context, tenantID, actorID string, roles []string) context.Context {
	ctx = tenancy.WithTenant(ctx, tenancy.ID(tenantID))
	return identityapi.WithPrincipal(ctx, identityapi.Principal{TenantID: tenantID, ActorID: actorID, Roles: roles})
}

func (a lifecycleContextAuthenticator) IssuePAT(ctx context.Context, tenantID, actorID, label string, scopes, roles []string, expiresAt *time.Time) (identityapi.PAT, string, error) {
	return a.Authenticator.IssuePAT(a.withLifecycleContext(ctx, tenantID, actorID, roles), tenantID, actorID, label, scopes, roles, expiresAt)
}

func (a lifecycleContextAuthenticator) RevokePAT(ctx context.Context, tenantID, actorID, patID string) (identityapi.PAT, error) {
	return a.Authenticator.RevokePAT(a.withLifecycleContext(ctx, tenantID, actorID, nil), tenantID, actorID, patID)
}

func (a lifecycleContextAuthenticator) ListPATs(ctx context.Context, tenantID, actorID string) ([]identityapi.PAT, error) {
	return a.Authenticator.ListPATs(a.withLifecycleContext(ctx, tenantID, actorID, nil), tenantID, actorID)
}
