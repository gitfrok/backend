// Package ci is the CI/CD context (SPEC-0020).
//
// It wires the in-process job lifecycle, queue, source validation, policy decision
// point, and event bus into a runnable Service. The KEDA dispatcher and Kubernetes
// sandbox launcher are injected as ports by cmd/dataplane-app, keeping every
// isolation and dispatch invariant unit-testable without a cluster.
package ci

import (
	"context"
	"net/http"
	"slices"

	"github.com/gitfrok/backend/modules/ci/api"
	"github.com/gitfrok/backend/modules/ci/internal/adapters/grpc"
	"github.com/gitfrok/backend/modules/ci/internal/adapters/k8s"
	"github.com/gitfrok/backend/modules/ci/internal/app"
	"github.com/gitfrok/backend/modules/ci/internal/dev"
	"github.com/gitfrok/backend/modules/ci/internal/dispatcher"
	"github.com/gitfrok/backend/modules/ci/internal/kedametrics"
	"github.com/gitfrok/backend/modules/ci/internal/memory"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
	"github.com/gitfrok/backend/platform/bus"
)

// RunnerConfig is the environment-resolved runner configuration, restated here so
// cmd/ can supply it without naming a package under this module's internal/ tree.
// It is resolved once per environment and never derived from a job or from a
// repository's own files.
type RunnerConfig struct {
	RuntimeClass     string
	Image            string // must be digest-pinned (@sha256:...)
	SourceEndpoint   string
	SourceCapability string
	Command          []string
	Namespace        string
}

// Launcher is the cluster port that turns one job attempt into one ephemeral
// sandbox. It is aliased here so cmd/ can hold and pass one without naming a
// package under this module's internal/ tree.
type Launcher = dispatcher.Launcher

// Runtime is the composed CI context: the job service the gRPC door serves, and
// the dispatch loop that drains the queue into sandboxes. Both share one queue
// and one store, which is why they are built together rather than separately.
type Runtime struct {
	jobs       api.Jobs
	dispatcher *dispatcher.Dispatcher
	gauge      *kedametrics.Gauge
}

// NewRuntime builds the CI context on its dev adapters. A nil launcher means this
// environment dispatches nothing: the job API still accepts and records jobs, and
// no sandbox is ever created.
func NewRuntime(pdp policyapi.DecisionPoint, events bus.Bus, config RunnerConfig, launcher Launcher) *Runtime {
	queue := memory.NewQueue()
	store := app.NewMemoryStore()
	gauge := kedametrics.NewGauge()
	runtime := &Runtime{
		jobs:  app.New(store, queue, stubSource{}, pdp, events),
		gauge: gauge,
	}
	if launcher != nil {
		runtime.dispatcher = dispatcher.New(queue, store, launcher, pdp, events,
			dispatcher.WithConfig(dispatcher.Config{
				RuntimeClass:     config.RuntimeClass,
				Image:            config.Image,
				SourceEndpoint:   config.SourceEndpoint,
				SourceCapability: config.SourceCapability,
				Command:          slices.Clone(config.Command),
			}),
			dispatcher.WithGauge(gauge),
		)
	}
	return runtime
}

// Jobs is the in-process job surface, for the gRPC door and for other contexts.
func (r *Runtime) Jobs() api.Jobs { return r.jobs }

// Dispatches reports whether this environment has a launcher and therefore drains
// its queue into sandboxes.
func (r *Runtime) Dispatches() bool { return r.dispatcher != nil }

// RunDispatcher blocks, draining the queue until ctx is cancelled. It returns
// immediately when no launcher is configured.
func (r *Runtime) RunDispatcher(ctx context.Context) error {
	if r.dispatcher == nil {
		return nil
	}
	return r.dispatcher.Run(ctx)
}

// MetricsHandler serves the queued-depth gauge in Prometheus exposition format.
// KEDA's Prometheus scaler reads `ci_queued_jobs` from it to scale the runner
// deployment on queue depth (T-0017 AC2).
func (r *Runtime) MetricsHandler() http.Handler { return kedametrics.Handler(r.gauge) }

// NewDevLauncher returns the dev sandbox launcher: it records dispatch attempts
// without contacting a cluster. It is not a production isolation boundary.
func NewDevLauncher() Launcher { return &dev.Launcher{} }

// NewClusterLauncher returns the production sandbox launcher: it creates one
// ephemeral, gVisor-isolated Kubernetes Job per attempt and destroys it after.
// An empty kubeconfigPath means the pod's own service account in-cluster.
func NewClusterLauncher(kubeconfigPath, namespace string) (Launcher, error) {
	client, err := k8s.NewClusterClient(kubeconfigPath, namespace)
	if err != nil {
		return nil, err
	}
	return k8s.NewLauncher(client, namespace), nil
}

// NewGRPCServer wraps the in-process job service in the CI/CD gRPC server adapter,
// ready to register on the plane binary's gRPC server.
func NewGRPCServer(jobs api.Jobs) *grpc.Server {
	return grpc.NewServer(jobs)
}

// stubSource is a dev adapter that returns a fixed digest without contacting a
// RepositoryReader gRPC server. Production injects the gitwire.Source adapter.
type stubSource struct{}

func (stubSource) Validate(_ context.Context, _, _, _, _ string) (string, error) {
	return "dev:ci-yaml-digest", nil
}
