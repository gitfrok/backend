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

	"github.com/gitfrok/backend/modules/ci/api"
	"github.com/gitfrok/backend/modules/ci/internal/adapters/grpc"
	"github.com/gitfrok/backend/modules/ci/internal/app"
	"github.com/gitfrok/backend/modules/ci/internal/dev"
	"github.com/gitfrok/backend/modules/ci/internal/dispatcher"
	"github.com/gitfrok/backend/modules/ci/internal/kedametrics"
	"github.com/gitfrok/backend/modules/ci/internal/memory"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
	"github.com/gitfrok/backend/platform/bus"
)

// New builds the CI context from its ports. The app wires the service; the
// dispatcher is wired separately so it can run its own loop.
func New(
	store app.Store,
	queue app.Queue,
	source app.Source,
	pdp policyapi.DecisionPoint,
	events bus.Bus,
	opts ...app.Option,
) *app.Service {
	return app.New(store, queue, source, pdp, events, opts...)
}

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

// NewDispatcher builds the dispatch loop: it publishes queue depth to the gauge
// KEDA scales on, claims one queued job per tick, and launches exactly one
// sandbox for it.
func NewDispatcher(
	queue dispatcher.Queue,
	store dispatcher.Store,
	launcher dispatcher.Launcher,
	pdp policyapi.DecisionPoint,
	events bus.Bus,
	config RunnerConfig,
	gauge *kedametrics.Gauge,
) *dispatcher.Dispatcher {
	return dispatcher.New(queue, store, launcher, pdp, events,
		dispatcher.WithConfig(dispatcher.Config{
			RuntimeClass:     config.RuntimeClass,
			Image:            config.Image,
			SourceEndpoint:   config.SourceEndpoint,
			SourceCapability: config.SourceCapability,
			Command:          append([]string(nil), config.Command...),
		}),
		dispatcher.WithGauge(gauge),
	)
}

// NewGauge returns the queued-depth gauge the dispatcher publishes to.
func NewGauge() *kedametrics.Gauge { return kedametrics.NewGauge() }

// MetricsHandler serves the queued-depth gauge in Prometheus exposition format.
// KEDA's Prometheus scaler reads `ci_queued_jobs` from it to scale the runner
// deployment on queue depth (T-0017 AC2).
func MetricsHandler(gauge *kedametrics.Gauge) http.Handler { return kedametrics.Handler(gauge) }

// NewDevLauncher returns the dev sandbox launcher: it records dispatch attempts
// without contacting a cluster. It is not a production isolation boundary.
func NewDevLauncher() *dev.Launcher { return &dev.Launcher{} }

// NewGRPCServer wraps the in-process job service in the CI/CD gRPC server adapter,
// ready to register on the plane binary's gRPC server.
func NewGRPCServer(jobs api.Jobs) *grpc.Server {
	return grpc.NewServer(jobs)
}

// NewQueue returns a dev/in-memory job queue. Production injects a KEDA-backed
// queue that exposes queued-depth as a Prometheus metric.
func NewQueue() *memory.Queue {
	return memory.NewQueue()
}

// NewStore returns a dev/in-memory job store. Production injects a tenant-scoped
// database store preserving the create-or-get atomicity invariant.
func NewStore() app.Store {
	return app.NewMemoryStore()
}

// stubSource is a dev adapter that returns a fixed digest without contacting a
// RepositoryReader gRPC server. Production injects the gitwire.Source adapter.
type stubSource struct{}

func (stubSource) Validate(_ context.Context, _, _, _, _ string) (string, error) {
	return "dev:ci-yaml-digest", nil
}

// NewSourceStub returns a no-op Source for local development.
func NewSourceStub() app.Source {
	return stubSource{}
}
