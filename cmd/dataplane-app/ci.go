package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gitfrok/backend/modules/ci"
)

// The runner configuration is per-environment, never compiled in (invariant 13).
// A tenant cannot influence any of it: the runtime class, the image, the source
// endpoint, and the source capability are all resolved here, once, from the
// deployment's own environment.
const (
	ciRuntimeClassEnv     = "GITFROK_CI_RUNTIME_CLASS"
	ciImageEnv            = "GITFROK_CI_RUNNER_IMAGE"
	ciSourceEndpointEnv   = "GITFROK_CI_SOURCE_ENDPOINT"
	ciSourceCapabilityEnv = "GITFROK_CI_SOURCE_CAPABILITY"
	ciCommandEnv          = "GITFROK_CI_RUNNER_COMMAND"
	ciNamespaceEnv        = "GITFROK_CI_NAMESPACE"
	// ciMetricsAddrEnv is where the queued-depth metric is served for KEDA's
	// Prometheus scaler. Empty means the plane publishes no scaler metric.
	ciMetricsAddrEnv = "GITFROK_CI_METRICS_ADDR"
)

// loadCIRunnerConfig reads the runner configuration. An empty image means CI
// dispatch is not configured for this environment, which is not an error: the
// job API still runs, and nothing is dispatched.
func loadCIRunnerConfig(getenv func(string) string) (ci.RunnerConfig, bool, error) {
	image := getenv(ciImageEnv)
	if image == "" {
		return ci.RunnerConfig{}, false, nil
	}

	config := ci.RunnerConfig{
		RuntimeClass:     getenv(ciRuntimeClassEnv),
		Image:            image,
		SourceEndpoint:   getenv(ciSourceEndpointEnv),
		SourceCapability: getenv(ciSourceCapabilityEnv),
		Namespace:        getenv(ciNamespaceEnv),
	}
	if command := strings.TrimSpace(getenv(ciCommandEnv)); command != "" {
		config.Command = strings.Fields(command)
	}

	// A mutable tag would let the contents of a sandbox change under a digest the
	// audit trail already recorded, so it is refused at startup rather than on the
	// first job (ADR-0035, invariant 3).
	if !strings.Contains(config.Image, "@sha256:") {
		return ci.RunnerConfig{}, false, fmt.Errorf("%s must be digest-pinned, got %q", ciImageEnv, config.Image)
	}
	for env, value := range map[string]string{
		ciRuntimeClassEnv:     config.RuntimeClass,
		ciSourceEndpointEnv:   config.SourceEndpoint,
		ciSourceCapabilityEnv: config.SourceCapability,
		ciNamespaceEnv:        config.Namespace,
	} {
		if value == "" {
			return ci.RunnerConfig{}, false, fmt.Errorf("%s is required when %s is set", env, ciImageEnv)
		}
	}
	if len(config.Command) == 0 {
		return ci.RunnerConfig{}, false, fmt.Errorf("%s is required when %s is set", ciCommandEnv, ciImageEnv)
	}
	return config, true, nil
}

// serveCIMetrics exposes the queued-depth gauge in Prometheus exposition format
// on its own listener, so KEDA can scale the runner on queue depth without the
// health endpoint becoming a metrics surface. It returns a close function.
func serveCIMetrics(ctx context.Context, addr string, handler http.Handler) (func(), error) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle("/metrics", handler)
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(os.Stderr, "dataplane CI metrics: %v\n", err)
		}
	}()
	return func() {
		shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}, nil
}
