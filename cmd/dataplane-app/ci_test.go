package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/gitfrok/backend/modules/ci"
)

const testRunnerImage = "ghcr.io/gitfrok/ci-runner@sha256:" +
	"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func completeRunnerEnv() map[string]string {
	return map[string]string{
		ciImageEnv:            testRunnerImage,
		ciRuntimeClassEnv:     "gvisor",
		ciSourceEndpointEnv:   "git-storaged:9000",
		ciSourceCapabilityEnv: "read-only-source",
		ciCommandEnv:          "/usr/bin/gitfrok-ci run",
		ciNamespaceEnv:        "gitfrok-ci",
	}
}

func getenvFrom(env map[string]string) func(string) string {
	return func(key string) string { return env[key] }
}

func TestLoadCIRunnerConfigReadsTheEnvironment(t *testing.T) {
	config, dispatches, err := loadCIRunnerConfig(getenvFrom(completeRunnerEnv()))
	if err != nil {
		t.Fatalf("loadCIRunnerConfig: %v", err)
	}
	if !dispatches {
		t.Fatal("a fully configured runner does not dispatch")
	}
	if config.RuntimeClass != "gvisor" || config.Namespace != "gitfrok-ci" {
		t.Fatalf("config = %+v", config)
	}
	if len(config.Command) != 2 || config.Command[0] != "/usr/bin/gitfrok-ci" {
		t.Fatalf("command = %v", config.Command)
	}
}

// An unconfigured runner is a valid deployment: jobs are recorded and nothing is
// dispatched. It must not fail the rollout.
func TestLoadCIRunnerConfigTreatsAnEmptyImageAsNoDispatch(t *testing.T) {
	config, dispatches, err := loadCIRunnerConfig(getenvFrom(map[string]string{}))
	if err != nil {
		t.Fatalf("loadCIRunnerConfig: %v", err)
	}
	if dispatches {
		t.Fatal("an unconfigured runner reported that it dispatches")
	}
	if !reflect.DeepEqual(config, ci.RunnerConfig{}) {
		t.Fatalf("config = %+v, want the zero value", config)
	}
}

// A mutable tag would let sandbox contents change under a digest the audit trail
// already recorded, so the rollout fails rather than the first job.
func TestLoadCIRunnerConfigRejectsAMutableImage(t *testing.T) {
	env := completeRunnerEnv()
	env[ciImageEnv] = "ghcr.io/gitfrok/ci-runner:latest"
	if _, _, err := loadCIRunnerConfig(getenvFrom(env)); err == nil {
		t.Fatal("loadCIRunnerConfig accepted a mutable image reference")
	}
}

func TestLoadCIRunnerConfigRequiresEveryValueOnceTheImageIsSet(t *testing.T) {
	for _, missing := range []string{ciRuntimeClassEnv, ciSourceEndpointEnv, ciSourceCapabilityEnv, ciCommandEnv, ciNamespaceEnv} {
		t.Run(missing, func(t *testing.T) {
			env := completeRunnerEnv()
			delete(env, missing)
			if _, _, err := loadCIRunnerConfig(getenvFrom(env)); err == nil {
				t.Fatalf("loadCIRunnerConfig accepted a runner with no %s", missing)
			}
		})
	}
}

// KEDA scales the runner on this metric, so the plane must actually serve it.
func TestServeCIMetricsExposesTheQueuedDepthGauge(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving a port: %v", err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("releasing the reserved port: %v", err)
	}

	runtime := ci.NewRuntime(denyAll{}, nil, ci.RunnerConfig{}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	closeMetrics, err := serveCIMetrics(ctx, addr, runtime.MetricsHandler())
	if err != nil {
		t.Fatalf("serveCIMetrics: %v", err)
	}
	defer closeMetrics()

	resp, err := http.Get("http://" + addr + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading /metrics: %v", err)
	}
	if !strings.Contains(string(body), "ci_queued_jobs") {
		t.Fatalf("/metrics does not expose the queued-depth gauge: %q", body)
	}
}
