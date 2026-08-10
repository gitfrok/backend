package k8s

import (
	"context"
	"errors"
	"strings"
	"testing"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"

	"github.com/gitfrok/backend/modules/ci/api"
	"github.com/gitfrok/backend/modules/ci/internal/dispatcher"
	"github.com/gitfrok/backend/modules/ci/internal/runner"
)

type fakeClient struct {
	created   []*batchv1.Job
	deleted   []string
	succeeded bool
	summary   string
	awaitErr  error
	createErr error
	deleteErr error
}

func (c *fakeClient) Create(_ context.Context, job *batchv1.Job) error {
	if c.createErr != nil {
		return c.createErr
	}
	c.created = append(c.created, job)
	return nil
}

func (c *fakeClient) AwaitTerminal(_ context.Context, _ string) (bool, string, error) {
	return c.succeeded, c.summary, c.awaitErr
}

func (c *fakeClient) Delete(_ context.Context, name string) error {
	if c.deleteErr != nil {
		return c.deleteErr
	}
	c.deleted = append(c.deleted, name)
	return nil
}

const digestImage = "ghcr.io/gitfrok/ci-runner@sha256:" +
	"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func testJob() api.Job {
	return api.Job{
		ID: "job-1", AttemptID: "ATTEMPT1", TenantID: "tenant-a", RepositoryID: "repo-a",
		CommitSHA: "sha-a", ConfigurationDigest: "config-a", State: api.JobQueued,
	}
}

func testRunnerConfig() dispatcher.Config {
	return dispatcher.Config{
		RuntimeClass:     "gvisor",
		Image:            digestImage,
		SourceEndpoint:   "git-storaged:9000",
		SourceCapability: "read-only-source",
		Command:          []string{"/usr/bin/gitfrok-ci"},
	}
}

// The emitted Job must carry every isolation property explicitly: gVisor runtime
// class, no service-account token, no host namespaces, no privilege, read-only
// root, all capabilities dropped, and only ephemeral storage (invariant 3).
func TestBuildJobEmitsAnIsolatedEphemeralSandbox(t *testing.T) {
	sandbox, err := runner.NewSandbox(testJob(), runner.Config{
		RuntimeClass: "gvisor", Image: digestImage,
		SourceEndpoint: "git-storaged:9000", SourceCapability: "read-only-source",
		Command: []string{"/usr/bin/gitfrok-ci"},
	})
	if err != nil {
		t.Fatalf("NewSandbox: %v", err)
	}

	manifest, err := BuildJob(sandbox, "gitfrok-ci")
	if err != nil {
		t.Fatalf("BuildJob: %v", err)
	}

	pod := manifest.Spec.Template.Spec
	if pod.RuntimeClassName == nil || *pod.RuntimeClassName != "gvisor" {
		t.Errorf("runtime class = %v, want gvisor", pod.RuntimeClassName)
	}
	if pod.AutomountServiceAccountToken == nil || *pod.AutomountServiceAccountToken {
		t.Error("the sandbox must not receive a service-account token")
	}
	if pod.HostNetwork || pod.HostPID || pod.HostIPC {
		t.Error("the sandbox must not join a host namespace")
	}
	if pod.RestartPolicy != corev1.RestartPolicyNever {
		t.Errorf("restart policy = %s, want Never", pod.RestartPolicy)
	}
	if manifest.Spec.BackoffLimit == nil || *manifest.Spec.BackoffLimit != 0 {
		t.Error("a job attempt must not be retried inside its own sandbox")
	}
	if manifest.Spec.TTLSecondsAfterFinished == nil {
		t.Error("the Job must be garbage-collected after it finishes")
	}

	container := pod.Containers[0]
	sc := container.SecurityContext
	if sc == nil || sc.Privileged == nil || *sc.Privileged {
		t.Error("the sandbox container must not be privileged")
	}
	if sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation {
		t.Error("privilege escalation must be disabled")
	}
	if sc.ReadOnlyRootFilesystem == nil || !*sc.ReadOnlyRootFilesystem {
		t.Error("the root filesystem must be read-only")
	}
	if sc.Capabilities == nil || len(sc.Capabilities.Drop) != 1 || sc.Capabilities.Drop[0] != "ALL" {
		t.Errorf("capabilities = %+v, want all dropped", sc.Capabilities)
	}
	if !strings.Contains(container.Image, "@sha256:") {
		t.Errorf("image %q is not digest-pinned", container.Image)
	}
	for _, v := range pod.Volumes {
		if v.EmptyDir == nil {
			t.Errorf("volume %q is not ephemeral", v.Name)
		}
		if v.HostPath != nil {
			t.Errorf("volume %q mounts a host path", v.Name)
		}
	}
	if manifest.Labels["gitfrok.io/tenant-id"] != "tenant-a" {
		t.Errorf("tenant label = %q, want tenant-a", manifest.Labels["gitfrok.io/tenant-id"])
	}
}

// A sandbox that somehow carries host access must be refused at the adapter
// boundary too, not only in the sandbox model — the cluster call is the last
// place the property can still be enforced.
func TestBuildJobRefusesAWidenedSandbox(t *testing.T) {
	base, err := runner.NewSandbox(testJob(), runner.Config{
		RuntimeClass: "gvisor", Image: digestImage,
		SourceEndpoint: "git-storaged:9000", SourceCapability: "read-only-source",
		Command: []string{"/usr/bin/gitfrok-ci"},
	})
	if err != nil {
		t.Fatalf("NewSandbox: %v", err)
	}

	for name, mutate := range map[string]func(*runner.Sandbox){
		"host network":          func(s *runner.Sandbox) { s.HostNetwork = true },
		"host pid":              func(s *runner.Sandbox) { s.HostPID = true },
		"privileged":            func(s *runner.Sandbox) { s.Privileged = true },
		"privilege escalation":  func(s *runner.Sandbox) { s.AllowPrivilegeEscalation = true },
		"service account token": func(s *runner.Sandbox) { s.AutomountServiceAccountToken = true },
		"writable root":         func(s *runner.Sandbox) { s.ReadOnlyRootFilesystem = false },
		"kept capabilities":     func(s *runner.Sandbox) { s.DropAllCapabilities = false },
		"open network":          func(s *runner.Sandbox) { s.DefaultDenyNetwork = false },
		"host path":             func(s *runner.Sandbox) { s.HostPaths = []string{"/var/run/docker.sock"} },
		"persistent volume":     func(s *runner.Sandbox) { s.Volumes = []runner.Volume{{Name: "cache"}} },
	} {
		t.Run(name, func(t *testing.T) {
			widened := base
			mutate(&widened)
			if _, err := BuildJob(widened, "gitfrok-ci"); err == nil {
				t.Fatalf("BuildJob accepted a sandbox with %s", name)
			}
		})
	}
}

func TestBuildJobRequiresANamespace(t *testing.T) {
	sandbox, err := runner.NewSandbox(testJob(), runner.Config{
		RuntimeClass: "gvisor", Image: digestImage,
		SourceEndpoint: "git-storaged:9000", SourceCapability: "read-only-source",
		Command: []string{"/usr/bin/gitfrok-ci"},
	})
	if err != nil {
		t.Fatalf("NewSandbox: %v", err)
	}
	if _, err := BuildJob(sandbox, ""); err == nil {
		t.Fatal("BuildJob accepted an empty namespace")
	}
}

// A mutable image reference never reaches the cluster.
func TestLaunchRejectsAMutableImageBeforeTouchingTheCluster(t *testing.T) {
	client := &fakeClient{}
	config := testRunnerConfig()
	config.Image = "ghcr.io/gitfrok/ci-runner:latest"

	if _, err := NewLauncher(client, "gitfrok-ci").Launch(context.Background(), testJob(), config); err == nil {
		t.Fatal("Launch accepted a mutable image reference")
	}
	if len(client.created) != 0 {
		t.Fatal("a rejected launch still created a Job")
	}
}

func TestAwaitDeletesTheSandboxAndReportsItsOutcome(t *testing.T) {
	client := &fakeClient{succeeded: true, summary: "passed"}
	attempt, err := NewLauncher(client, "gitfrok-ci").Launch(context.Background(), testJob(), testRunnerConfig())
	if err != nil {
		t.Fatalf("Launch: %v", err)
	}
	if len(client.created) != 1 {
		t.Fatalf("expected 1 Job created, got %d", len(client.created))
	}

	state, summary, err := attempt.Await(context.Background())
	if err != nil {
		t.Fatalf("Await: %v", err)
	}
	if state != api.JobSucceeded || summary != "passed" {
		t.Fatalf("Await = %s/%q, want SUCCEEDED/passed", state, summary)
	}
	if len(client.deleted) != 1 || client.deleted[0] != client.created[0].Name {
		t.Fatalf("sandbox was not deleted: %v", client.deleted)
	}
}

// An unconfirmed deletion means the ephemeral sandbox may still exist, so the
// attempt fails rather than reporting a clean success.
func TestAwaitTreatsUnconfirmedCleanupAsFailure(t *testing.T) {
	client := &fakeClient{succeeded: true, summary: "passed", deleteErr: errors.New("api server unavailable")}
	attempt, err := NewLauncher(client, "gitfrok-ci").Launch(context.Background(), testJob(), testRunnerConfig())
	if err != nil {
		t.Fatalf("Launch: %v", err)
	}
	state, _, err := attempt.Await(context.Background())
	if err == nil {
		t.Fatal("Await hid an unconfirmed cleanup")
	}
	if state != api.JobFailed {
		t.Fatalf("state = %s, want FAILED", state)
	}
}

// The Job name is derived from the attempt ID, so a retried create collides
// instead of starting a second sandbox for the same attempt.
func TestJobNameIsDerivedFromTheAttempt(t *testing.T) {
	client := &fakeClient{succeeded: true}
	if _, err := NewLauncher(client, "gitfrok-ci").Launch(context.Background(), testJob(), testRunnerConfig()); err != nil {
		t.Fatalf("Launch: %v", err)
	}
	if got, want := client.created[0].Name, "ci-attempt-attempt1"; got != want {
		t.Fatalf("job name = %q, want %q", got, want)
	}
}

var _ dispatcher.Launcher = (*Launcher)(nil)
