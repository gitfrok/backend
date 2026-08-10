package runner

import (
	"testing"

	"github.com/gitfrok/backend/modules/ci/api"
)

func TestSandboxBindsOneAttemptToGVisorWithoutHostAccess(t *testing.T) {
	sandbox, err := NewSandbox(api.Job{ID: "job-a", AttemptID: "attempt-a", TenantID: "tenant-a", RepositoryID: "repo-a", CommitSHA: "aabbcc", ConfigurationDigest: "sha256:config"}, Config{RuntimeClass: "gvisor", Image: "registry.example/ci@sha256:image", Command: []string{"/bin/test"}, SourceEndpoint: "https://source.internal", SourceCapability: "single-job-capability"})
	if err != nil {
		t.Fatal(err)
	}
	if sandbox.RuntimeClass != "gvisor" || sandbox.AutomountServiceAccountToken || sandbox.HostPID || sandbox.HostIPC || sandbox.HostNetwork || sandbox.Privileged || sandbox.AllowPrivilegeEscalation || !sandbox.ReadOnlyRootFilesystem || len(sandbox.HostPaths) != 0 {
		t.Fatalf("sandbox isolation = %+v", sandbox)
	}
	if len(sandbox.Volumes) != 1 || !sandbox.Volumes[0].Ephemeral || !sandbox.DefaultDenyNetwork || sandbox.TenantID != "tenant-a" || sandbox.CommitSHA != "aabbcc" {
		t.Fatalf("sandbox binding = %+v", sandbox)
	}
}

func TestSandboxRejectsMissingRuntimeOrMutableImage(t *testing.T) {
	job := api.Job{ID: "job-a", AttemptID: "attempt-a", TenantID: "tenant-a", RepositoryID: "repo-a", CommitSHA: "aabbcc"}
	for _, config := range []Config{
		{Image: "registry.example/ci@sha256:image", Command: []string{"test"}, SourceEndpoint: "https://source.internal", SourceCapability: "cap"},
		{RuntimeClass: "gvisor", Image: "registry.example/ci:latest", Command: []string{"test"}, SourceEndpoint: "https://source.internal", SourceCapability: "cap"},
	} {
		if _, err := NewSandbox(job, config); err == nil {
			t.Fatal("NewSandbox succeeded with unsafe configuration")
		}
	}
}
