// Package runner shapes the one-job sandbox boundary. A Kubernetes adapter
// turns this restricted model into a Job; keeping it free of client-go makes
// every isolation property unit-testable before cluster integration.
package runner

import (
	"errors"
	"slices"
	"strings"

	"github.com/gitfrok/backend/modules/ci/api"
)

type Config struct {
	RuntimeClass, Image, SourceEndpoint, SourceCapability string
	Command                                               []string
}

type Volume struct {
	Name      string
	Ephemeral bool
}

// Sandbox contains only the values a Kubernetes Job adapter may emit. Every
// field defaults to the safer value, so callers cannot accidentally opt into
// host access through an omitted boolean (SPEC-0020 AC4).
type Sandbox struct {
	JobID, AttemptID, TenantID, RepositoryID, CommitSHA, ConfigurationDigest string
	RuntimeClass, Image, SourceEndpoint, SourceCapability                    string
	Command                                                                  []string
	AutomountServiceAccountToken, HostPID, HostIPC, HostNetwork              bool
	Privileged, AllowPrivilegeEscalation, ReadOnlyRootFilesystem             bool
	DropAllCapabilities, DefaultDenyNetwork                                  bool
	HostPaths                                                                []string
	Volumes                                                                  []Volume
}

func NewSandbox(job api.Job, config Config) (Sandbox, error) {
	if job.ID == "" || job.AttemptID == "" || job.TenantID == "" || job.RepositoryID == "" || job.CommitSHA == "" || config.RuntimeClass == "" || config.SourceEndpoint == "" || config.SourceCapability == "" || len(config.Command) == 0 || !strings.Contains(config.Image, "@sha256:") {
		return Sandbox{}, errors.New("ci runner: incomplete immutable sandbox configuration")
	}
	return Sandbox{JobID: job.ID, AttemptID: job.AttemptID, TenantID: job.TenantID, RepositoryID: job.RepositoryID, CommitSHA: job.CommitSHA, ConfigurationDigest: job.ConfigurationDigest, RuntimeClass: config.RuntimeClass, Image: config.Image, Command: slices.Clone(config.Command), SourceEndpoint: config.SourceEndpoint, SourceCapability: config.SourceCapability, ReadOnlyRootFilesystem: true, DropAllCapabilities: true, DefaultDenyNetwork: true, Volumes: []Volume{{Name: "work", Ephemeral: true}}}, nil
}
