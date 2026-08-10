// Package k8s turns the restricted sandbox model into a Kubernetes Job and runs
// exactly one job attempt inside it. The cluster calls are behind a small Client
// port so every isolation property of the emitted spec is unit-testable without a
// cluster (SPEC-0010, SPEC-0020 AC2/AC4, invariant 3).
package k8s

import (
	"context"
	"errors"
	"fmt"
	"strings"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/gitfrok/backend/modules/ci/api"
	"github.com/gitfrok/backend/modules/ci/internal/dispatcher"
	"github.com/gitfrok/backend/modules/ci/internal/runner"
)

// Client is the narrow cluster surface this adapter needs. A production
// implementation wraps a namespaced client-go BatchV1 client.
type Client interface {
	// Create submits one Job. It must fail if a Job of that name already exists,
	// so a retried attempt can never produce a second sandbox for the same attempt.
	Create(ctx context.Context, job *batchv1.Job) error
	// AwaitTerminal blocks until the named Job reached a terminal state. It
	// returns whether it succeeded and a short outcome summary.
	AwaitTerminal(ctx context.Context, name string) (succeeded bool, summary string, err error)
	// Delete removes the Job and its pod. Returning an error means cleanup is
	// unconfirmed, which the attempt reports as a failure rather than a success.
	Delete(ctx context.Context, name string) error
}

// Launcher creates one ephemeral, gVisor-isolated Job per attempt.
type Launcher struct {
	client    Client
	namespace string
}

func NewLauncher(client Client, namespace string) *Launcher {
	return &Launcher{client: client, namespace: namespace}
}

// Launch builds the sandbox for this attempt and creates its Job. The sandbox
// model rejects a mutable image or a missing runtime class before anything
// reaches the cluster.
func (l *Launcher) Launch(ctx context.Context, job api.Job, config dispatcher.Config) (dispatcher.Attempt, error) {
	sandbox, err := runner.NewSandbox(job, runner.Config{
		RuntimeClass:     config.RuntimeClass,
		Image:            config.Image,
		SourceEndpoint:   config.SourceEndpoint,
		SourceCapability: config.SourceCapability,
		Command:          config.Command,
	})
	if err != nil {
		return nil, err
	}
	manifest, err := BuildJob(sandbox, l.namespace)
	if err != nil {
		return nil, err
	}
	if err := l.client.Create(ctx, manifest); err != nil {
		return nil, err
	}
	return &attempt{client: l.client, name: manifest.Name}, nil
}

type attempt struct {
	client Client
	name   string
}

// Await waits for the Job to terminate and then deletes it. An unconfirmed
// deletion is reported as cleanup uncertainty: an ephemeral sandbox that may
// still exist is never reported as a clean success (invariant 3).
func (a *attempt) Await(ctx context.Context) (api.JobState, string, error) {
	succeeded, summary, err := a.client.AwaitTerminal(ctx, a.name)
	if err != nil {
		_ = a.client.Delete(ctx, a.name)
		return api.JobFailed, "sandbox did not reach a terminal state", err
	}
	if deleteErr := a.client.Delete(ctx, a.name); deleteErr != nil {
		return api.JobFailed, "sandbox cleanup unconfirmed", deleteErr
	}
	if !succeeded {
		return api.JobFailed, summary, nil
	}
	return api.JobSucceeded, summary, nil
}

// jobName is deterministic in the attempt ID, so a retried Create collides with
// the existing Job instead of starting a second sandbox for the same attempt.
func jobName(attemptID string) string {
	return "ci-attempt-" + strings.ToLower(attemptID)
}

// BuildJob maps a sandbox onto a Kubernetes Job. Every field the sandbox model
// treats as a safety property is set explicitly here rather than left to a
// cluster default, so a permissive namespace default cannot widen a sandbox.
func BuildJob(sandbox runner.Sandbox, namespace string) (*batchv1.Job, error) {
	if namespace == "" {
		return nil, errors.New("ci k8s: no namespace configured for the runner")
	}
	if len(sandbox.HostPaths) != 0 {
		return nil, fmt.Errorf("ci k8s: sandbox requested %d host path(s)", len(sandbox.HostPaths))
	}
	if !sandbox.DropAllCapabilities || !sandbox.ReadOnlyRootFilesystem || !sandbox.DefaultDenyNetwork {
		return nil, errors.New("ci k8s: sandbox does not drop capabilities, pin a read-only root, or deny network by default")
	}
	if sandbox.Privileged || sandbox.AllowPrivilegeEscalation || sandbox.HostNetwork || sandbox.HostPID || sandbox.HostIPC || sandbox.AutomountServiceAccountToken {
		return nil, errors.New("ci k8s: sandbox requested host access or privilege")
	}

	no, yes := new(false), new(true)
	backoffLimit := new(int32(0))
	ttlSecondsAfterFinish := new(int32(0))
	runAsUser := new(int64(65532))

	volumes := make([]corev1.Volume, 0, len(sandbox.Volumes))
	mounts := make([]corev1.VolumeMount, 0, len(sandbox.Volumes))
	for _, v := range sandbox.Volumes {
		if !v.Ephemeral {
			return nil, fmt.Errorf("ci k8s: volume %q is not ephemeral", v.Name)
		}
		volumes = append(volumes, corev1.Volume{
			Name:         v.Name,
			VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}},
		})
		mounts = append(mounts, corev1.VolumeMount{Name: v.Name, MountPath: "/" + v.Name})
	}

	labels := map[string]string{
		"app.kubernetes.io/name":      "gitfrok-ci-runner",
		"gitfrok.io/tenant-id":        sandbox.TenantID,
		"gitfrok.io/repository-id":    sandbox.RepositoryID,
		"gitfrok.io/job-id":           sandbox.JobID,
		"gitfrok.io/attempt-id":       sandbox.AttemptID,
		"gitfrok.io/configuration":    sandbox.ConfigurationDigest,
		"gitfrok.io/default-deny-net": fmt.Sprintf("%t", sandbox.DefaultDenyNetwork),
	}

	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      jobName(sandbox.AttemptID),
			Namespace: namespace,
			Labels:    labels,
		},
		Spec: batchv1.JobSpec{
			BackoffLimit:            backoffLimit,
			TTLSecondsAfterFinished: ttlSecondsAfterFinish,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{
					RuntimeClassName:             &sandbox.RuntimeClass,
					RestartPolicy:                corev1.RestartPolicyNever,
					AutomountServiceAccountToken: no,
					HostNetwork:                  sandbox.HostNetwork,
					HostPID:                      sandbox.HostPID,
					HostIPC:                      sandbox.HostIPC,
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot: yes,
						RunAsUser:    runAsUser,
					},
					Volumes: volumes,
					Containers: []corev1.Container{{
						Name:    "runner",
						Image:   sandbox.Image,
						Command: sandbox.Command,
						Env: []corev1.EnvVar{
							{Name: "GITFROK_SOURCE_ENDPOINT", Value: sandbox.SourceEndpoint},
							{Name: "GITFROK_SOURCE_CAPABILITY", Value: sandbox.SourceCapability},
							{Name: "GITFROK_COMMIT_SHA", Value: sandbox.CommitSHA},
						},
						VolumeMounts: mounts,
						SecurityContext: &corev1.SecurityContext{
							Privileged:               &sandbox.Privileged,
							AllowPrivilegeEscalation: &sandbox.AllowPrivilegeEscalation,
							ReadOnlyRootFilesystem:   &sandbox.ReadOnlyRootFilesystem,
							Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
						},
					}},
				},
			},
		},
	}, nil
}
