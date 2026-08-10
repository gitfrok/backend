package k8s

import (
	"context"
	"errors"
	"fmt"

	batchv1 "k8s.io/api/batch/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// BatchJobs is the slice of client-go this adapter uses. Naming it keeps the
// cluster client testable against client-go's own fake clientset rather than
// against a hand-written double that could drift from the real API.
type BatchJobs interface {
	Create(ctx context.Context, job *batchv1.Job, opts metav1.CreateOptions) (*batchv1.Job, error)
	Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error
	Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error)
}

// ClusterClient runs job attempts as Kubernetes Jobs in one namespace.
type ClusterClient struct {
	jobs      BatchJobs
	namespace string
}

// NewClusterClient builds a client from the pod's own service account when it
// runs in a cluster, and from kubeconfigPath otherwise. The namespace is
// per-environment configuration; it is never derived from a job or a tenant.
func NewClusterClient(kubeconfigPath, namespace string) (*ClusterClient, error) {
	if namespace == "" {
		return nil, errors.New("ci k8s: no namespace configured for the runner")
	}
	config, err := restConfig(kubeconfigPath)
	if err != nil {
		return nil, err
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("ci k8s: build cluster client: %w", err)
	}
	return NewClusterClientFor(clientset.BatchV1().Jobs(namespace), namespace), nil
}

// NewClusterClientFor wraps an already-built namespaced Jobs client.
func NewClusterClientFor(jobs BatchJobs, namespace string) *ClusterClient {
	return &ClusterClient{jobs: jobs, namespace: namespace}
}

func restConfig(kubeconfigPath string) (*rest.Config, error) {
	if kubeconfigPath == "" {
		config, err := rest.InClusterConfig()
		if err != nil {
			return nil, fmt.Errorf("ci k8s: no in-cluster configuration and no kubeconfig: %w", err)
		}
		return config, nil
	}
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	if err != nil {
		return nil, fmt.Errorf("ci k8s: kubeconfig at %s: %w", kubeconfigPath, err)
	}
	return config, nil
}

// Create submits the Job. An already-existing name is an error rather than a
// second sandbox for the same attempt, which is why the name is derived from the
// attempt ID.
func (c *ClusterClient) Create(ctx context.Context, job *batchv1.Job) error {
	if job.Namespace != c.namespace {
		return fmt.Errorf("ci k8s: job namespace %q is not the configured %q", job.Namespace, c.namespace)
	}
	if _, err := c.jobs.Create(ctx, job, metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("ci k8s: create job %s: %w", job.Name, err)
	}
	return nil
}

// AwaitTerminal blocks until the Job either succeeds or fails. A closed watch is
// reopened; a cancelled context ends the wait with an error, which the attempt
// reports as a failure rather than as a clean run.
func (c *ClusterClient) AwaitTerminal(ctx context.Context, name string) (bool, string, error) {
	for {
		watcher, err := c.jobs.Watch(ctx, metav1.ListOptions{
			FieldSelector: fields.OneTermEqualSelector("metadata.name", name).String(),
		})
		if err != nil {
			return false, "", fmt.Errorf("ci k8s: watch job %s: %w", name, err)
		}
		succeeded, summary, terminal, err := awaitOnce(ctx, watcher)
		watcher.Stop()
		if err != nil {
			return false, "", err
		}
		if terminal {
			return succeeded, summary, nil
		}
		// The watch closed without a terminal condition — reopen and keep waiting.
	}
}

func awaitOnce(ctx context.Context, watcher watch.Interface) (succeeded bool, summary string, terminal bool, err error) {
	for {
		select {
		case <-ctx.Done():
			return false, "", false, ctx.Err()
		case event, open := <-watcher.ResultChan():
			if !open {
				return false, "", false, nil
			}
			job, ok := event.Object.(*batchv1.Job)
			if !ok {
				continue
			}
			if event.Type == watch.Deleted {
				// Something removed the sandbox out from under the attempt. That is
				// not a successful run, and it is not something to keep waiting on.
				return false, "sandbox deleted before it terminated", true, nil
			}
			if state, reason, done := terminalCondition(job); done {
				return state, reason, true, nil
			}
		}
	}
}

func terminalCondition(job *batchv1.Job) (succeeded bool, summary string, terminal bool) {
	for _, condition := range job.Status.Conditions {
		if condition.Status != "True" {
			continue
		}
		switch condition.Type {
		case batchv1.JobComplete:
			return true, "sandbox completed", true
		case batchv1.JobFailed:
			reason := condition.Reason
			if reason == "" {
				reason = "sandbox failed"
			}
			return false, reason, true
		}
	}
	return false, "", false
}

// Delete removes the Job and, through foreground propagation, the pod it created.
// An error here means cleanup is unconfirmed, which the attempt surfaces as a
// failure: an ephemeral sandbox that may still exist is not a clean run.
func (c *ClusterClient) Delete(ctx context.Context, name string) error {
	propagation := metav1.DeletePropagationForeground
	if err := c.jobs.Delete(ctx, name, metav1.DeleteOptions{PropagationPolicy: &propagation}); err != nil {
		return fmt.Errorf("ci k8s: delete job %s: %w", name, err)
	}
	return nil
}

var _ Client = (*ClusterClient)(nil)
