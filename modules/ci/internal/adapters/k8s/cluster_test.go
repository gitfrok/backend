package k8s

import (
	"context"
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/gitfrok/backend/modules/ci/api"
)

func clusterClient(t *testing.T) (*ClusterClient, *fake.Clientset) {
	t.Helper()
	clientset := fake.NewSimpleClientset()
	return NewClusterClientFor(clientset.BatchV1().Jobs("gitfrok-ci"), "gitfrok-ci"), clientset
}

func complete(name string, condition batchv1.JobConditionType, reason string) *batchv1.Job {
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "gitfrok-ci"},
		Status: batchv1.JobStatus{Conditions: []batchv1.JobCondition{{
			Type: condition, Status: corev1.ConditionTrue, Reason: reason,
		}}},
	}
}

// The whole point of the launcher is that one attempt produces one sandbox, so a
// second create under the same name must fail rather than start another.
func TestCreateRefusesASecondJobForTheSameAttempt(t *testing.T) {
	client, _ := clusterClient(t)
	job := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "ci-attempt-1", Namespace: "gitfrok-ci"}}

	if err := client.Create(context.Background(), job); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := client.Create(context.Background(), job); err == nil {
		t.Fatal("a second create for the same attempt was accepted")
	}
}

// The namespace is per-environment configuration. A job aimed anywhere else does
// not reach the API server.
func TestCreateRefusesAJobForAnotherNamespace(t *testing.T) {
	client, clientset := clusterClient(t)
	job := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "ci-attempt-1", Namespace: "kube-system"}}

	if err := client.Create(context.Background(), job); err == nil {
		t.Fatal("a job for another namespace was accepted")
	}
	jobs, err := clientset.BatchV1().Jobs("kube-system").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(jobs.Items) != 0 {
		t.Fatalf("the refused job still reached the API server: %+v", jobs.Items)
	}
}

func TestAwaitTerminalReportsCompletion(t *testing.T) {
	client, clientset := clusterClient(t)
	watcher := clientset.BatchV1().Jobs("gitfrok-ci")
	if _, err := watcher.Create(context.Background(), complete("ci-attempt-1", "", ""), metav1.CreateOptions{}); err != nil {
		t.Fatalf("seeding the job: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() {
		// The fake clientset only emits watch events for changes made after the
		// watch is open, so the terminal condition is applied here.
		time.Sleep(20 * time.Millisecond)
		_, _ = watcher.Update(ctx, complete("ci-attempt-1", batchv1.JobComplete, "Completed"), metav1.UpdateOptions{})
	}()

	succeeded, summary, err := client.AwaitTerminal(ctx, "ci-attempt-1")
	if err != nil {
		t.Fatalf("AwaitTerminal: %v", err)
	}
	if !succeeded || summary == "" {
		t.Fatalf("AwaitTerminal = %t/%q, want a successful terminal state", succeeded, summary)
	}
}

func TestAwaitTerminalReportsFailureWithItsReason(t *testing.T) {
	client, clientset := clusterClient(t)
	watcher := clientset.BatchV1().Jobs("gitfrok-ci")
	if _, err := watcher.Create(context.Background(), complete("ci-attempt-1", "", ""), metav1.CreateOptions{}); err != nil {
		t.Fatalf("seeding the job: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() {
		time.Sleep(20 * time.Millisecond)
		_, _ = watcher.Update(ctx, complete("ci-attempt-1", batchv1.JobFailed, "BackoffLimitExceeded"), metav1.UpdateOptions{})
	}()

	succeeded, summary, err := client.AwaitTerminal(ctx, "ci-attempt-1")
	if err != nil {
		t.Fatalf("AwaitTerminal: %v", err)
	}
	if succeeded {
		t.Fatal("a failed job was reported as successful")
	}
	if summary != "BackoffLimitExceeded" {
		t.Fatalf("summary = %q, want the failure reason", summary)
	}
}

// A sandbox removed out from under the attempt is a terminal failure, not
// something to keep waiting on and not a success.
func TestAwaitTerminalTreatsDeletionAsFailure(t *testing.T) {
	client, clientset := clusterClient(t)
	watcher := clientset.BatchV1().Jobs("gitfrok-ci")
	if _, err := watcher.Create(context.Background(), complete("ci-attempt-1", "", ""), metav1.CreateOptions{}); err != nil {
		t.Fatalf("seeding the job: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() {
		time.Sleep(20 * time.Millisecond)
		_ = watcher.Delete(ctx, "ci-attempt-1", metav1.DeleteOptions{})
	}()

	succeeded, _, err := client.AwaitTerminal(ctx, "ci-attempt-1")
	if err != nil {
		t.Fatalf("AwaitTerminal: %v", err)
	}
	if succeeded {
		t.Fatal("a deleted job was reported as successful")
	}
}

// A cancelled wait is an error, so the attempt reports cleanup uncertainty rather
// than a clean outcome it never observed.
func TestAwaitTerminalFailsWhenTheContextEnds(t *testing.T) {
	client, clientset := clusterClient(t)
	if _, err := clientset.BatchV1().Jobs("gitfrok-ci").Create(context.Background(), complete("ci-attempt-1", "", ""), metav1.CreateOptions{}); err != nil {
		t.Fatalf("seeding the job: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := client.AwaitTerminal(ctx, "ci-attempt-1"); err == nil {
		t.Fatal("a cancelled wait reported a terminal state it never observed")
	}
}

func TestDeleteRemovesTheJob(t *testing.T) {
	client, clientset := clusterClient(t)
	job := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "ci-attempt-1", Namespace: "gitfrok-ci"}}
	if err := client.Create(context.Background(), job); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := client.Delete(context.Background(), "ci-attempt-1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	remaining, err := clientset.BatchV1().Jobs("gitfrok-ci").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(remaining.Items) != 0 {
		t.Fatalf("the sandbox survived deletion: %+v", remaining.Items)
	}
}

// An unconfirmed deletion must surface as an error so the attempt can fail.
func TestDeleteOfAnUnknownJobIsAnError(t *testing.T) {
	client, _ := clusterClient(t)
	if err := client.Delete(context.Background(), "ci-attempt-missing"); err == nil {
		t.Fatal("deleting a job that is not there was reported as confirmed cleanup")
	}
}

// The launcher composes with the real cluster client, not only with a test double.
func TestLauncherRunsAnAttemptThroughTheClusterClient(t *testing.T) {
	client, clientset := clusterClient(t)
	launcher := NewLauncher(client, "gitfrok-ci")

	attempt, err := launcher.Launch(context.Background(), testJob(), testRunnerConfig())
	if err != nil {
		t.Fatalf("Launch: %v", err)
	}
	created, err := clientset.BatchV1().Jobs("gitfrok-ci").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(created.Items) != 1 {
		t.Fatalf("Launch created %d jobs, want 1", len(created.Items))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	name := created.Items[0].Name
	go func() {
		time.Sleep(20 * time.Millisecond)
		_, _ = clientset.BatchV1().Jobs("gitfrok-ci").Update(ctx, complete(name, batchv1.JobComplete, "Completed"), metav1.UpdateOptions{})
	}()

	state, _, err := attempt.Await(ctx)
	if err != nil {
		t.Fatalf("Await: %v", err)
	}
	if state != api.JobSucceeded {
		t.Fatalf("state = %s, want SUCCEEDED", state)
	}
	remaining, err := clientset.BatchV1().Jobs("gitfrok-ci").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(remaining.Items) != 0 {
		t.Fatalf("the sandbox was not destroyed after the attempt: %+v", remaining.Items)
	}
}
