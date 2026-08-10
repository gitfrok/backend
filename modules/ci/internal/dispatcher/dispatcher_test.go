package dispatcher

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gitfrok/backend/modules/ci/api"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
	"github.com/gitfrok/backend/platform/bus"
)

type fakeStore struct {
	jobs map[string]api.Job
}

func newFakeStore() *fakeStore { return &fakeStore{jobs: map[string]api.Job{}} }
func (s *fakeStore) CreateOrGet(_ context.Context, key string, candidate api.Job) (api.Job, bool, error) {
	return candidate, true, nil
}
func (s *fakeStore) Get(_ context.Context, id string) (api.Job, error) {
	j, ok := s.jobs[id]
	if !ok {
		return api.Job{}, errors.New("not found")
	}
	return j, nil
}
func (s *fakeStore) Save(_ context.Context, job api.Job) error {
	if _, ok := s.jobs[job.ID]; !ok {
		return errors.New("not found")
	}
	s.jobs[job.ID] = job
	return nil
}

type fakeQueue struct {
	enqueued, cancelled, claimable []string
}

func (q *fakeQueue) Enqueue(_ context.Context, id string) error {
	q.enqueued = append(q.enqueued, id)
	q.claimable = append(q.claimable, id)
	return nil
}

func (q *fakeQueue) Cancel(_ context.Context, id string) error {
	q.cancelled = append(q.cancelled, id)
	return nil
}

func (q *fakeQueue) Claim(_ context.Context) (string, bool, error) {
	if len(q.claimable) == 0 {
		return "", false, nil
	}
	id := q.claimable[0]
	q.claimable = q.claimable[1:]
	return id, true, nil
}

func (q *fakeQueue) Depth(_ context.Context) (int64, error) { return int64(len(q.claimable)), nil }

type fakeGauge struct{ values []int64 }

func (g *fakeGauge) Set(n int64) { g.values = append(g.values, n) }

type fakeLauncher struct {
	launched []fakeLaunch
	fail     bool
}

type fakeLaunch struct {
	jobID, attemptID, sha, digest string
	config                        Config
}

func (l *fakeLauncher) Launch(_ context.Context, job api.Job, cfg Config) (Attempt, error) {
	l.launched = append(l.launched, fakeLaunch{jobID: job.ID, attemptID: job.AttemptID, sha: job.CommitSHA, digest: job.ConfigurationDigest, config: cfg})
	if l.fail {
		return nil, errors.New("launch failed")
	}
	return &fakeAttempt{state: api.JobSucceeded, summary: "passed"}, nil
}

type fakeAttempt struct {
	state   api.JobState
	summary string
}

func (a *fakeAttempt) Await(_ context.Context) (api.JobState, string, error) {
	return a.state, a.summary, nil
}

type allowPDP struct{}

func (allowPDP) Decide(_ context.Context, _ policyapi.Request) (policyapi.Decision, error) {
	return policyapi.Decision{Allowed: true, DecisionID: "decision-1"}, nil
}

// testConfig is the environment-resolved runner configuration cmd/ would supply.
var testConfig = Config{
	RuntimeClass:     "gvisor",
	Image:            "ghcr.io/gitfrok/ci-runner@sha256:" + strings.Repeat("a", 64),
	SourceEndpoint:   "git-storaged:9000",
	SourceCapability: "read-only-source",
	Command:          []string{"/usr/bin/gitfrok-ci"},
}

func newTestDispatcher(t *testing.T, launcher Launcher, opts ...Option) (*Dispatcher, *fakeStore, *fakeQueue) {
	t.Helper()
	store := newFakeStore()
	store.jobs["job-1"] = api.Job{ID: "job-1", TenantID: "tenant-a", RepositoryID: "repo-a", ActorID: "actor-a", Ref: "refs/heads/main", CommitSHA: "sha-a", ConfigurationDigest: "config-a", State: api.JobQueued, QueuedAt: time.Now()}
	queue := &fakeQueue{}
	bus := bus.NewInProcess()
	d := New(queue, store, launcher, allowPDP{}, bus, append([]Option{WithConfig(testConfig)}, opts...)...)
	return d, store, queue
}

func TestDispatchOneLaunchesSandboxAndReachesTerminal(t *testing.T) {
	launcher := &fakeLauncher{}
	d, store, _ := newTestDispatcher(t, launcher)
	if err := d.DispatchOne(context.Background(), "job-1"); err != nil {
		t.Fatalf("DispatchOne: %v", err)
	}
	if len(launcher.launched) != 1 {
		t.Fatalf("expected 1 launch, got %d", len(launcher.launched))
	}
	if launcher.launched[0].sha != "sha-a" || launcher.launched[0].digest != "config-a" {
		t.Fatalf("launched = %+v", launcher.launched[0])
	}
	job := store.jobs["job-1"]
	if job.State != api.JobSucceeded {
		t.Fatalf("job state = %s, want SUCCEEDED", job.State)
	}
	if job.AttemptID == "" || job.StartedAt == nil || job.FinishedAt == nil {
		t.Fatalf("job missing attempt/lifecycle: %+v", job)
	}
}

func TestDispatchOneLaunchFailureIsTerminalFailed(t *testing.T) {
	launcher := &fakeLauncher{fail: true}
	d, store, _ := newTestDispatcher(t, launcher)
	if err := d.DispatchOne(context.Background(), "job-1"); err != nil {
		t.Fatalf("DispatchOne: %v", err)
	}
	job := store.jobs["job-1"]
	if job.State != api.JobFailed {
		t.Fatalf("job state = %s, want FAILED", job.State)
	}
}

func TestDispatchOneOnlyRunsQueuedJobs(t *testing.T) {
	launcher := &fakeLauncher{}
	d, store, _ := newTestDispatcher(t, launcher)
	store.jobs["job-2"] = api.Job{ID: "job-2", TenantID: "tenant-a", State: api.JobRunning}
	if err := d.DispatchOne(context.Background(), "job-2"); err == nil {
		t.Fatal("expected error for non-queued job")
	}
}

// The launched sandbox must carry the runner configuration resolved by cmd/, not
// anything derived from the job: a tenant cannot choose its own runtime class,
// image, or source capability (SPEC-0020 AC4, T-0017 AC3).
func TestLaunchUsesTheEnvironmentResolvedRunnerConfiguration(t *testing.T) {
	launcher := &fakeLauncher{}
	d, _, _ := newTestDispatcher(t, launcher)
	if err := d.DispatchOne(context.Background(), "job-1"); err != nil {
		t.Fatalf("DispatchOne: %v", err)
	}
	got := launcher.launched[0]
	if !reflect.DeepEqual(got.config, testConfig) {
		t.Fatalf("launch config = %+v, want %+v", got.config, testConfig)
	}
	if got.attemptID == "" {
		t.Fatal("launch did not receive the dispatcher-assigned attempt ID")
	}
}

// Tick is the loop body KEDA scales: it must publish queue depth and claim at
// most one job per iteration (T-0017 AC2).
func TestTickPublishesQueueDepthAndClaimsOneJob(t *testing.T) {
	launcher := &fakeLauncher{}
	gauge := &fakeGauge{}
	d, store, queue := newTestDispatcher(t, launcher, WithGauge(gauge))
	store.jobs["job-2"] = api.Job{ID: "job-2", TenantID: "tenant-a", RepositoryID: "repo-a", ActorID: "actor-a", Ref: "refs/heads/main", CommitSHA: "sha-b", ConfigurationDigest: "config-b", State: api.JobQueued, QueuedAt: time.Now()}
	for _, id := range []string{"job-1", "job-2"} {
		if err := queue.Enqueue(context.Background(), id); err != nil {
			t.Fatalf("Enqueue: %v", err)
		}
	}

	if err := d.Tick(context.Background()); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if len(launcher.launched) != 1 {
		t.Fatalf("expected exactly 1 launch per tick, got %d", len(launcher.launched))
	}
	if len(gauge.values) != 1 || gauge.values[0] != 2 {
		t.Fatalf("gauge = %v, want the queue depth [2] observed before the claim", gauge.values)
	}

	if err := d.Tick(context.Background()); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if len(launcher.launched) != 2 {
		t.Fatalf("expected the second job dispatched on the next tick, got %d launches", len(launcher.launched))
	}
	if gauge.values[1] != 1 {
		t.Fatalf("gauge after one claim = %d, want 1", gauge.values[1])
	}

	// An empty queue is not an error and launches nothing.
	if err := d.Tick(context.Background()); err != nil {
		t.Fatalf("Tick on an empty queue: %v", err)
	}
	if len(launcher.launched) != 2 {
		t.Fatalf("empty queue launched a sandbox: %d", len(launcher.launched))
	}
}

// A claimed job leaves the queue, so a second dispatcher replica cannot claim it
// and launch a second sandbox for the same job (SPEC-0020 AC2).
func TestClaimedJobIsNotClaimedTwice(t *testing.T) {
	launcher := &fakeLauncher{}
	d, _, queue := newTestDispatcher(t, launcher)
	if err := queue.Enqueue(context.Background(), "job-1"); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if err := d.Tick(context.Background()); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if err := d.Tick(context.Background()); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if len(launcher.launched) != 1 {
		t.Fatalf("job launched %d times, want exactly 1", len(launcher.launched))
	}
}
