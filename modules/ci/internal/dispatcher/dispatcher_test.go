package dispatcher

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gitfrok/backend/modules/ci/api"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
	"github.com/gitfrok/backend/platform/bus"
)

type fakeStore struct {
	mu   sync.Mutex
	jobs map[string]api.Job
}

func newFakeStore() *fakeStore { return &fakeStore{jobs: map[string]api.Job{}} }
func (s *fakeStore) CreateOrGet(_ context.Context, key string, candidate api.Job) (api.Job, bool, error) {
	return candidate, true, nil
}
func (s *fakeStore) Get(_ context.Context, id string) (api.Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[id]
	if !ok {
		return api.Job{}, errors.New("not found")
	}
	return j, nil
}
func (s *fakeStore) Save(_ context.Context, job api.Job) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.jobs[job.ID]; !ok {
		return errors.New("not found")
	}
	s.jobs[job.ID] = job
	return nil
}

// put seeds a job for a test; get reads one back. Both keep the test's direct
// access race-free against the async dispatch goroutines.
func (s *fakeStore) put(job api.Job) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.jobs[job.ID] = job
}
func (s *fakeStore) get(id string) (api.Job, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[id]
	return j, ok
}

type fakeQueue struct {
	mu                             sync.Mutex
	enqueued, cancelled, claimable []string
}

func (q *fakeQueue) Enqueue(_ context.Context, id string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.enqueued = append(q.enqueued, id)
	q.claimable = append(q.claimable, id)
	return nil
}

func (q *fakeQueue) Cancel(_ context.Context, id string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.cancelled = append(q.cancelled, id)
	return nil
}

func (q *fakeQueue) Claim(_ context.Context) (string, bool, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.claimable) == 0 {
		return "", false, nil
	}
	id := q.claimable[0]
	q.claimable = q.claimable[1:]
	return id, true, nil
}

func (q *fakeQueue) Depth(_ context.Context) (int64, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return int64(len(q.claimable)), nil
}

func (q *fakeQueue) claimableCount() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.claimable)
}
func (q *fakeQueue) cancelledCount() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.cancelled)
}

type fakeGauge struct {
	mu     sync.Mutex
	values []int64
}

func (g *fakeGauge) Set(n int64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.values = append(g.values, n)
}
func (g *fakeGauge) count() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.values)
}
func (g *fakeGauge) at(i int) int64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.values[i]
}

type fakeLauncher struct {
	mu       sync.Mutex
	launched []fakeLaunch
	fail     bool
}

type fakeLaunch struct {
	jobID, attemptID, sha, digest string
	config                        Config
}

func (l *fakeLauncher) Launch(_ context.Context, job api.Job, cfg Config) (Attempt, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.launched = append(l.launched, fakeLaunch{jobID: job.ID, attemptID: job.AttemptID, sha: job.CommitSHA, digest: job.ConfigurationDigest, config: cfg})
	if l.fail {
		return nil, errors.New("launch failed")
	}
	return &fakeAttempt{state: api.JobSucceeded, summary: "passed"}, nil
}
func (l *fakeLauncher) launchCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.launched)
}
func (l *fakeLauncher) first() fakeLaunch {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.launched[0]
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
	store.put(api.Job{ID: "job-1", TenantID: "tenant-a", RepositoryID: "repo-a", ActorID: "actor-a", Ref: "refs/heads/main", CommitSHA: "sha-a", ConfigurationDigest: "config-a", State: api.JobQueued, QueuedAt: time.Now()})
	queue := &fakeQueue{}
	bus := bus.NewInProcess()
	d := New(queue, store, launcher, allowPDP{}, bus, append([]Option{WithConfig(testConfig)}, opts...)...)
	return d, store, queue
}

func TestDispatchOneLaunchesSandboxAndReachesTerminal(t *testing.T) {
	launcher := &fakeLauncher{}
	d, store, _ := newTestDispatcher(t, launcher)
	if err := d.DispatchOne(t.Context(), "job-1"); err != nil {
		t.Fatalf("DispatchOne: %v", err)
	}
	if launcher.launchCount() != 1 {
		t.Fatalf("expected 1 launch, got %d", launcher.launchCount())
	}
	if got := launcher.first(); got.sha != "sha-a" || got.digest != "config-a" {
		t.Fatalf("launched = %+v", got)
	}
	job, _ := store.get("job-1")
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
	if err := d.DispatchOne(t.Context(), "job-1"); err != nil {
		t.Fatalf("DispatchOne: %v", err)
	}
	job, _ := store.get("job-1")
	if job.State != api.JobFailed {
		t.Fatalf("job state = %s, want FAILED", job.State)
	}
}

func TestDispatchOneOnlyRunsQueuedJobs(t *testing.T) {
	launcher := &fakeLauncher{}
	d, store, _ := newTestDispatcher(t, launcher)
	store.put(api.Job{ID: "job-2", TenantID: "tenant-a", State: api.JobRunning})
	if err := d.DispatchOne(t.Context(), "job-2"); err == nil {
		t.Fatal("expected error for non-queued job")
	}
}

// The launched sandbox must carry the runner configuration resolved by cmd/, not
// anything derived from the job: a tenant cannot choose its own runtime class,
// image, or source capability (SPEC-0020 AC4, T-0017 AC3).
func TestLaunchUsesTheEnvironmentResolvedRunnerConfiguration(t *testing.T) {
	launcher := &fakeLauncher{}
	d, _, _ := newTestDispatcher(t, launcher)
	if err := d.DispatchOne(t.Context(), "job-1"); err != nil {
		t.Fatalf("DispatchOne: %v", err)
	}
	got := launcher.first()
	if !reflect.DeepEqual(got.config, testConfig) {
		t.Fatalf("launch config = %+v, want %+v", got.config, testConfig)
	}
	if got.attemptID == "" {
		t.Fatal("launch did not receive the dispatcher-assigned attempt ID")
	}
}

// Tick is the loop body KEDA scales: it must publish queue depth and claim at
// most one job per iteration (T-0017 AC2). Dispatch is async, so the test waits
// for each launch to land.
func TestTickPublishesQueueDepthAndClaimsOneJob(t *testing.T) {
	launcher := &fakeLauncher{}
	gauge := &fakeGauge{}
	d, store, queue := newTestDispatcher(t, launcher, WithGauge(gauge))
	store.put(api.Job{ID: "job-2", TenantID: "tenant-a", RepositoryID: "repo-a", ActorID: "actor-a", Ref: "refs/heads/main", CommitSHA: "sha-b", ConfigurationDigest: "config-b", State: api.JobQueued, QueuedAt: time.Now()})
	for _, id := range []string{"job-1", "job-2"} {
		if err := queue.Enqueue(t.Context(), id); err != nil {
			t.Fatalf("Enqueue: %v", err)
		}
	}

	if err := d.Tick(t.Context()); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	waitFor(t, 2*time.Second, func() bool { return launcher.launchCount() == 1 }, "exactly one launch per tick")
	if gauge.count() != 1 || gauge.at(0) != 2 {
		t.Fatalf("gauge = %d values, first=%d; want the queue depth [2] observed before the claim", gauge.count(), gauge.at(0))
	}

	if err := d.Tick(t.Context()); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	waitFor(t, 2*time.Second, func() bool { return launcher.launchCount() == 2 }, "the second job dispatches on the next tick")
	if gauge.at(1) != 1 {
		t.Fatalf("gauge after one claim = %d, want 1", gauge.at(1))
	}

	// An empty queue is not an error and launches nothing.
	if err := d.Tick(t.Context()); err != nil {
		t.Fatalf("Tick on an empty queue: %v", err)
	}
	d.WaitIdle()
	if launcher.launchCount() != 2 {
		t.Fatalf("empty queue launched a sandbox: %d", launcher.launchCount())
	}
}

// A claimed job leaves the queue, so a second dispatcher replica cannot claim it
// and launch a second sandbox for the same job (SPEC-0020 AC2).
func TestClaimedJobIsNotClaimedTwice(t *testing.T) {
	launcher := &fakeLauncher{}
	d, _, queue := newTestDispatcher(t, launcher)
	if err := queue.Enqueue(t.Context(), "job-1"); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if err := d.Tick(t.Context()); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if err := d.Tick(t.Context()); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	d.WaitIdle()
	if launcher.launchCount() != 1 {
		t.Fatalf("job launched %d times, want exactly 1", launcher.launchCount())
	}
}

// ---------------------------------------------------------------------------
// Fair-use envelope throttle (SPEC-0041 AC5/AC9, T-0035)
// ---------------------------------------------------------------------------

// fakeThrottle is a mutable EnvelopeThrottle the tests retune mid-flight.
type fakeThrottle struct {
	mu       sync.Mutex
	maxCI    int32
	queueCap int64
}

func (f *fakeThrottle) MaxCIConcurrency() int32 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.maxCI
}
func (f *fakeThrottle) QueueDepthCap() int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.queueCap
}
func (f *fakeThrottle) set(maxCI int32, queueCap int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.maxCI, f.queueCap = maxCI, queueCap
}

// blockingLauncher holds every dispatched sandbox in flight until release, so a
// test can pin the in-flight count at the claim gate.
type blockingLauncher struct {
	mu       sync.Mutex
	launched []string
	done     chan struct{}
}

func newBlockingLauncher() *blockingLauncher { return &blockingLauncher{done: make(chan struct{})} }
func (l *blockingLauncher) Launch(_ context.Context, job api.Job, _ Config) (Attempt, error) {
	l.mu.Lock()
	l.launched = append(l.launched, job.ID)
	l.mu.Unlock()
	return &blockingAttempt{done: l.done}, nil
}
func (l *blockingLauncher) release() { close(l.done) }
func (l *blockingLauncher) launchCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.launched)
}

type blockingAttempt struct{ done chan struct{} }

func (a *blockingAttempt) Await(ctx context.Context) (api.JobState, string, error) {
	select {
	case <-a.done:
		return api.JobSucceeded, "done", nil
	case <-ctx.Done():
		return api.JobFailed, "cancelled", ctx.Err()
	}
}

// waitFor polls cond until it holds or the deadline passes.
func waitFor(t *testing.T, timeout time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("%s", msg)
}

// queuedJob is a minimal queued job seeded at a known time, for throttle tests.
func queuedJob(id string, queuedAt time.Time) api.Job {
	return api.Job{ID: id, TenantID: "tenant-a", RepositoryID: "repo-a", ActorID: "actor-a", Ref: "refs/heads/main", CommitSHA: "sha-" + id, ConfigurationDigest: "cfg-" + id, State: api.JobQueued, QueuedAt: queuedAt}
}

// newThrottledDispatcher wires a dispatcher over a blocking launcher and a
// throttle, with a fixed clock so delay-window comparisons are deterministic.
func newThrottledDispatcher(throttle EnvelopeThrottle, launcher Launcher, gauge Gauge, base time.Time) (*Dispatcher, *fakeStore, *fakeQueue) {
	store := newFakeStore()
	queue := &fakeQueue{}
	opts := []Option{WithConfig(testConfig), WithEnvelopeThrottle(throttle), WithClock(func() time.Time { return base })}
	if gauge != nil {
		opts = append(opts, WithGauge(gauge))
	}
	d := New(queue, store, launcher, allowPDP{}, bus.NewInProcess(), opts...)
	return d, store, queue
}

// Below the cap the claim gate binds nothing: every queued job dispatches
// (SPEC-0041 AC5 — the throttle only reduces, never below what is stated).
func TestClaimGateBelowCapDispatchesFreely(t *testing.T) {
	base := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	launcher := newBlockingLauncher()
	throttle := &fakeThrottle{maxCI: 3}
	d, store, queue := newThrottledDispatcher(throttle, launcher, nil, base)
	for i, id := range []string{"job-1", "job-2"} {
		store.put(queuedJob(id, base.Add(-time.Duration(i+1)*time.Second)))
		_ = queue.Enqueue(t.Context(), id)
	}
	if err := d.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := d.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 2*time.Second, func() bool { return launcher.launchCount() == 2 }, "both jobs below the cap should dispatch")
	if d.InFlight() != 2 {
		t.Fatalf("in-flight = %d, want 2", d.InFlight())
	}
	launcher.release()
	d.WaitIdle()
}

// At the cap the claim gate refuses to claim: queued jobs are DELAYED, never
// dropped and never cancelled, and dispatch resumes once in-flight falls below
// the cap (SPEC-0041 AC5, T-0035 AC3/AC4).
func TestClaimGateAtCapDelaysNotDrops(t *testing.T) {
	base := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	launcher := newBlockingLauncher()
	throttle := &fakeThrottle{maxCI: 1}
	d, store, queue := newThrottledDispatcher(throttle, launcher, nil, base)
	for i, id := range []string{"job-1", "job-2", "job-3"} {
		store.put(queuedJob(id, base.Add(-time.Duration(i+1)*time.Second)))
		_ = queue.Enqueue(t.Context(), id)
	}

	// First tick dispatches job-1, taking in-flight to the cap.
	if err := d.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 2*time.Second, func() bool { return launcher.launchCount() == 1 }, "job-1 should dispatch")

	// While at the cap, further ticks claim nothing: job-2/job-3 stay queued.
	for i := 0; i < 3; i++ {
		if err := d.Tick(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if launcher.launchCount() != 1 {
		t.Fatalf("cap breached: %d dispatched, want 1", launcher.launchCount())
	}
	if got := queue.claimableCount(); got != 2 {
		t.Fatalf("queued jobs dropped: %d remain, want 2", got)
	}
	if got := queue.cancelledCount(); got != 0 {
		t.Fatalf("cap cancelled %d queued jobs, want 0", got)
	}
	if d.InFlight() != 1 {
		t.Fatalf("in-flight = %d, want 1", d.InFlight())
	}

	// Release job-1 and drain: the delayed jobs dispatch, none lost.
	launcher.release()
	d.WaitIdle()
	for i := 0; i < 4; i++ {
		_ = d.Tick(t.Context())
		d.WaitIdle()
	}
	waitFor(t, 2*time.Second, func() bool { return launcher.launchCount() == 3 }, "all delayed jobs should eventually dispatch")
	if got := queue.cancelledCount(); got != 0 {
		t.Fatalf("delayed jobs were cancelled: %d", got)
	}
}

// The cap gates NEW claims only; it never cancels work already dispatched
// (SPEC-0041 AC4, T-0035 AC4).
func TestCapNeverCancelsRunningWork(t *testing.T) {
	base := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	launcher := newBlockingLauncher()
	throttle := &fakeThrottle{maxCI: 1}
	d, store, queue := newThrottledDispatcher(throttle, launcher, nil, base)
	store.put(queuedJob("job-1", base.Add(-time.Second)))
	_ = queue.Enqueue(t.Context(), "job-1")

	if err := d.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 2*time.Second, func() bool { return launcher.launchCount() == 1 }, "job-1 should dispatch")
	waitFor(t, 2*time.Second, func() bool {
		j, _ := store.get("job-1")
		return j.State == api.JobRunning
	}, "job-1 should reach RUNNING")

	// While it runs at the cap, repeated ticks must leave it running, not cancel it.
	for i := 0; i < 3; i++ {
		_ = d.Tick(t.Context())
	}
	if got := queue.cancelledCount(); got != 0 {
		t.Fatalf("running job cancelled: %d cancellations", got)
	}
	if j, _ := store.get("job-1"); j.State != api.JobRunning {
		t.Fatalf("running job state = %s, want RUNNING", j.State)
	}

	launcher.release()
	d.WaitIdle()
	if j, _ := store.get("job-1"); j.State != api.JobSucceeded {
		t.Fatalf("job-1 = %s, want SUCCEEDED", j.State)
	}
}

// A job queued when the claim gate held dispatch carries the delay's cause when
// it finally runs; a job dispatched before the delay opened carries none
// (SPEC-0041 AC5, T-0035 AC3).
func TestDelayedJobCarriesEnvelopeThrottleCause(t *testing.T) {
	base := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	launcher := newBlockingLauncher()
	throttle := &fakeThrottle{maxCI: 1}
	d, store, queue := newThrottledDispatcher(throttle, launcher, nil, base)
	store.put(queuedJob("job-1", base.Add(-2*time.Second)))
	store.put(queuedJob("job-2", base.Add(-time.Second))) // queued before the delay opens
	_ = queue.Enqueue(t.Context(), "job-1")
	_ = queue.Enqueue(t.Context(), "job-2")

	// Dispatch job-1 to the cap, then hold at the cap with job-2 waiting.
	if err := d.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 2*time.Second, func() bool { return launcher.launchCount() == 1 }, "job-1 should dispatch")
	if err := d.Tick(t.Context()); err != nil {
		t.Fatal(err)
	} // at cap: job-2 waiting -> delay opens at `base`

	launcher.release()
	d.WaitIdle()
	for i := 0; i < 4; i++ {
		_ = d.Tick(t.Context())
		d.WaitIdle()
	}
	waitFor(t, 2*time.Second, func() bool { return launcher.launchCount() == 2 }, "job-2 should dispatch after the delay")

	if j, _ := store.get("job-2"); j.DelayCause != api.DelayCauseEnvelopeThrottle {
		t.Fatalf("job-2 delay cause = %q, want %q", j.DelayCause, api.DelayCauseEnvelopeThrottle)
	}
	if j, _ := store.get("job-1"); j.DelayCause != "" {
		t.Fatalf("job-1 delay cause = %q, want empty (dispatched before the delay)", j.DelayCause)
	}
}

// The scaler-input half caps the queue-depth gauge KEDA reads, but never below
// the real depth when that is smaller (T-0035, SPEC-0041 AC5).
func TestQueueDepthGaugeCappedByEnvelope(t *testing.T) {
	base := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)

	// Depth 10, cap 5: KEDA reads the capped value.
	launcher := newBlockingLauncher()
	throttle := &fakeThrottle{maxCI: 0, queueCap: 5}
	gauge := &fakeGauge{}
	d, store, queue := newThrottledDispatcher(throttle, launcher, gauge, base)
	for i := 0; i < 10; i++ {
		id := fmt.Sprintf("job-%d", i)
		store.put(queuedJob(id, base.Add(-time.Second)))
		_ = queue.Enqueue(t.Context(), id)
	}
	if err := d.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if gauge.at(0) != 5 {
		t.Fatalf("gauge = %d, want the cap 5 (depth was 10)", gauge.at(0))
	}
	launcher.release()
	d.WaitIdle()

	// Depth 3, cap 5: the real depth is already below the cap and is published as-is.
	launcher2 := newBlockingLauncher()
	gauge2 := &fakeGauge{}
	d2, store2, queue2 := newThrottledDispatcher(&fakeThrottle{maxCI: 0, queueCap: 5}, launcher2, gauge2, base)
	for i := 0; i < 3; i++ {
		id := fmt.Sprintf("small-%d", i)
		store2.put(queuedJob(id, base.Add(-time.Second)))
		_ = queue2.Enqueue(t.Context(), id)
	}
	if err := d2.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if gauge2.at(0) != 3 {
		t.Fatalf("gauge = %d, want the real depth 3 (below the cap 5)", gauge2.at(0))
	}
	launcher2.release()
	d2.WaitIdle()
}

// A data plane that has never received envelope state runs unthrottled: fresh
// caps are 0/0, and a 0 cap binds nothing (T-0035 AC7).
func TestFreshCapsRunUnthrottled(t *testing.T) {
	caps := NewCaps()
	if caps.MaxCIConcurrency() != 0 || caps.QueueDepthCap() != 0 {
		t.Fatal("fresh caps must be unthrottled (0/0)")
	}
	base := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	launcher := newBlockingLauncher()
	d, store, queue := newThrottledDispatcher(caps, launcher, nil, base)
	for i, id := range []string{"j1", "j2", "j3"} {
		store.put(queuedJob(id, base.Add(-time.Duration(i+1)*time.Second)))
		_ = queue.Enqueue(t.Context(), id)
	}
	for i := 0; i < 3; i++ {
		if err := d.Tick(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, 2*time.Second, func() bool { return launcher.launchCount() == 3 }, "absence of a cap must dispatch everything")
	launcher.release()
	d.WaitIdle()
}

// The control plane publishes, the agent applies into the caps holder, and the
// claim gate observes the change live — then a 0 lifts the cap (T-0035 AC1/AC2,
// SPEC-0041 AC9 end to end on the shared holder).
func TestCapsUpdateIsObservedByClaimGate(t *testing.T) {
	caps := NewCaps()
	base := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	launcher := newBlockingLauncher()
	d, store, queue := newThrottledDispatcher(caps, launcher, nil, base)
	store.put(queuedJob("job-1", base.Add(-3*time.Second)))
	store.put(queuedJob("job-2", base.Add(-2*time.Second)))
	_ = queue.Enqueue(t.Context(), "job-1")
	_ = queue.Enqueue(t.Context(), "job-2")

	// Unthrottled: job-1 dispatches.
	if err := d.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 2*time.Second, func() bool { return launcher.launchCount() == 1 }, "job-1 should dispatch unthrottled")

	// The control plane states a cap of 1 (breach); the agent applies it here.
	if err := caps.ApplyEnvelopeCaps(1, 50); err != nil {
		t.Fatalf("ApplyEnvelopeCaps: %v", err)
	}
	if err := d.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if launcher.launchCount() != 1 {
		t.Fatalf("cap not observed: %d dispatched, want 1", launcher.launchCount())
	}
	if queue.claimableCount() != 1 {
		t.Fatalf("job-2 should remain queued while at the cap")
	}

	// The breach resolves; the control plane states 0 and the cap lifts.
	if err := caps.ApplyEnvelopeCaps(0, 0); err != nil {
		t.Fatalf("ApplyEnvelopeCaps: %v", err)
	}
	launcher.release()
	d.WaitIdle() // job-1 finishes, in-flight returns to 0
	for i := 0; i < 4; i++ {
		_ = d.Tick(t.Context())
		d.WaitIdle()
	}
	waitFor(t, 2*time.Second, func() bool { return launcher.launchCount() == 2 }, "lifting the cap must let job-2 dispatch")
}
