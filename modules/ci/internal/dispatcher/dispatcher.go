// Package dispatcher owns the CI dispatch loop: it claims one queued job,
// launches an isolated sandbox for it, waits for terminal cleanup, and records
// the outcome. The K8s adapter is injectable so the dispatch contract and
// audit-emission invariants are unit-testable without a cluster (SPEC-0020 AC3/AC7).
package dispatcher

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gitfrok/backend/modules/ci/api"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
	"github.com/gitfrok/backend/platform/audit"
	"github.com/gitfrok/backend/platform/bus"
	"github.com/gitfrok/backend/platform/ids"
)

// Launcher is the cluster adapter that turns a job+config into one ephemeral
// sandbox. Its only contract is: exactly one attempt per call, cleanup confirmed
// in the returned result. A production implementation creates a Kubernetes Job
// with the gVisor RuntimeClass and a unique service account (SPEC-0020 AC2/AC4).
type Launcher interface {
	// Launch creates an ephemeral sandbox for one job attempt. The returned
	// Attempt binds the job to exactly one sandbox lifecycle. The job already
	// carries the attempt ID the dispatcher assigned, so an adapter never invents
	// its own identity for the sandbox it creates.
	Launch(ctx context.Context, job api.Job, config Config) (Attempt, error)
}

// Attempt is the one-shot handle to a launched sandbox. Await blocks until the
// sandbox is gone and the attempt has reached a terminal state.
type Attempt interface {
	// Await blocks until the sandbox terminated and cleanup is confirmed.
	// It returns the terminal state, outcome summary, and any error indicating
	// cleanup uncertainty (which must surface as FAILED, never success).
	Await(ctx context.Context) (api.JobState, string, error)
}

// Config is the environment-resolved CI runner configuration. It is resolved once
// by cmd/ and never derived from a job, a request, or a repository's own files, so
// a tenant cannot influence the runtime class, the image, or the source capability.
type Config struct {
	RuntimeClass     string
	Image            string // must be digest-pinned (@sha256:...)
	SourceEndpoint   string
	SourceCapability string
	Command          []string
	SourceTTL        time.Duration
}

// Queue is the durable job queue. Enqueue/Cancel are best-effort idempotent;
// Claim removes exactly one queued job so that two dispatchers cannot launch two
// sandboxes for it. Depth is the value KEDA scales the runner deployment on.
type Queue interface {
	Enqueue(ctx context.Context, jobID string) error
	Cancel(ctx context.Context, jobID string) error
	// Claim returns the next queued job ID. ok is false when the queue is empty.
	Claim(ctx context.Context) (jobID string, ok bool, err error)
	// Depth is the number of jobs awaiting dispatch.
	Depth(ctx context.Context) (int64, error)
}

// Gauge is the queued-depth metric port. The dispatcher publishes queue depth to
// it on every tick; the plane binary exposes it in Prometheus exposition format
// for KEDA's scaler to read (SPEC-0020 AC3, T-0017 AC2).
type Gauge interface {
	Set(n int64)
}

// EnvelopeThrottle is the fair-use cap source the data plane applies from the
// control plane's envelope desired state (SPEC-0041 AC9, T-0035). The claim
// gate binds MaxCIConcurrency as a hard bound on in-flight dispatch; the scaler
// input caps the queue-depth gauge KEDA reads at QueueDepthCap. Both are
// fail-safe: a zero value means that half of the throttle does not bind, and an
// absent throttle runs unthrottled — absence is never a cap of zero (AC7).
type EnvelopeThrottle interface {
	// MaxCIConcurrency is the published in-flight cap. 0 = no cap.
	MaxCIConcurrency() int32
	// QueueDepthCap caps the queue-depth gauge KEDA reads. 0 = no cap.
	QueueDepthCap() int64
}

// Store is CI's job persistence port.
type Store interface {
	CreateOrGet(ctx context.Context, key string, job api.Job) (api.Job, bool, error)
	Get(ctx context.Context, jobID string) (api.Job, error)
	Save(ctx context.Context, job api.Job) error
}

// Caps is the thread-safe holder of the fair-use throttle caps the data plane
// applies from the control plane's envelope desired state (SPEC-0041 AC9,
// T-0035). It is the single seam both halves of the enforcement share: the
// agent client WRITES it when an EnvelopeStateUpdate arrives (it implements
// the apply side), and the dispatcher READS it through EnvelopeThrottle on
// every tick. The control plane never reaches into the cluster to set these
// directly (ADR-0061) — it states them on the channel, the data plane applies
// them here.
//
// Zero binds nothing: a cap of 0 is "no cap", and a fresh holder is therefore
// unthrottled (AC7). A received 0 LIFTS a cap rather than preserving the prior
// one, because the control plane's no-breach evaluation produces 0 — were 0
// "unchanged", a resolved breach could never be lifted.
type Caps struct {
	maxCI    atomic.Int64 // in-flight dispatch cap, read as int32
	queueCap atomic.Int64 // queue-depth gauge cap KEDA reads
}

// NewCaps returns an empty holder: both caps 0, i.e. unthrottled until the
// control plane states otherwise (AC7).
func NewCaps() *Caps { return &Caps{} }

// MaxCIConcurrency implements EnvelopeThrottle.
func (c *Caps) MaxCIConcurrency() int32 { return int32(c.maxCI.Load()) }

// QueueDepthCap implements EnvelopeThrottle.
func (c *Caps) QueueDepthCap() int64 { return c.queueCap.Load() }

// ApplyEnvelopeCaps stores the newest caps as the ABSOLUTE desired state the
// control plane stated. Negative inputs clamp to 0 (no cap), never an error:
// a malformed number must fail the plane open, throttling nothing it should
// not (AC7). It always succeeds; the ack the agent sends reports that.
func (c *Caps) ApplyEnvelopeCaps(maxCI int32, queueCap int64) error {
	if maxCI < 0 {
		maxCI = 0
	}
	if queueCap < 0 {
		queueCap = 0
	}
	c.maxCI.Store(int64(maxCI))
	c.queueCap.Store(queueCap)
	return nil
}

// Dispatcher claims queued jobs and dispatches them to isolated sandboxes.
type Dispatcher struct {
	queue    Queue
	store    Store
	launcher Launcher
	config   Config
	gauge    Gauge
	throttle EnvelopeThrottle
	pdp      policyapi.DecisionPoint
	bus      bus.Bus
	newID    func() string
	clock    func() time.Time
	interval time.Duration

	inflight atomic.Int64 // sandboxes launched and not yet terminal (the claim gate's count)

	delayMu   sync.Mutex
	delayFrom time.Time // instant the claim gate first refused while jobs waited; zero = no open delay
	wg        sync.WaitGroup
}

type Option func(*Dispatcher)

func WithIDs(newID func() string) Option    { return func(d *Dispatcher) { d.newID = newID } }
func WithClock(now func() time.Time) Option { return func(d *Dispatcher) { d.clock = now } }

// WithConfig sets the environment-resolved runner configuration passed to every
// launch. Without it the dispatcher has no digest-pinned image and every launch
// is refused by the sandbox model.
func WithConfig(config Config) Option { return func(d *Dispatcher) { d.config = config } }

// WithGauge publishes queue depth to the KEDA scaler metric on every tick.
func WithGauge(g Gauge) Option { return func(d *Dispatcher) { d.gauge = g } }

// WithEnvelopeThrottle attaches the fair-use caps the data plane applies from
// the control plane's envelope desired state (SPEC-0041 AC9, T-0035). Without
// one the dispatcher runs unthrottled — absence is not a cap of zero (AC7).
// Must be set before Run.
func WithEnvelopeThrottle(t EnvelopeThrottle) Option {
	return func(d *Dispatcher) { d.throttle = t }
}

// WithInterval sets the claim interval. Tests use a short one.
func WithInterval(every time.Duration) Option { return func(d *Dispatcher) { d.interval = every } }

func New(queue Queue, store Store, launcher Launcher, pdp policyapi.DecisionPoint, b bus.Bus, opts ...Option) *Dispatcher {
	d := &Dispatcher{queue: queue, store: store, launcher: launcher, pdp: pdp, bus: b, newID: ids.NewULID, clock: time.Now, interval: 100 * time.Millisecond}
	for _, opt := range opts {
		opt(d)
	}
	return d
}

// Run starts the dispatch loop. It blocks until ctx is cancelled, claiming one
// queued job at a time and launching a sandbox for it.
func (d *Dispatcher) Run(ctx context.Context) error {
	ticker := time.NewTicker(d.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			// A claim or dispatch failure concerns one job and is retried on the
			// next tick; only cancellation ends the loop.
			_ = d.Tick(ctx)
		}
	}
}

// Tick is one iteration of the dispatch loop: publish queue depth for the KEDA
// scaler, claim at most one queued job, and dispatch it. Claiming removes the job
// from the queue, so a queued job launches exactly one sandbox even when several
// dispatcher replicas are scaled up (SPEC-0020 AC2). A cancelled job is no longer
// claimable and therefore never launches.
//
// The fair-use claim gate binds here (SPEC-0041 AC5, T-0035): while in-flight
// sandboxes sit at the published MaxCIConcurrency, the tick claims nothing —
// queued jobs are DELAYED, never dropped, and every job queued through the
// refusal carries the delay's cause when it finally dispatches. The gate never
// touches a running sandbox (AC4) and an absent or zero cap never binds (AC7).
func (d *Dispatcher) Tick(ctx context.Context) error {
	var maxCI int32
	var queueCap int64
	if d.throttle != nil {
		maxCI, queueCap = d.throttle.MaxCIConcurrency(), d.throttle.QueueDepthCap()
	}

	var depth int64
	if d.gauge != nil {
		var err error
		depth, err = d.queue.Depth(ctx)
		if err != nil {
			return err
		}
		published := depth
		// The scaler-input half of the throttle (T-0035): the envelope caps
		// the queue-depth gauge KEDA reads, so replicas scale down under a
		// breach. The cap shapes the gauge only — it never removes a queued
		// job, so nothing is dropped.
		if queueCap > 0 && published > queueCap {
			published = queueCap
		}
		d.gauge.Set(published)
	} else if maxCI > 0 {
		var err error
		depth, err = d.queue.Depth(ctx)
		if err != nil {
			return err
		}
	}

	if maxCI > 0 && d.inflight.Load() >= int64(maxCI) {
		if depth > 0 {
			d.markDelayed()
		}
		return nil
	}

	jobID, ok, err := d.queue.Claim(ctx)
	if err != nil {
		return err
	}
	if !ok {
		// An empty queue ends every open delay: nothing is left waiting.
		d.clearDelayed()
		return nil
	}
	d.inflight.Add(1)
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		defer d.inflight.Add(-1)
		// A dispatch failure concerns one job and stays one job: the loop's
		// next tick carries on, exactly as the synchronous loop did.
		_ = d.DispatchOne(ctx, jobID)
	}()
	return nil
}

// InFlight is the number of sandboxes launched and not yet terminal — the
// count the claim gate binds against.
func (d *Dispatcher) InFlight() int64 { return d.inflight.Load() }

// WaitIdle blocks until every dispatched sandbox has reached its terminal
// state. It is the test and shutdown seam for the async dispatch loop.
func (d *Dispatcher) WaitIdle() { d.wg.Wait() }

// markDelayed records the instant the claim gate first refused while jobs
// waited; every job already queued at that instant has been delayed by the
// throttle, and carries the cause when it dispatches (SPEC-0041 AC5).
func (d *Dispatcher) markDelayed() {
	d.delayMu.Lock()
	if d.delayFrom.IsZero() {
		d.delayFrom = d.clock().UTC()
	}
	d.delayMu.Unlock()
}

// clearDelayed ends the open delay once the queue has drained.
func (d *Dispatcher) clearDelayed() {
	d.delayMu.Lock()
	d.delayFrom = time.Time{}
	d.delayMu.Unlock()
}

// delayCauseFor is the cause a job carries when it waited through an open
// claim-gate refusal: it was already queued when dispatch stopped at the cap.
func (d *Dispatcher) delayCauseFor(job api.Job) string {
	d.delayMu.Lock()
	from := d.delayFrom
	d.delayMu.Unlock()
	if !from.IsZero() && !job.QueuedAt.After(from) {
		return api.DelayCauseEnvelopeThrottle
	}
	return ""
}

// DispatchOne claims and dispatches a single job by ID. This is the testable
// entry point: it validates the job is still queued, launches one attempt,
// and records the terminal outcome with audit evidence.
func (d *Dispatcher) DispatchOne(ctx context.Context, jobID string) error {
	job, err := d.store.Get(ctx, jobID)
	if err != nil {
		return err
	}
	if job.State != api.JobQueued {
		return errors.New("ci: job not queued for dispatch")
	}

	attemptID := d.newID()
	now := d.clock().UTC()

	// Re-validate PDP authorization at dispatch time using server-derived context.
	req := policyapi.Request{
		TenantID: job.TenantID,
		Subject:  policyapi.Subject{ID: job.ActorID, TenantID: job.TenantID},
		Action:   "ci.run",
		Resource: policyapi.Resource{Type: "repository", ID: job.RepositoryID},
		Context:  map[string]string{"ref": job.Ref, "commit_sha": job.CommitSHA},
	}
	decision, err := d.pdp.Decide(ctx, req)
	if err != nil || !decision.Allowed {
		return errors.New("ci: dispatch denied by PDP")
	}

	job.AttemptID = attemptID
	job.State = api.JobRunning
	job.StartedAt = &now
	if cause := d.delayCauseFor(job); cause != "" && job.DelayCause == "" {
		// The delay is visible as a cause on the job itself (SPEC-0041 AC5):
		// it waited while the claim gate held dispatch at the published cap.
		job.DelayCause = cause
	}
	if err := d.store.Save(ctx, job); err != nil {
		return err
	}
	if err := d.bus.Publish(ctx, api.CIJobStarted{
		EventID: d.newID(), JobID: job.ID, AttemptID: attemptID,
		TenantID: job.TenantID, RepositoryID: job.RepositoryID, OccurredAt: now,
	}); err != nil {
		return err
	}

	// The runner configuration is the one cmd/ resolved from the environment. It is
	// never derived from the job or from the repository's own CI file, so a tenant
	// cannot choose its runtime class, image, or source capability.
	attempt, err := d.launcher.Launch(ctx, job, d.config)
	if err != nil {
		job.State = api.JobFailed
		finished := d.clock().UTC()
		job.FinishedAt = &finished
		job.OutcomeSummary = "sandbox launch failed"
		_ = d.store.Save(ctx, job)
		return d.publishTerminal(ctx, job, attemptID, api.JobFailed, "sandbox launch failed")
	}

	state, summary, awaitErr := attempt.Await(ctx)
	finished := d.clock().UTC()
	job.State = state
	job.FinishedAt = &finished
	job.OutcomeSummary = summary
	if awaitErr != nil {
		job.State = api.JobFailed
		job.OutcomeSummary = "cleanup uncertainty"
		state = api.JobFailed
		summary = "cleanup uncertainty"
	}
	_ = d.store.Save(ctx, job)

	// Audit evidence for accepted dispatch + terminal outcome (SPEC-0020 AC7).
	if dispatchErr := d.bus.Publish(ctx, audit.CIDispatch{
		TenantID: job.TenantID, ActorID: job.ActorID, RepositoryID: job.RepositoryID,
		JobID: job.ID, AttemptID: attemptID, CommitSHA: job.CommitSHA,
		ConfigurationDigest: job.ConfigurationDigest, PolicyDecisionID: decision.DecisionID,
		OccurredAt: now,
	}); dispatchErr != nil {
		return dispatchErr
	}
	return d.publishTerminal(ctx, job, attemptID, state, summary)
}

func (d *Dispatcher) publishTerminal(ctx context.Context, job api.Job, attemptID string, state api.JobState, summary string) error {
	finished := d.clock().UTC()
	return d.bus.Publish(ctx, api.CIJobFinished{
		EventID: d.newID(), JobID: job.ID, AttemptID: attemptID,
		TenantID: job.TenantID, RepositoryID: job.RepositoryID,
		TerminalState: state, OutcomeSummary: summary, OccurredAt: finished,
	})
}
