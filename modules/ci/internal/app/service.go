// Package app orchestrates the CI/CD job lifecycle. It owns queue records and
// job state; source validation, PDP decisions, and sandbox execution remain
// explicit ports so CI never reaches another context's internals.
package app

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/gitfrok/backend/modules/ci/api"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
	repoapi "github.com/gitfrok/backend/modules/repository/api"
	"github.com/gitfrok/backend/platform/bus"
	"github.com/gitfrok/backend/platform/ids"
)

// Source validates that ref resolves to exactly commitSHA and returns the
// digest of the v0 configuration parsed at that immutable revision.
type Source interface {
	Validate(ctx context.Context, tenantID, repositoryID, ref, commitSHA string) (configurationDigest string, err error)
}

// Queue is CI-owned durable queue plumbing. It contains only an opaque job ID.
type Queue interface {
	Enqueue(context.Context, string) error
	Cancel(context.Context, string) error
}

type Store interface {
	CreateOrGet(context.Context, string, api.Job) (api.Job, bool, error)
	Get(context.Context, string) (api.Job, error)
	Save(context.Context, api.Job) error
}

type Service struct {
	store  Store
	queue  Queue
	source Source
	pdp    policyapi.DecisionPoint
	bus    bus.Bus
	newID  func() string
	now    func() time.Time
}

type Option func(*Service)

func WithIDs(newID func() string) Option    { return func(s *Service) { s.newID = newID } }
func WithClock(now func() time.Time) Option { return func(s *Service) { s.now = now } }

func New(store Store, queue Queue, source Source, pdp policyapi.DecisionPoint, events bus.Bus, opts ...Option) *Service {
	s := &Service{store: store, queue: queue, source: source, pdp: pdp, bus: events, newID: ids.NewULID, now: time.Now}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// SubscribeRefUpdates connects the Repository/Git event surface to CI without
// giving CI access to repository storage. The event already holds the verified
// actor context; it is PEP input, never an asserted authorization result.
func (s *Service) SubscribeRefUpdates(events bus.Bus) {
	bus.SubscribeTyped(events, s.onRefUpdated)
}

func (s *Service) onRefUpdated(ctx context.Context, event repoapi.RefUpdated) error {
	_, err := s.Enqueue(ctx, api.EnqueueRequest{
		Context: api.Context{TenantID: event.TenantID, RepositoryID: event.RepoID, ActorID: event.ActorID, ActorRoles: append([]string(nil), event.ActorRoles...), RequestID: "event:" + event.EventID},
		Ref:     event.Ref, CommitSHA: event.NewSha, SourceEventID: event.EventID, Trigger: api.TriggerRefUpdated,
	})
	return err
}

func (s *Service) Enqueue(ctx context.Context, req api.EnqueueRequest) (api.Job, error) {
	if !validContext(req.Context) || req.Ref == "" || req.CommitSHA == "" || !validTrigger(req) {
		return api.Job{}, api.ErrDenied
	}
	if !s.allowed(ctx, req.Context, "ci.run", "repository", req.RepositoryID, map[string]string{"ref": req.Ref, "commit_sha": req.CommitSHA, "trigger": string(req.Trigger)}) {
		return api.Job{}, api.ErrDenied
	}
	digest, err := s.source.Validate(ctx, req.TenantID, req.RepositoryID, req.Ref, req.CommitSHA)
	if err != nil || digest == "" {
		return api.Job{}, api.ErrDenied
	}
	key := idempotencyKey(req)
	now := s.now().UTC()
	candidate := api.Job{ID: s.newID(), TenantID: req.TenantID, RepositoryID: req.RepositoryID, ActorID: req.ActorID, Ref: req.Ref, CommitSHA: req.CommitSHA, Trigger: req.Trigger, ActorRoles: append([]string(nil), req.ActorRoles...), State: api.JobQueued, QueuedAt: now, ConfigurationDigest: digest}
	job, created, err := s.store.CreateOrGet(ctx, key, candidate)
	if err != nil {
		return api.Job{}, api.ErrDenied
	}
	if !created {
		return job, nil
	}
	if err := s.queue.Enqueue(ctx, job.ID); err != nil {
		return api.Job{}, fmt.Errorf("ci: queue job: %w", err)
	}
	if err := s.bus.Publish(ctx, api.CIJobQueued{EventID: s.newID(), JobID: job.ID, TenantID: job.TenantID, RepositoryID: job.RepositoryID, Ref: job.Ref, CommitSHA: job.CommitSHA, ConfigurationDigest: job.ConfigurationDigest, OccurredAt: now}); err != nil {
		return api.Job{}, fmt.Errorf("ci: publish queued: %w", err)
	}
	return job, nil
}

func (s *Service) Get(ctx context.Context, principal api.Context, jobID string) (api.Job, error) {
	if !validContext(principal) || jobID == "" {
		return api.Job{}, api.ErrDenied
	}
	job, err := s.store.Get(ctx, jobID)
	if err != nil || job.TenantID != principal.TenantID {
		return api.Job{}, api.ErrDenied
	}
	return job, nil
}

func (s *Service) Cancel(ctx context.Context, principal api.Context, jobID string) (api.Job, error) {
	job, err := s.Get(ctx, principal, jobID)
	if err != nil || !s.allowed(ctx, principal, "ci.cancel", "ci_job", jobID, map[string]string{"state": string(job.State)}) {
		return api.Job{}, api.ErrDenied
	}
	if job.State != api.JobQueued {
		return job, nil
	}
	now := s.now().UTC()
	job.State, job.FinishedAt, job.OutcomeSummary = api.JobCancelled, &now, "cancelled before sandbox launch"
	if err := s.store.Save(ctx, job); err != nil {
		return api.Job{}, api.ErrDenied
	}
	if err := s.queue.Cancel(ctx, job.ID); err != nil {
		return api.Job{}, fmt.Errorf("ci: cancel queue job: %w", err)
	}
	if err := s.bus.Publish(ctx, api.CIJobFinished{EventID: s.newID(), JobID: job.ID, TenantID: job.TenantID, RepositoryID: job.RepositoryID, TerminalState: api.JobCancelled, OutcomeSummary: job.OutcomeSummary, OccurredAt: now}); err != nil {
		return api.Job{}, fmt.Errorf("ci: publish cancellation: %w", err)
	}
	return job, nil
}

func (s *Service) allowed(ctx context.Context, principal api.Context, action, resourceType, resourceID string, attributes map[string]string) bool {
	decision, err := s.pdp.Decide(ctx, policyapi.Request{TenantID: principal.TenantID, Subject: policyapi.Subject{ID: principal.ActorID, TenantID: principal.TenantID, Roles: append([]string(nil), principal.ActorRoles...)}, Action: action, Resource: policyapi.Resource{Type: resourceType, ID: resourceID}, Context: attributes})
	return err == nil && decision.Allowed
}

func validContext(c api.Context) bool {
	return c.TenantID != "" && c.RepositoryID != "" && c.ActorID != "" && c.RequestID != ""
}
func validTrigger(req api.EnqueueRequest) bool {
	return (req.Trigger == api.TriggerRefUpdated && req.SourceEventID != "") || (req.Trigger == api.TriggerManual && req.SourceEventID == "")
}
func idempotencyKey(req api.EnqueueRequest) string {
	if req.Trigger == api.TriggerRefUpdated {
		return "event:" + req.SourceEventID
	}
	return "request:" + req.RequestID
}

// memoryStore is the local/test persistence adapter. Its mutex makes the
// create-or-get operation atomic, the same invariant a production tenant-scoped
// database unique constraint must preserve.
type memoryStore struct {
	mu          sync.Mutex
	jobs        map[string]api.Job
	idempotency map[string]string
}

// NewMemoryStore returns a dev/in-memory job store preserving the
// create-or-get atomicity invariant. Production injects a tenant-scoped DB store.
func NewMemoryStore() Store {
	return &memoryStore{jobs: map[string]api.Job{}, idempotency: map[string]string{}}
}

func newMemoryStore() *memoryStore {
	return &memoryStore{jobs: map[string]api.Job{}, idempotency: map[string]string{}}
}
func (m *memoryStore) CreateOrGet(_ context.Context, key string, candidate api.Job) (api.Job, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if id, ok := m.idempotency[key]; ok {
		return m.jobs[id], false, nil
	}
	m.jobs[candidate.ID], m.idempotency[key] = candidate, candidate.ID
	return candidate, true, nil
}
func (m *memoryStore) Get(_ context.Context, id string) (api.Job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	job, ok := m.jobs[id]
	if !ok {
		return api.Job{}, errors.New("not found")
	}
	return job, nil
}
func (m *memoryStore) Save(_ context.Context, job api.Job) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.jobs[job.ID]; !ok {
		return errors.New("not found")
	}
	m.jobs[job.ID] = job
	return nil
}
func (m *memoryStore) count() int { m.mu.Lock(); defer m.mu.Unlock(); return len(m.jobs) }
