// Package app owns the merge-request lifecycle: state, reviews, branch-protection
// records, and idempotency keys. Authorization is always a PDP decision with
// server-derived context, and the ref move at the end of a merge goes through a
// port to Repository/Git rather than against its storage (SPEC-0019).
package app

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gitfrok/backend/modules/codereview/api"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
	repoapi "github.com/gitfrok/backend/modules/repository/api"
	"github.com/gitfrok/backend/platform/audit"
	"github.com/gitfrok/backend/platform/bus"
	"github.com/gitfrok/backend/platform/ids"
)

// MergeRefCommand is one authorized ref move. It carries the verified principal
// because Repository/Git asks its own PDP: a caller allowed by this context's
// enforcement point is not therefore trusted by storage's.
type MergeRefCommand struct {
	TenantID, RepositoryID  string
	ActorID, RequestID      string
	ActorRoles              []string
	TargetRef, Revision     string
	ExpectedCurrentRevision string
}

// RefMover is Repository/Git's contract boundary for moving a ref. Code Review
// never writes a ref itself and never touches Git storage (SPEC-0019 AC7).
type RefMover interface {
	// MoveRef moves the target ref to the revision, but only while the ref is
	// still at ExpectedCurrentRevision. The decision has already been made; this
	// is the effect, and the expectation is what stops it landing on a state the
	// decision was never made against.
	MoveRef(ctx context.Context, command MergeRefCommand) error
}

// Review is one actor's current position. Superseding an actor's review replaces
// this record; the audit trail keeps the history.
type Review struct {
	ActorID      string
	Disposition  api.Disposition
	HeadRevision string
	SubmittedAt  time.Time
}

// Store is the context's persistence port. Every method is tenant-scoped by the
// caller passing an already-authorized context; the memory adapter below keeps
// the create-or-get atomicity a production unique constraint must also preserve.
type Store interface {
	// CreateOrGet records a merge request under an idempotency key, or returns
	// the one already recorded under it.
	CreateOrGet(ctx context.Context, key string, candidate api.MergeRequest) (api.MergeRequest, bool, error)
	Get(ctx context.Context, id string) (api.MergeRequest, error)
	// OpenForTarget returns the open merge requests in one tenant and repository
	// whose target ref is targetRef.
	OpenForTarget(ctx context.Context, tenantID, repositoryID, targetRef string) ([]api.MergeRequest, error)
	// OpenForSource returns the open merge requests in one tenant and repository
	// whose source ref is sourceRef.
	OpenForSource(ctx context.Context, tenantID, repositoryID, sourceRef string) ([]api.MergeRequest, error)
	// SaveRefRevision records where Repository/Git last announced a ref to be.
	SaveRefRevision(ctx context.Context, tenantID, repositoryID, ref, revision string) error
	// RefRevision returns the last announced revision for a ref, empty when this
	// context has never been told about it.
	RefRevision(ctx context.Context, tenantID, repositoryID, ref string) (string, error)
	// Save persists a merge request whose Version has already been incremented.
	Save(ctx context.Context, mr api.MergeRequest) error
	// PutReview replaces the submitting actor's current review.
	PutReview(ctx context.Context, mergeRequestID string, review Review) error
	Reviews(ctx context.Context, mergeRequestID string) ([]Review, error)
	// Protection returns the exact-ref rule, and false when the ref is not protected.
	Protection(ctx context.Context, tenantID, repositoryID, targetRef string) (api.BranchProtection, bool, error)
	SaveProtection(ctx context.Context, protection api.BranchProtection) error
	// Seen reports whether a request ID was already applied, recording it if not.
	Seen(ctx context.Context, requestID string) (bool, error)
}

type Service struct {
	store Store
	refs  RefMover
	pdp   policyapi.DecisionPoint
	bus   bus.Bus
	newID func() string
	now   func() time.Time
	// findings assembles the server-derived findings facts a merge decision
	// presents to the security gate (T-0025, SPEC-0029). Nil — and nil alone
	// — means this plane wired no facts provider: the security gate stays
	// disengaged and the SPEC-0019 approval gate stands alone, exactly as
	// before T-0025.
	findings api.FindingsFactsProvider
}

type Option func(*Service)

func WithIDs(newID func() string) Option    { return func(s *Service) { s.newID = newID } }
func WithClock(now func() time.Time) Option { return func(s *Service) { s.now = now } }

func New(store Store, refs RefMover, pdp policyapi.DecisionPoint, events bus.Bus, opts ...Option) *Service {
	s := &Service{store: store, refs: refs, pdp: pdp, bus: events, newID: ids.NewULID, now: time.Now}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// SubscribeRefUpdates keeps each open merge request's view of its target ref
// current. Repository/Git announces every ref change; Code Review listens rather
// than reading Git state, so a merge always names a revision this context
// actually observed (invariant 14).
func (s *Service) SubscribeRefUpdates(events bus.Bus) {
	bus.SubscribeTyped(events, s.onRefUpdated)
}

// SetFindingsFacts attaches the findings-facts provider the security merge
// gate assembles its input from (T-0025, SPEC-0029, SPEC-0030). It is a
// post-construction step, exactly like Security/Findings' merge-base
// resolver: the provider exists only once the composition root has composed
// both contexts, and a service composed without one leaves the security gate
// disengaged rather than engaged on nothing.
func (s *Service) SetFindingsFacts(provider api.FindingsFactsProvider) {
	s.findings = provider
}

func (s *Service) onRefUpdated(ctx context.Context, event repoapi.RefUpdated) error {
	if err := s.store.SaveRefRevision(ctx, event.TenantID, event.RepoID, event.Ref, event.NewSha); err != nil {
		return err
	}
	affected, err := s.store.OpenForTarget(ctx, event.TenantID, event.RepoID, event.Ref)
	if err != nil {
		return err
	}
	for _, mr := range affected {
		// Only the projected view of the target moves. The version guards the
		// caller's own edits, and a ref moving under a merge request is not one of
		// them — bumping it here would invalidate a review the author is mid-way
		// through submitting.
		mr.TargetRevision = event.NewSha
		if err := s.store.Save(ctx, mr); err != nil {
			return err
		}
		// The merge base can move when the target moves, so attribution
		// consumers must recompute (SPEC-0028): the event names both sides of
		// what can move, repeating the head a retarget did not change.
		if err := s.bus.Publish(ctx, api.MergeRequestUpdated{
			EventID: s.newID(), MergeRequestID: mr.ID, TenantID: mr.TenantID, RepositoryID: mr.RepositoryID,
			ActorID: event.ActorID, HeadRevision: mr.HeadRevision,
			SourceRef: mr.SourceRef, TargetRef: mr.TargetRef, OccurredAt: s.now().UTC(),
		}); err != nil {
			return err
		}
	}
	// A push to a source ref advances the head of every open merge request
	// reviewing it; attribution consumers recompute against the new head
	// (SPEC-0028).
	sourced, err := s.store.OpenForSource(ctx, event.TenantID, event.RepoID, event.Ref)
	if err != nil {
		return err
	}
	for _, mr := range sourced {
		if mr.HeadRevision == event.NewSha {
			continue
		}
		mr.HeadRevision = event.NewSha
		if err := s.store.Save(ctx, mr); err != nil {
			return err
		}
		if err := s.bus.Publish(ctx, api.MergeRequestUpdated{
			EventID: s.newID(), MergeRequestID: mr.ID, TenantID: mr.TenantID, RepositoryID: mr.RepositoryID,
			ActorID: event.ActorID, HeadRevision: mr.HeadRevision,
			SourceRef: mr.SourceRef, TargetRef: mr.TargetRef, OccurredAt: s.now().UTC(),
		}); err != nil {
			return err
		}
	}
	return nil
}

// Open records a merge request from one source ref to one target ref. Replaying
// a request ID returns the request that ID already created.
func (s *Service) Open(ctx context.Context, req api.OpenRequest) (api.MergeRequest, error) {
	if !validContext(req.Context) || !validBranchRef(req.SourceRef) || !validBranchRef(req.TargetRef) ||
		req.SourceRef == req.TargetRef {
		return api.MergeRequest{}, api.ErrDenied
	}
	if !s.allowed(ctx, req.Context, "merge_request.open", "repository", req.RepositoryID, map[string]string{
		"source_ref": req.SourceRef,
		"target_ref": req.TargetRef,
	}) {
		return api.MergeRequest{}, api.ErrDenied
	}

	// Both revisions are Repository/Git's facts, taken from what it has announced.
	// The caller says which refs to review, never which revisions: a caller-chosen
	// head would let one open a request against a revision nobody pushed.
	headRevision, err := s.store.RefRevision(ctx, req.TenantID, req.RepositoryID, req.SourceRef)
	if err != nil || headRevision == "" {
		return api.MergeRequest{}, api.ErrDenied
	}
	targetRevision, err := s.store.RefRevision(ctx, req.TenantID, req.RepositoryID, req.TargetRef)
	if err != nil {
		return api.MergeRequest{}, api.ErrDenied
	}

	now := s.now().UTC()
	candidate := api.MergeRequest{
		ID: s.newID(), TenantID: req.TenantID, RepositoryID: req.RepositoryID,
		SourceRef: req.SourceRef, TargetRef: req.TargetRef,
		Title: req.Title, Description: req.Description,
		CreatorID: req.ActorID, State: api.StateOpen, HeadRevision: headRevision,
		TargetRevision: targetRevision,
		CreatedAt:      now, UpdatedAt: now, Version: 1,
	}
	mr, created, err := s.store.CreateOrGet(ctx, "request:"+req.RequestID, candidate)
	if err != nil {
		return api.MergeRequest{}, api.ErrDenied
	}
	if !created {
		return mr, nil
	}
	if err := s.bus.Publish(ctx, api.MergeRequestOpened{
		EventID: s.newID(), MergeRequestID: mr.ID, TenantID: mr.TenantID, RepositoryID: mr.RepositoryID,
		SourceRef: mr.SourceRef, TargetRef: mr.TargetRef, CreatorID: mr.CreatorID, OccurredAt: now,
	}); err != nil {
		return api.MergeRequest{}, err
	}
	// MergeRequestOpened carries no head revision, and attribution consumers
	// need the (head, target) pair the moment the request exists: the update
	// event follows the open event on the same path (SPEC-0028).
	if err := s.bus.Publish(ctx, api.MergeRequestUpdated{
		EventID: s.newID(), MergeRequestID: mr.ID, TenantID: mr.TenantID, RepositoryID: mr.RepositoryID,
		ActorID: mr.CreatorID, HeadRevision: mr.HeadRevision,
		SourceRef: mr.SourceRef, TargetRef: mr.TargetRef, OccurredAt: now,
	}); err != nil {
		return api.MergeRequest{}, err
	}
	return mr, nil
}

// Get returns a merge request within the caller's tenant. A request in another
// tenant is indistinguishable from one that does not exist.
func (s *Service) Get(ctx context.Context, principal api.Context, mergeRequestID string) (api.MergeRequest, error) {
	if !validContext(principal) || mergeRequestID == "" {
		return api.MergeRequest{}, api.ErrDenied
	}
	mr, err := s.store.Get(ctx, mergeRequestID)
	if err != nil || mr.TenantID != principal.TenantID || mr.RepositoryID != principal.RepositoryID {
		return api.MergeRequest{}, api.ErrDenied
	}
	return mr, nil
}

// Review records the actor's current disposition, superseding their previous one.
// An accepted approval appends exactly one immutable audit record.
func (s *Service) Review(ctx context.Context, req api.ReviewRequest) (api.MergeRequest, error) {
	mr, err := s.Get(ctx, req.Context, req.MergeRequestID)
	if err != nil || !validDisposition(req.Disposition) || req.HeadRevision == "" {
		return api.MergeRequest{}, api.ErrDenied
	}
	if mr.State != api.StateOpen {
		return api.MergeRequest{}, api.ErrDenied
	}
	if req.ExpectedVersion != mr.Version {
		return api.MergeRequest{}, api.ErrVersionConflict
	}
	decision, allowed := s.decide(ctx, req.Context, "merge_request.review", "merge_request", mr.ID, map[string]string{
		"state":         string(mr.State),
		"head_revision": mr.HeadRevision,
	})
	if !allowed {
		return api.MergeRequest{}, api.ErrDenied
	}
	replayed, err := s.store.Seen(ctx, req.RequestID)
	if err != nil {
		return api.MergeRequest{}, api.ErrDenied
	}
	if replayed {
		return mr, nil
	}

	now := s.now().UTC()
	if err := s.store.PutReview(ctx, mr.ID, Review{
		ActorID: req.ActorID, Disposition: req.Disposition,
		HeadRevision: req.HeadRevision, SubmittedAt: now,
	}); err != nil {
		return api.MergeRequest{}, api.ErrDenied
	}
	mr.Version, mr.UpdatedAt = mr.Version+1, now
	if err := s.store.Save(ctx, mr); err != nil {
		return api.MergeRequest{}, api.ErrDenied
	}

	if err := s.bus.Publish(ctx, api.ReviewSubmitted{
		EventID: s.newID(), MergeRequestID: mr.ID, TenantID: mr.TenantID, RepositoryID: mr.RepositoryID,
		ActorID: req.ActorID, Disposition: req.Disposition, HeadRevision: req.HeadRevision, OccurredAt: now,
	}); err != nil {
		return api.MergeRequest{}, err
	}
	// Only an accepted approval is evidence; a comment or a change request is
	// review activity, not an authorization-relevant acceptance (SPEC-0019 AC6).
	if req.Disposition == api.DispositionApprove {
		if err := s.bus.Publish(ctx, audit.MergeRequestApproved{
			TenantID: mr.TenantID, ActorID: req.ActorID, RepositoryID: mr.RepositoryID,
			MergeRequestID: mr.ID, HeadRevision: req.HeadRevision, RequestID: req.RequestID,
			PolicyDecisionID: decision.DecisionID, OccurredAt: now,
		}); err != nil {
			return api.MergeRequest{}, err
		}
	}
	return mr, nil
}

// Merge asks the PDP with server-derived approval facts and, only if allowed,
// moves the target ref through Repository/Git.
func (s *Service) Merge(ctx context.Context, req api.MergeRequestCommand) (api.MergeRequest, error) {
	mr, err := s.Get(ctx, req.Context, req.MergeRequestID)
	if err != nil {
		return api.MergeRequest{}, api.ErrDenied
	}
	if mr.State != api.StateOpen {
		return api.MergeRequest{}, api.ErrDenied
	}
	if req.ExpectedVersion != mr.Version {
		return api.MergeRequest{}, api.ErrVersionConflict
	}

	// Both counts are facts this context derives: the valid approvals from its own
	// review log at the current head revision, and the requirement from the
	// protection rule. Neither can be supplied by a caller (SPEC-0019 AC5).
	valid, err := s.validApprovals(ctx, mr)
	if err != nil {
		return api.MergeRequest{}, api.ErrDenied
	}
	protection, protected, err := s.store.Protection(ctx, mr.TenantID, mr.RepositoryID, mr.TargetRef)
	if err != nil {
		return api.MergeRequest{}, api.ErrDenied
	}
	decision, allowed := s.decide(ctx, req.Context, "merge_request.merge", "merge_request", mr.ID,
		s.mergeGateContext(ctx, mr, req.ActorID, map[string]string{
			"target_ref":         mr.TargetRef,
			"protected":          strconv.FormatBool(protected),
			"valid_approvals":    strconv.Itoa(valid),
			"required_approvals": strconv.Itoa(int(protection.RequiredApprovals)),
		}))
	if !allowed {
		return api.MergeRequest{}, api.ErrDenied
	}
	replayed, err := s.store.Seen(ctx, req.RequestID)
	if err != nil {
		return api.MergeRequest{}, api.ErrDenied
	}
	if replayed {
		return mr, nil
	}

	// The move names the target revision this context last saw. If the ref has
	// moved since — someone else merged, or a push landed — storage refuses, and
	// the merge fails rather than landing on state nobody decided about.
	if err := s.refs.MoveRef(ctx, MergeRefCommand{
		TenantID: mr.TenantID, RepositoryID: mr.RepositoryID,
		ActorID: req.ActorID, RequestID: req.RequestID,
		ActorRoles: slices.Clone(req.ActorRoles),
		TargetRef:  mr.TargetRef, Revision: mr.HeadRevision,
		ExpectedCurrentRevision: mr.TargetRevision,
	}); err != nil {
		return api.MergeRequest{}, api.ErrDenied
	}

	now := s.now().UTC()
	mr.State, mr.Version, mr.UpdatedAt = api.StateMerged, mr.Version+1, now
	if err := s.store.Save(ctx, mr); err != nil {
		return api.MergeRequest{}, api.ErrDenied
	}
	if err := s.bus.Publish(ctx, api.MergeRequestMerged{
		EventID: s.newID(), MergeRequestID: mr.ID, TenantID: mr.TenantID, RepositoryID: mr.RepositoryID,
		ActorID: req.ActorID, TargetRef: mr.TargetRef, HeadRevision: mr.HeadRevision, OccurredAt: now,
	}); err != nil {
		return api.MergeRequest{}, err
	}
	return mr, s.bus.Publish(ctx, audit.MergeRequestMerged{
		TenantID: mr.TenantID, ActorID: req.ActorID, RepositoryID: mr.RepositoryID,
		MergeRequestID: mr.ID, TargetRef: mr.TargetRef, HeadRevision: mr.HeadRevision,
		RequestID: req.RequestID, PolicyDecisionID: decision.DecisionID, OccurredAt: now,
	})
}

// SetProtection replaces the exact-ref rule and announces it. Repository/Git
// projects the event; it never reads this context's tables.
func (s *Service) SetProtection(ctx context.Context, req api.ProtectionRequest) (api.BranchProtection, error) {
	if !validContext(req.Context) || !validBranchRef(req.TargetRef) || req.RequiredApprovals < 0 {
		return api.BranchProtection{}, api.ErrDenied
	}
	if !s.allowed(ctx, req.Context, "repository.branch_protection.manage", "repository", req.RepositoryID, map[string]string{
		"target_ref":         req.TargetRef,
		"required_approvals": strconv.Itoa(int(req.RequiredApprovals)),
	}) {
		return api.BranchProtection{}, api.ErrDenied
	}

	current, exists, err := s.store.Protection(ctx, req.TenantID, req.RepositoryID, req.TargetRef)
	if err != nil {
		return api.BranchProtection{}, api.ErrDenied
	}
	if exists && req.ExpectedVersion != current.Version {
		return api.BranchProtection{}, api.ErrVersionConflict
	}
	if !exists && req.ExpectedVersion != 0 {
		return api.BranchProtection{}, api.ErrVersionConflict
	}
	replayed, err := s.store.Seen(ctx, req.RequestID)
	if err != nil {
		return api.BranchProtection{}, api.ErrDenied
	}
	if replayed {
		return current, nil
	}

	updated := api.BranchProtection{
		TenantID: req.TenantID, RepositoryID: req.RepositoryID, TargetRef: req.TargetRef,
		RequiredApprovals: req.RequiredApprovals, Version: current.Version + 1,
	}
	if err := s.store.SaveProtection(ctx, updated); err != nil {
		return api.BranchProtection{}, api.ErrDenied
	}
	return updated, s.bus.Publish(ctx, api.BranchProtectionChanged{
		EventID: s.newID(), TenantID: updated.TenantID, RepositoryID: updated.RepositoryID,
		TargetRef: updated.TargetRef, RequiredApprovals: updated.RequiredApprovals,
		ActorID: req.Context.ActorID, ActorRoles: slices.Clone(req.Context.ActorRoles),
		OccurredAt: s.now().UTC(),
	})
}

// mergeGateContext composes the merge decision's server-derived context
// (SPEC-0029 AC5): the SPEC-0019 protection and approval facts first, then —
// only when this plane wired a findings-facts provider — the security gate's
// findings facts. The security gate COMPOSES with the approval gate, never
// replaces it: both sets of facts ride one decision, and either can deny it.
//
// Engaging the gate and failing to assemble its facts are deliberately
// indistinguishable to the caller: the gate is engaged with NO facts, which
// the reviewed policy denies (SPEC-0029 AC9). A fact that cannot be assembled
// fails closed — never a fail-open default, and never a synchronous
// cross-context read to recover it. The facts assemble under the merge's own
// verified actor: the merge-base read the comparison needs is resolved under
// the identity being decided about, never under a privileged server handle.
func (s *Service) mergeGateContext(ctx context.Context, mr api.MergeRequest, actorID string, base map[string]string) map[string]string {
	if s.findings == nil {
		return base
	}
	base[api.ContextKeyFindingsGate] = "true"
	facts, err := s.findings.FindingsFacts(ctx, mr.TenantID, mr.RepositoryID, actorID, mr.ID)
	if err != nil {
		return base
	}
	maps.Copy(base, facts.Context())
	return base
}

// validApprovals counts approvals made against the merge request's current head
// revision. A changed head therefore invalidates every earlier approval, which is
// the whole point of pinning a review to a revision (SPEC-0019 AC4).
func (s *Service) validApprovals(ctx context.Context, mr api.MergeRequest) (int, error) {
	reviews, err := s.store.Reviews(ctx, mr.ID)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, review := range reviews {
		if review.Disposition == api.DispositionApprove && review.HeadRevision == mr.HeadRevision {
			count++
		}
	}
	return count, nil
}

func (s *Service) decide(ctx context.Context, principal api.Context, action, resourceType, resourceID string, attributes map[string]string) (policyapi.Decision, bool) {
	decision, err := s.pdp.Decide(ctx, policyapi.Request{
		TenantID: principal.TenantID,
		Subject: policyapi.Subject{
			ID: principal.ActorID, TenantID: principal.TenantID,
			Roles: slices.Clone(principal.ActorRoles),
		},
		Action:   action,
		Resource: policyapi.Resource{Type: resourceType, ID: resourceID},
		Context:  attributes,
	})
	return decision, err == nil && decision.Allowed
}

func (s *Service) allowed(ctx context.Context, principal api.Context, action, resourceType, resourceID string, attributes map[string]string) bool {
	_, allowed := s.decide(ctx, principal, action, resourceType, resourceID, attributes)
	return allowed
}

func validContext(c api.Context) bool {
	return c.TenantID != "" && c.RepositoryID != "" && c.ActorID != "" && c.RequestID != ""
}

// validBranchRef accepts only an exact branch ref. Pattern syntax is deliberately
// absent from v1, so a rule cannot silently cover refs nobody named, and a name
// that could be read as a path escape is refused outright.
func validBranchRef(ref string) bool {
	const prefix = "refs/heads/"
	if !strings.HasPrefix(ref, prefix) || len(ref) == len(prefix) {
		return false
	}
	name := ref[len(prefix):]
	if strings.HasPrefix(name, "/") || strings.HasSuffix(name, "/") || strings.Contains(name, "//") {
		return false
	}
	for segment := range strings.SplitSeq(name, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return !strings.ContainsAny(name, "*?[]^~: \t\\\x00")
}

func validDisposition(d api.Disposition) bool {
	switch d {
	case api.DispositionApprove, api.DispositionRequestChanges, api.DispositionComment:
		return true
	}
	return false
}

// memoryStore is the local/test persistence adapter. Its mutex makes create-or-get
// and the request-ID check atomic, the invariant a tenant-scoped database unique
// constraint must also preserve.
type memoryStore struct {
	mu          sync.Mutex
	requests    map[string]api.MergeRequest
	idempotency map[string]string
	seen        map[string]bool
	reviews     map[string][]Review
	protections map[string]api.BranchProtection
	// refs is this context's own view of where Repository/Git last announced each
	// ref to be. The in-memory adapter starts empty, so a merge request opened
	// before any ref announcement has no observed target revision; a persistent
	// store keeps it across restarts.
	refs map[string]string
}

// NewMemoryStore returns the dev/in-memory store. Production injects a
// tenant-scoped database store.
func NewMemoryStore() Store {
	return &memoryStore{
		requests: map[string]api.MergeRequest{}, idempotency: map[string]string{},
		seen: map[string]bool{}, reviews: map[string][]Review{},
		protections: map[string]api.BranchProtection{}, refs: map[string]string{},
	}
}

func (m *memoryStore) CreateOrGet(_ context.Context, key string, candidate api.MergeRequest) (api.MergeRequest, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if id, ok := m.idempotency[key]; ok {
		return m.requests[id], false, nil
	}
	m.requests[candidate.ID], m.idempotency[key] = candidate, candidate.ID
	return candidate, true, nil
}

func (m *memoryStore) Get(_ context.Context, id string) (api.MergeRequest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	mr, ok := m.requests[id]
	if !ok {
		return api.MergeRequest{}, errors.New("not found")
	}
	return mr, nil
}

func (m *memoryStore) SaveRefRevision(_ context.Context, tenantID, repositoryID, ref, revision string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.refs[protectionKey(tenantID, repositoryID, ref)] = revision
	return nil
}

func (m *memoryStore) RefRevision(_ context.Context, tenantID, repositoryID, ref string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.refs[protectionKey(tenantID, repositoryID, ref)], nil
}

func (m *memoryStore) OpenForTarget(_ context.Context, tenantID, repositoryID, targetRef string) ([]api.MergeRequest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []api.MergeRequest
	for _, mr := range m.requests {
		if mr.State == api.StateOpen && mr.TenantID == tenantID && mr.RepositoryID == repositoryID && mr.TargetRef == targetRef {
			out = append(out, mr)
		}
	}
	return out, nil
}

func (m *memoryStore) OpenForSource(_ context.Context, tenantID, repositoryID, sourceRef string) ([]api.MergeRequest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []api.MergeRequest
	for _, mr := range m.requests {
		if mr.State == api.StateOpen && mr.TenantID == tenantID && mr.RepositoryID == repositoryID && mr.SourceRef == sourceRef {
			out = append(out, mr)
		}
	}
	return out, nil
}

func (m *memoryStore) Save(_ context.Context, mr api.MergeRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.requests[mr.ID]; !ok {
		return errors.New("not found")
	}
	m.requests[mr.ID] = mr
	return nil
}

func (m *memoryStore) PutReview(_ context.Context, mergeRequestID string, review Review) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	current := m.reviews[mergeRequestID]
	for i, existing := range current {
		if existing.ActorID == review.ActorID {
			current[i] = review
			m.reviews[mergeRequestID] = current
			return nil
		}
	}
	m.reviews[mergeRequestID] = append(current, review)
	return nil
}

func (m *memoryStore) Reviews(_ context.Context, mergeRequestID string) ([]Review, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.reviews[mergeRequestID]), nil
}

func (m *memoryStore) Protection(_ context.Context, tenantID, repositoryID, targetRef string) (api.BranchProtection, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	protection, ok := m.protections[protectionKey(tenantID, repositoryID, targetRef)]
	return protection, ok, nil
}

func (m *memoryStore) SaveProtection(_ context.Context, protection api.BranchProtection) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.protections[protectionKey(protection.TenantID, protection.RepositoryID, protection.TargetRef)] = protection
	return nil
}

func (m *memoryStore) Seen(_ context.Context, requestID string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.seen[requestID] {
		return true, nil
	}
	m.seen[requestID] = true
	return false, nil
}

func protectionKey(tenantID, repositoryID, targetRef string) string {
	return tenantID + "\x00" + repositoryID + "\x00" + targetRef
}
