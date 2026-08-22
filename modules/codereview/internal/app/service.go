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
	// Landing carries the repository's landing policy (SPEC-0065) when this
	// context could read one. It is a server-derived fact read at merge time,
	// never a caller field: api.MergeRequestCommand cannot express a strategy,
	// which is what makes AC7 hold by construction. Nil means the legacy
	// landing — byte-for-byte today's move.
	Landing *LandingPlan
}

// LandingPlan is the policy the ref mover executes on storage's side.
type LandingPlan struct {
	Strategy              string // domain vocabulary: "" | merge_commit | squash | rebase
	TrunkBased            bool
	MessageTitle          string
	MergeRequestReference string
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
	// Save persists a merge request whose Version has already been incremented, and
	// only serves those bumped writers — SubmitReview, Merge, and the other
	// caller-editing paths. A store that finds the stored row no longer at the
	// version this write read reports an api.ErrVersionConflict rather than
	// writing over whoever won the race (ADR-0080 decision 3, ADR-0084 decision 1).
	Save(ctx context.Context, mr api.MergeRequest) error
	// SaveProjection is the event path's version-preserving write (ADR-0084
	// decision 1). It writes the projected fields — TargetRevision, HeadRevision —
	// without advancing the version, because a ref moving under a merge request is
	// not a caller edit and must not invalidate a review mid-submission. A store
	// whose row moved under the projection re-reads and re-applies rather than
	// surfacing a conflict a caller would have to interpret.
	SaveProjection(ctx context.Context, mr api.MergeRequest) error
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
	// landings reads the repository's landing policy at merge time
	// (SPEC-0065). Nil means this plane composed no repository settings: the
	// legacy landing applies, byte-for-byte.
	landings LandingPolicies
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

// LandingPolicies reads one repository's landing policy (SPEC-0065). It is a
// port, not a parameter: AC7 makes the strategy a server-side read from the
// repository record at merge time, so no caller field can choose it.
type LandingPolicies interface {
	// LandingFor reports the policy as the record holds it. found is false
	// when no explicit policy exists — which means the legacy landing, not a
	// default guess. An error refuses the merge: guessing a history shape
	// because the record was unreadable would be worse than refusing.
	LandingFor(ctx context.Context, tenantID, actorID string, roles []string, repoID string) (strategy string, trunkBased bool, found bool, err error)
}

// SetLandingPolicies attaches the landing-policy reader, post-construction
// like every cross-context fact source. A service without one lands legacy —
// the composition that has no repository settings to read has nothing to
// change behaviour over.
func (s *Service) SetLandingPolicies(reader LandingPolicies) {
	s.landings = reader
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
		// through submitting. SaveProjection is the write shaped for exactly this:
		// version-preserving by construction (ADR-0084 decision 1).
		mr.TargetRevision = event.NewSha
		if err := s.store.SaveProjection(ctx, mr); err != nil {
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
		if err := s.store.SaveProjection(ctx, mr); err != nil {
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
	state := api.StateOpen
	if req.Draft {
		// A draft is quiet (ADR-0087, SPEC-0064): it merges nothing, receives no
		// projections, and announces nothing until someone marks it ready.
		state = api.StateDraft
	}
	candidate := api.MergeRequest{
		ID: s.newID(), TenantID: req.TenantID, RepositoryID: req.RepositoryID,
		SourceRef: req.SourceRef, TargetRef: req.TargetRef,
		Title: req.Title, Description: req.Description,
		CreatorID: req.ActorID, State: state, HeadRevision: headRevision,
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
	// A draft announces nothing (ADR-0087 decision 3): the events below are what
	// attribution consumers and projections key on, and a draft must be invisible
	// to both until it is ready.
	if mr.State == api.StateOpen {
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
	// A draft accepts reviews — early feedback is the point (SPEC-0064 AC5) —
	// but nothing terminal or merged does.
	if mr.State != api.StateOpen && mr.State != api.StateDraft {
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
		return api.MergeRequest{}, saveErr(err)
	}

	if err := s.bus.Publish(ctx, api.ReviewSubmitted{
		EventID: s.newID(), MergeRequestID: mr.ID, TenantID: mr.TenantID, RepositoryID: mr.RepositoryID,
		ActorID: req.ActorID, Disposition: req.Disposition, HeadRevision: req.HeadRevision, OccurredAt: now,
		CreatorID: mr.CreatorID,
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
	// protection rule. Neither can be supplied by a caller (SPEC-0019 AC5). The
	// actors behind the count are captured here too, so the merge announcement
	// names exactly who counted AT THE GATE — not whoever approved by the time
	// the ref move finished (SPEC-0063).
	approvalActors, err := s.validApprovalActors(ctx, mr)
	if err != nil {
		return api.MergeRequest{}, api.ErrDenied
	}
	valid := len(approvalActors)
	protection, protected, err := s.store.Protection(ctx, mr.TenantID, mr.RepositoryID, mr.TargetRef)
	if err != nil {
		return api.MergeRequest{}, api.ErrDenied
	}
	decision, allowed := s.decide(ctx, req.Context, "merge_request.merge", "merge_request", mr.ID,
		s.mergeGateContext(ctx, mr, req.ActorID, slices.Clone(req.ActorRoles), map[string]string{
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

	now := s.now().UTC()
	mr.State, mr.Version, mr.UpdatedAt = api.StateMerged, mr.Version+1, now
	// The record is saved BEFORE the ref moves (ADR-0084 decision 3): a version
	// conflict refuses the merge while nothing has moved. The memory posture hid
	// this ordering because its Save could not fail; the durable one can.
	if err := s.store.Save(ctx, mr); err != nil {
		return api.MergeRequest{}, saveErr(err)
	}

	// The move names the target revision this context last saw. If the ref has
	// moved since — someone else merged, or a push landed — storage refuses, and
	// the merge fails rather than landing on state nobody decided about. The
	// record already says MERGED, so the refusal is compensated: a re-open under
	// its own version bump and a named audit record (SPEC-0061 AC12).
	// The landing policy is a server-side read from the repository record at
	// merge time (SPEC-0065 AC7) — after the gate has said yes, before the ref
	// moves. An unreadable record refuses rather than guessing: silently
	// changing the history shape because a read failed would be worse than the
	// coarse refusal every other failure produces. No policy wired, or none
	// recorded, means the legacy landing byte-for-byte.
	var plan *LandingPlan
	if s.landings != nil {
		strategy, trunkBased, found, err := s.landings.LandingFor(ctx,
			req.TenantID, req.ActorID, req.ActorRoles, mr.RepositoryID)
		if err != nil {
			return api.MergeRequest{}, api.ErrDenied
		}
		if found {
			plan = &LandingPlan{
				Strategy:              strategy,
				TrunkBased:            trunkBased,
				MessageTitle:          mr.Title,
				MergeRequestReference: mr.ID,
			}
		}
	}
	if err := s.refs.MoveRef(ctx, MergeRefCommand{
		TenantID: mr.TenantID, RepositoryID: mr.RepositoryID,
		ActorID: req.ActorID, RequestID: req.RequestID,
		ActorRoles: slices.Clone(req.ActorRoles),
		TargetRef:  mr.TargetRef, Revision: mr.HeadRevision,
		ExpectedCurrentRevision: mr.TargetRevision,
		Landing:                 plan,
	}); err != nil {
		if compErr := s.compensateMerge(ctx, mr, req.ActorID, req.RequestID, decision.DecisionID, err.Error()); compErr != nil {
			return api.MergeRequest{}, compErr
		}
		return api.MergeRequest{}, api.ErrDenied
	}

	if err := s.bus.Publish(ctx, api.MergeRequestMerged{
		EventID: s.newID(), MergeRequestID: mr.ID, TenantID: mr.TenantID, RepositoryID: mr.RepositoryID,
		ActorID: req.ActorID, TargetRef: mr.TargetRef, HeadRevision: mr.HeadRevision, OccurredAt: now,
		CreatorID:             mr.CreatorID,
		CountedApprovalActors: approvalActors,
	}); err != nil {
		return api.MergeRequest{}, err
	}
	return mr, s.bus.Publish(ctx, audit.MergeRequestMerged{
		TenantID: mr.TenantID, ActorID: req.ActorID, RepositoryID: mr.RepositoryID,
		MergeRequestID: mr.ID, TargetRef: mr.TargetRef, HeadRevision: mr.HeadRevision,
		RequestID: req.RequestID, PolicyDecisionID: decision.DecisionID, OccurredAt: now,
	})
}

// saveErr keeps a version conflict distinguishable from every other way a write
// can fail: a stale version is the one failure a caller can act on, and it has
// always surfaced as api.ErrVersionConflict — the guard moved into the durable
// write, and the wire did not move with it (ADR-0084 decision 2).
func saveErr(err error) error {
	if errors.Is(err, api.ErrVersionConflict) {
		return api.ErrVersionConflict
	}
	return api.ErrDenied
}

// compensateMerge re-opens a merge request whose ref move failed after the
// guarded Save had already recorded it MERGED, and names the compensation on the
// audit trail (SPEC-0061 AC12, ADR-0084 decision 3). Without it a retry would
// find a MERGED record pointing at a ref that never moved.
//
// The re-open retries against whatever row is there now — the same
// re-read-and-re-apply posture as the projection write — because a compensation
// that could itself be lost would leave exactly the hazard it exists for.
func (s *Service) compensateMerge(ctx context.Context, merged api.MergeRequest, actorID, requestID, decisionID, reason string) error {
	current := merged
	for range 8 {
		if current.State == api.StateMerged {
			current.State, current.Version, current.UpdatedAt = api.StateOpen, current.Version+1, s.now().UTC()
			err := s.store.Save(ctx, current)
			if errors.Is(err, api.ErrVersionConflict) {
				reloaded, getErr := s.store.Get(ctx, merged.ID)
				if getErr != nil {
					return getErr
				}
				current = reloaded
				continue
			}
			if err != nil {
				return err
			}
		}
		return s.bus.Publish(ctx, audit.MergeRequestMergeCompensated{
			TenantID: merged.TenantID, ActorID: actorID, RepositoryID: merged.RepositoryID,
			MergeRequestID: merged.ID, TargetRef: merged.TargetRef, HeadRevision: merged.HeadRevision,
			RequestID: requestID, PolicyDecisionID: decisionID, Reason: reason, OccurredAt: s.now().UTC(),
		})
	}
	return api.ErrVersionConflict
}

// MarkReady moves a DRAFT merge request to OPEN (ADR-0087, SPEC-0064). It is
// the draft's one transition: any other state is refused, the expected-version
// pre-check produces the same conflict error as every other command, and both
// revisions are re-read from what Repository/Git last announced — a draft opened
// against last week's target becomes reviewable against the current one.
func (s *Service) MarkReady(ctx context.Context, req api.ReadyRequest) (api.MergeRequest, error) {
	mr, err := s.Get(ctx, req.Context, req.MergeRequestID)
	if err != nil {
		return api.MergeRequest{}, api.ErrDenied
	}
	if mr.State != api.StateDraft {
		return api.MergeRequest{}, api.ErrDenied
	}
	if req.ExpectedVersion != mr.Version {
		return api.MergeRequest{}, api.ErrVersionConflict
	}
	if !s.allowed(ctx, req.Context, "merge_request.ready", "merge_request", mr.ID, nil) {
		return api.MergeRequest{}, api.ErrDenied
	}
	headRevision, err := s.store.RefRevision(ctx, mr.TenantID, mr.RepositoryID, mr.SourceRef)
	if err != nil || headRevision == "" {
		return api.MergeRequest{}, api.ErrDenied
	}
	targetRevision, err := s.store.RefRevision(ctx, mr.TenantID, mr.RepositoryID, mr.TargetRef)
	if err != nil {
		return api.MergeRequest{}, api.ErrDenied
	}
	mr.State, mr.HeadRevision, mr.TargetRevision = api.StateOpen, headRevision, targetRevision
	mr.Version, mr.UpdatedAt = mr.Version+1, s.now().UTC()
	if err := s.store.Save(ctx, mr); err != nil {
		return api.MergeRequest{}, saveErr(err)
	}
	// The draft's one announcement (SPEC-0064): everything before this was
	// quiet by decision. Notifications consumes it as the review-requested
	// fact (SPEC-0063 AC1) — same recipients as an open would have had.
	return mr, s.bus.Publish(ctx, api.MergeRequestReady{
		EventID: s.newID(), MergeRequestID: mr.ID, TenantID: mr.TenantID, RepositoryID: mr.RepositoryID,
		ActorID: req.ActorID, HeadRevision: mr.HeadRevision, TargetRef: mr.TargetRef,
		OccurredAt: mr.UpdatedAt,
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
// verified actor — identity AND roles: the merge-base read the comparison
// needs is resolved under the subject being decided about, never under a
// privileged server handle, and storage's PDP denies a role-less repo.read
// (north-star Stage D).
func (s *Service) mergeGateContext(ctx context.Context, mr api.MergeRequest, actorID string, actorRoles []string, base map[string]string) map[string]string {
	if s.findings == nil {
		return base
	}
	base[api.ContextKeyFindingsGate] = "true"
	facts, err := s.findings.FindingsFacts(ctx, mr.TenantID, mr.RepositoryID, actorID, actorRoles, mr.ID)
	if err != nil {
		return base
	}
	maps.Copy(base, facts.Context())
	return base
}

// validApprovals counts approvals made against the merge request's current head
// revision by people who are not the author (ADR-0085, SPEC-0062 AC3). A changed
// head therefore invalidates every earlier approval, which is the whole point of
// pinning a review to a revision (SPEC-0019 AC4); and the author's own review —
// still recorded, still audited as review activity — never counts toward the
// gate, because four eyes means two people who are not the one being merged.
func (s *Service) validApprovals(ctx context.Context, mr api.MergeRequest) (int, error) {
	actors, err := s.validApprovalActors(ctx, mr)
	if err != nil {
		return 0, err
	}
	return len(actors), nil
}

// validApprovalActors names the approvals validApprovals counts. The names are
// published on MergeRequestMerged so a recipient-deriving consumer needs no
// reach-back into this context (SPEC-0063); they are still only names — never
// a count, never an outcome.
func (s *Service) validApprovalActors(ctx context.Context, mr api.MergeRequest) ([]string, error) {
	reviews, err := s.store.Reviews(ctx, mr.ID)
	if err != nil {
		return nil, err
	}
	var actors []string
	for _, review := range reviews {
		if review.ActorID == mr.CreatorID {
			continue
		}
		if review.Disposition == api.DispositionApprove && review.HeadRevision == mr.HeadRevision {
			actors = append(actors, review.ActorID)
		}
	}
	return actors, nil
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

// NewMemoryStore returns the dev/in-memory store. A plane with a database pool
// gets the durable store instead (adapters/postgres); a plane without one runs
// this, and loses every merge request, review, branch-protection rule and
// external issue reference on restart — a dev convenience, not a production
// posture (ADR-0080 decision 4).
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

// SaveProjection is the memory store's version-preserving write: the same
// unguarded overwrite as Save, because the version guard lives in the durable
// adapter and the in-memory store cannot race itself.
func (m *memoryStore) SaveProjection(_ context.Context, mr api.MergeRequest) error {
	return m.Save(nil, mr)
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
