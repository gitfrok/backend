package app

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/gitfrok/backend/modules/codereview/api"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
	repoapi "github.com/gitfrok/backend/modules/repository/api"
	"github.com/gitfrok/backend/platform/audit"
	"github.com/gitfrok/backend/platform/bus"
)

// recordingPDP answers from the same rule shape the Rego policy uses, and keeps
// every request so the tests can assert what context the PEP derived.
type recordingPDP struct {
	requests []policyapi.Request
	deny     map[string]bool
}

func (p *recordingPDP) Decide(_ context.Context, req policyapi.Request) (policyapi.Decision, error) {
	p.requests = append(p.requests, req)
	if p.deny[req.Action] {
		return policyapi.Decision{Allowed: false, DecisionID: "decision-deny"}, nil
	}
	// The merge rule is the one the PDP evaluates from server-derived counts,
	// including the four-eyes floor the bundle enforces beside required_approvals
	// (ADR-0085) — the fake mirrors the real rule so a service-level test cannot
	// pass on facts the bundle would refuse.
	if req.Action == "merge_request.merge" {
		valid, _ := strconv.Atoi(req.Context["valid_approvals"])
		required, _ := strconv.Atoi(req.Context["required_approvals"])
		if valid < required || valid < 2 {
			return policyapi.Decision{Allowed: false, DecisionID: "decision-insufficient"}, nil
		}
	}
	return policyapi.Decision{Allowed: true, DecisionID: "decision-allow"}, nil
}

func (p *recordingPDP) lastFor(action string) (policyapi.Request, bool) {
	for i := len(p.requests) - 1; i >= 0; i-- {
		if p.requests[i].Action == action {
			return p.requests[i], true
		}
	}
	return policyapi.Request{}, false
}

type recordingRefs struct {
	moves    []string
	commands []MergeRefCommand
	current  map[string]string
	err      error
}

// MoveRef enforces the same compare-and-swap storage does, so a merge naming a
// stale target revision fails here exactly as it would there.
func (r *recordingRefs) MoveRef(_ context.Context, command MergeRefCommand) error {
	r.commands = append(r.commands, command)
	if r.err != nil {
		return r.err
	}
	key := command.TenantID + "/" + command.RepositoryID + "/" + command.TargetRef
	if r.current != nil {
		if r.current[key] != command.ExpectedCurrentRevision {
			return errors.New("the ref moved since the merge was decided")
		}
		r.current[key] = command.Revision
	}
	r.moves = append(r.moves, key+"@"+command.Revision)
	return nil
}

type collector struct {
	approvals []audit.MergeRequestApproved
	merges    []audit.MergeRequestMerged
	opened    []api.MergeRequestOpened
	reviews   []api.ReviewSubmitted
	merged    []api.MergeRequestMerged
	protected []api.BranchProtectionChanged
	// events is the plane's bus, so a test can announce a ref update the way
	// Repository/Git does.
	events bus.Bus
}

func newService(t *testing.T) (*Service, *recordingPDP, *recordingRefs, *collector) {
	t.Helper()
	pdp := &recordingPDP{deny: map[string]bool{}}
	refs := &recordingRefs{}
	events := bus.NewInProcess()
	got := &collector{}
	// Every audit record travels under one event name, so they are collected on
	// the audit topic and sorted by concrete type rather than by subscription.
	events.Subscribe(audit.EventAudit, func(_ context.Context, e bus.Event) error {
		switch record := e.(type) {
		case audit.MergeRequestApproved:
			got.approvals = append(got.approvals, record)
		case audit.MergeRequestMerged:
			got.merges = append(got.merges, record)
		}
		return nil
	})
	bus.SubscribeTyped(events, func(_ context.Context, e api.MergeRequestOpened) error {
		got.opened = append(got.opened, e)
		return nil
	})
	bus.SubscribeTyped(events, func(_ context.Context, e api.ReviewSubmitted) error {
		got.reviews = append(got.reviews, e)
		return nil
	})
	bus.SubscribeTyped(events, func(_ context.Context, e api.MergeRequestMerged) error {
		got.merged = append(got.merged, e)
		return nil
	})
	bus.SubscribeTyped(events, func(_ context.Context, e api.BranchProtectionChanged) error {
		got.protected = append(got.protected, e)
		return nil
	})

	counter := 0
	service := New(NewMemoryStore(), refs, pdp, events,
		WithIDs(func() string { counter++; return "id-" + strconv.Itoa(counter) }),
		WithClock(func() time.Time { return time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC) }),
	)
	service.SubscribeRefUpdates(events)
	got.events = events
	// The target ref exists before any merge request opens against it, which is
	// what Repository/Git would have announced by then.
	announceTarget(t, events, "refs/heads/main", "sha-target")
	announceTarget(t, events, "refs/heads/feature", "sha-head")
	return service, pdp, refs, got
}

func principal(tenant, actor, request string, roles ...string) api.Context {
	return api.Context{TenantID: tenant, RepositoryID: "repo-a", ActorID: actor, RequestID: request, ActorRoles: roles}
}

// announceTarget is how Repository/Git tells Code Review where a ref stands. The
// tests use it rather than seeding state directly, because the event is the only
// route by which this context learns a revision.
func announceTarget(t *testing.T, events bus.Bus, ref, revision string) {
	t.Helper()
	if err := events.Publish(t.Context(), repoapi.RefUpdated{
		EventID: "event-" + revision, TenantID: "tenant-a", RepoID: "repo-a", Ref: ref,
		NewSha: revision, ActorID: "actor-z", OccurredAt: time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatalf("Publish RefUpdated: %v", err)
	}
}

func openOne(t *testing.T, s *Service, requestID string) api.MergeRequest {
	t.Helper()
	mr, err := s.Open(t.Context(), api.OpenRequest{
		Context:   principal("tenant-a", "actor-a", requestID, "member"),
		SourceRef: "refs/heads/feature", TargetRef: "refs/heads/main",
		Title: "Add a thing",
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return mr
}

// approveAs records one approval by the named actor at the merge request's
// current head. The four-eyes floor (ADR-0085) means a mergeable merge request
// needs two of these from two people who are not the author, so tests that land
// a merge call it twice with distinct actors.
func approveAs(t *testing.T, s *Service, mr api.MergeRequest, actor, requestID string) api.MergeRequest {
	t.Helper()
	reviewed, err := s.Review(t.Context(), api.ReviewRequest{
		Context:        principal("tenant-a", actor, requestID, "member"),
		MergeRequestID: mr.ID, Disposition: api.DispositionApprove,
		HeadRevision: mr.HeadRevision, ExpectedVersion: mr.Version,
	})
	if err != nil {
		t.Fatalf("Review (%s): %v", actor, err)
	}
	return reviewed
}

// approveTwoRecords the floor's worth of approvals — actor-b then actor-c, neither
// of them the author.
func approveTwo(t *testing.T, s *Service, mr api.MergeRequest) api.MergeRequest {
	t.Helper()
	mr = approveAs(t, s, mr, "actor-b", "request-review")
	return approveAs(t, s, mr, "actor-c", "request-review-2")
}

// AC1: open, review, and merge at the current expected version; a replayed
// request ID is idempotent and a stale version changes nothing.
func TestOpenReviewMergeAtTheExpectedVersion(t *testing.T) {
	service, _, refs, got := newService(t)
	ctx := t.Context()

	mr := openOne(t, service, "request-open")
	if mr.State != api.StateOpen || mr.Version != 1 {
		t.Fatalf("opened = %+v, want an OPEN request at version 1", mr)
	}
	if len(got.opened) != 1 {
		t.Fatalf("MergeRequestOpened published %d times", len(got.opened))
	}

	reviewed, err := service.Review(ctx, api.ReviewRequest{
		Context:        principal("tenant-a", "actor-b", "request-review", "member"),
		MergeRequestID: mr.ID, Disposition: api.DispositionApprove,
		HeadRevision: "sha-head", ExpectedVersion: mr.Version,
	})
	if err != nil {
		t.Fatalf("Review: %v", err)
	}
	if reviewed.Version != 2 {
		t.Fatalf("version after review = %d, want 2", reviewed.Version)
	}
	// The floor (ADR-0085): a mergeable merge request carries two non-author
	// approvals, so the happy path now reviews twice before it merges.
	reviewed = approveAs(t, service, reviewed, "actor-c", "request-review-2")

	merged, err := service.Merge(ctx, api.MergeRequestCommand{
		Context:        principal("tenant-a", "actor-a", "request-merge", "member"),
		MergeRequestID: mr.ID, ExpectedVersion: reviewed.Version,
	})
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	if merged.State != api.StateMerged {
		t.Fatalf("state = %s, want MERGED", merged.State)
	}
	if len(refs.moves) != 1 || refs.moves[0] != "tenant-a/repo-a/refs/heads/main@sha-head" {
		t.Fatalf("ref moves = %v", refs.moves)
	}

	// Replaying the merge request ID changes nothing and moves no ref again.
	replayed, err := service.Merge(ctx, api.MergeRequestCommand{
		Context:        principal("tenant-a", "actor-a", "request-merge", "member"),
		MergeRequestID: mr.ID, ExpectedVersion: merged.Version,
	})
	if !errors.Is(err, api.ErrDenied) {
		t.Fatalf("re-merging a merged request: got %+v/%v, want a denial", replayed, err)
	}
	if len(refs.moves) != 1 {
		t.Fatalf("a replayed merge moved the ref again: %v", refs.moves)
	}
}

func TestOpenIsIdempotentOnTheRequestID(t *testing.T) {
	service, _, _, got := newService(t)
	first := openOne(t, service, "request-open")
	second := openOne(t, service, "request-open")
	if first.ID != second.ID {
		t.Fatalf("replaying a request ID opened a second merge request: %s vs %s", first.ID, second.ID)
	}
	if len(got.opened) != 1 {
		t.Fatalf("MergeRequestOpened published %d times for one request ID", len(got.opened))
	}
}

func TestStaleVersionChangesNoState(t *testing.T) {
	service, _, _, _ := newService(t)
	ctx := t.Context()
	mr := openOne(t, service, "request-open")

	if _, err := service.Review(ctx, api.ReviewRequest{
		Context:        principal("tenant-a", "actor-b", "request-review", "member"),
		MergeRequestID: mr.ID, Disposition: api.DispositionApprove,
		HeadRevision: "sha-head", ExpectedVersion: mr.Version + 5,
	}); !errors.Is(err, api.ErrVersionConflict) {
		t.Fatalf("stale review version: %v, want a version conflict", err)
	}

	current, err := service.Get(ctx, principal("tenant-a", "actor-a", "request-get", "member"), mr.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if current.Version != mr.Version {
		t.Fatalf("version = %d, want it unchanged at %d", current.Version, mr.Version)
	}
}

// AC2: nothing is reachable across a tenant boundary, and the refusal is the
// same coarse one a missing merge request produces.
func TestAnotherTenantSeesNothing(t *testing.T) {
	service, _, refs, _ := newService(t)
	ctx := t.Context()
	mr := openOne(t, service, "request-open")

	intruder := principal("tenant-b", "actor-x", "request-x", "owner")
	if _, err := service.Get(ctx, intruder, mr.ID); !errors.Is(err, api.ErrDenied) {
		t.Fatalf("cross-tenant Get: %v, want the coarse denial", err)
	}
	if _, err := service.Review(ctx, api.ReviewRequest{
		Context: intruder, MergeRequestID: mr.ID, Disposition: api.DispositionApprove,
		HeadRevision: "sha-head", ExpectedVersion: 1,
	}); !errors.Is(err, api.ErrDenied) {
		t.Fatalf("cross-tenant Review: %v, want the coarse denial", err)
	}
	if _, err := service.Merge(ctx, api.MergeRequestCommand{
		Context: intruder, MergeRequestID: mr.ID, ExpectedVersion: 1,
	}); !errors.Is(err, api.ErrDenied) {
		t.Fatalf("cross-tenant Merge: %v, want the coarse denial", err)
	}
	if len(refs.moves) != 0 {
		t.Fatalf("a cross-tenant merge moved a ref: %v", refs.moves)
	}

	// The same refusal for a merge request that never existed: the surface does
	// not distinguish the two, so it cannot be used to enumerate either.
	if _, err := service.Get(ctx, principal("tenant-a", "actor-a", "request-y", "member"), "no-such-id"); !errors.Is(err, api.ErrDenied) {
		t.Fatalf("unknown ID: %v, want the same coarse denial", err)
	}
}

// AC3: a PDP-approved merge with the required approvals moves the protected
// ref. (The direct-push half is enforced by the Git transport PEP against its
// own projection; see the repository projection tests.)
func TestProtectedRefIsMergedOnlyWithTheRequiredApprovals(t *testing.T) {
	service, pdp, refs, _ := newService(t)
	ctx := t.Context()

	if _, err := service.SetProtection(ctx, api.ProtectionRequest{
		Context:   principal("tenant-a", "admin-a", "request-protect", "owner"),
		TargetRef: "refs/heads/main", RequiredApprovals: 1,
	}); err != nil {
		t.Fatalf("SetProtection: %v", err)
	}

	mr := openOne(t, service, "request-open")
	if _, err := service.Merge(ctx, api.MergeRequestCommand{
		Context:        principal("tenant-a", "actor-a", "request-merge-early", "member"),
		MergeRequestID: mr.ID, ExpectedVersion: mr.Version,
	}); !errors.Is(err, api.ErrDenied) {
		t.Fatal("an unapproved merge into a protected ref was allowed")
	}
	if len(refs.moves) != 0 {
		t.Fatalf("a denied merge moved the ref: %v", refs.moves)
	}
	request, ok := pdp.lastFor("merge_request.merge")
	if !ok {
		t.Fatal("the merge was refused without asking the PDP")
	}
	if request.Context["protected"] != "true" || request.Context["required_approvals"] != "1" || request.Context["valid_approvals"] != "0" {
		t.Fatalf("PDP context = %v, want the server-derived protection facts", request.Context)
	}

	reviewed, err := service.Review(ctx, api.ReviewRequest{
		Context:        principal("tenant-a", "actor-b", "request-review", "member"),
		MergeRequestID: mr.ID, Disposition: api.DispositionApprove,
		HeadRevision: "sha-head", ExpectedVersion: mr.Version,
	})
	if err != nil {
		t.Fatalf("Review: %v", err)
	}
	reviewed = approveAs(t, service, reviewed, "actor-c", "request-review-2")
	if _, err := service.Merge(ctx, api.MergeRequestCommand{
		Context:        principal("tenant-a", "actor-a", "request-merge", "member"),
		MergeRequestID: mr.ID, ExpectedVersion: reviewed.Version,
	}); err != nil {
		t.Fatalf("approved merge into a protected ref: %v", err)
	}
	if len(refs.moves) != 1 {
		t.Fatalf("approved merge moved %d refs, want 1", len(refs.moves))
	}
}

// AC4: an approval is pinned to the revision it was made against, so a changed
// head invalidates it.
func TestApprovalFromAnotherHeadRevisionDoesNotCount(t *testing.T) {
	service, pdp, _, _ := newService(t)
	ctx := t.Context()
	mr := openOne(t, service, "request-open")

	reviewed, err := service.Review(ctx, api.ReviewRequest{
		Context:        principal("tenant-a", "actor-b", "request-review", "member"),
		MergeRequestID: mr.ID, Disposition: api.DispositionApprove,
		HeadRevision: "sha-old", ExpectedVersion: mr.Version,
	})
	if err != nil {
		t.Fatalf("Review: %v", err)
	}
	// Two approvals at the current head satisfy the floor (ADR-0085); if the
	// stale head approval counted, the fact below would read 3 rather than 2.
	reviewed = approveAs(t, service, reviewed, "actor-c", "request-review-2")
	reviewed = approveAs(t, service, reviewed, "actor-d", "request-review-3")
	if _, err := service.Merge(ctx, api.MergeRequestCommand{
		Context:        principal("tenant-a", "actor-a", "request-merge", "member"),
		MergeRequestID: mr.ID, ExpectedVersion: reviewed.Version,
	}); err != nil {
		t.Fatalf("Merge: %v", err)
	}
	request, _ := pdp.lastFor("merge_request.merge")
	if request.Context["valid_approvals"] != "2" {
		t.Fatalf("valid_approvals = %q, want an approval from another head to count for nothing", request.Context["valid_approvals"])
	}
}

func TestALaterReviewSupersedesTheSameActorsEarlierOne(t *testing.T) {
	service, pdp, _, _ := newService(t)
	ctx := t.Context()
	mr := openOne(t, service, "request-open")

	reviewed, err := service.Review(ctx, api.ReviewRequest{
		Context:        principal("tenant-a", "actor-b", "request-approve", "member"),
		MergeRequestID: mr.ID, Disposition: api.DispositionApprove,
		HeadRevision: "sha-head", ExpectedVersion: mr.Version,
	})
	if err != nil {
		t.Fatalf("Review: %v", err)
	}
	reviewed, err = service.Review(ctx, api.ReviewRequest{
		Context:        principal("tenant-a", "actor-b", "request-retract", "member"),
		MergeRequestID: mr.ID, Disposition: api.DispositionRequestChanges,
		HeadRevision: "sha-head", ExpectedVersion: reviewed.Version,
	})
	if err != nil {
		t.Fatalf("superseding Review: %v", err)
	}
	// The floor's worth of fresh approvals (ADR-0085); if the superseded
	// request-changes disposition counted as an approval, the fact below would
	// read 3 rather than 2.
	reviewed = approveAs(t, service, reviewed, "actor-c", "request-review-2")
	reviewed = approveAs(t, service, reviewed, "actor-d", "request-review-3")

	if _, err := service.Merge(ctx, api.MergeRequestCommand{
		Context:        principal("tenant-a", "actor-a", "request-merge", "member"),
		MergeRequestID: mr.ID, ExpectedVersion: reviewed.Version,
	}); err != nil {
		t.Fatalf("Merge: %v", err)
	}
	request, _ := pdp.lastFor("merge_request.merge")
	if request.Context["valid_approvals"] != "2" {
		t.Fatalf("valid_approvals = %q, want the superseded approval not to count", request.Context["valid_approvals"])
	}
}

// AC5: every authorization-sensitive command asks the PDP, with roles taken from
// the verified context rather than from anything the caller could assert.
func TestEveryMutationAsksThePDP(t *testing.T) {
	service, pdp, _, _ := newService(t)
	ctx := t.Context()

	mr := openOne(t, service, "request-open")
	mr = approveAs(t, service, mr, "actor-b", "request-review")
	mr = approveAs(t, service, mr, "actor-c", "request-review-2")
	if _, err := service.SetProtection(ctx, api.ProtectionRequest{
		Context:   principal("tenant-a", "admin-a", "request-protect", "owner"),
		TargetRef: "refs/heads/main", RequiredApprovals: 0,
	}); err != nil {
		t.Fatalf("SetProtection: %v", err)
	}
	if _, err := service.Merge(ctx, api.MergeRequestCommand{
		Context:        principal("tenant-a", "actor-a", "request-merge", "member"),
		MergeRequestID: mr.ID, ExpectedVersion: mr.Version,
	}); err != nil {
		t.Fatalf("Merge: %v", err)
	}

	for _, action := range []string{"merge_request.open", "merge_request.review", "merge_request.merge", "repository.branch_protection.manage"} {
		request, ok := pdp.lastFor(action)
		if !ok {
			t.Fatalf("no PDP decision was asked for %s", action)
		}
		if request.TenantID != "tenant-a" || request.Subject.TenantID != "tenant-a" {
			t.Errorf("%s asked outside the caller's tenant: %+v", action, request)
		}
		if len(request.Subject.Roles) == 0 {
			t.Errorf("%s asked without the verified actor roles", action)
		}
		if _, present := request.Context["allowed"]; present {
			t.Errorf("%s carried an allow flag into the decision", action)
		}
	}
}

func TestADeniedCommandChangesNoState(t *testing.T) {
	service, pdp, refs, got := newService(t)
	ctx := t.Context()
	pdp.deny["merge_request.open"] = true

	if _, err := service.Open(ctx, api.OpenRequest{
		Context:   principal("tenant-a", "actor-a", "request-open", "reader"),
		SourceRef: "refs/heads/feature", TargetRef: "refs/heads/main",
	}); !errors.Is(err, api.ErrDenied) {
		t.Fatalf("a PDP denial produced %v, want the coarse denial", err)
	}
	if len(got.opened) != 0 || len(refs.moves) != 0 {
		t.Fatal("a denied open still changed state")
	}
}

// AC6: an accepted approval and an accepted merge each append exactly one
// immutable audit record, correlated to the PDP decision.
func TestAcceptedApprovalAndMergeAreEachAuditedOnce(t *testing.T) {
	service, _, _, got := newService(t)
	ctx := t.Context()
	mr := openOne(t, service, "request-open")

	reviewed, err := service.Review(ctx, api.ReviewRequest{
		Context:        principal("tenant-a", "actor-b", "request-review", "member"),
		MergeRequestID: mr.ID, Disposition: api.DispositionApprove,
		HeadRevision: "sha-head", ExpectedVersion: mr.Version,
	})
	if err != nil {
		t.Fatalf("Review: %v", err)
	}
	// The floor (ADR-0085): the merge needs a second non-author approval.
	reviewed = approveAs(t, service, reviewed, "actor-c", "request-review-2")
	if _, err := service.Merge(ctx, api.MergeRequestCommand{
		Context:        principal("tenant-a", "actor-a", "request-merge", "member"),
		MergeRequestID: mr.ID, ExpectedVersion: reviewed.Version,
	}); err != nil {
		t.Fatalf("Merge: %v", err)
	}

	if len(got.approvals) != 2 {
		t.Fatalf("approval audit records = %d, want exactly 2 — one per accepting approval", len(got.approvals))
	}
	approval := got.approvals[0]
	if approval.TenantID != "tenant-a" || approval.ActorID != "actor-b" || approval.MergeRequestID != mr.ID ||
		approval.RequestID != "request-review" || approval.PolicyDecisionID == "" {
		t.Fatalf("approval audit record = %+v", approval)
	}
	if approval.Action() != audit.ActionMergeRequestApproved {
		t.Fatalf("approval action = %q", approval.Action())
	}

	if len(got.merges) != 1 {
		t.Fatalf("merge audit records = %d, want exactly 1", len(got.merges))
	}
	if got.merges[0].PolicyDecisionID == "" || got.merges[0].TargetRef != "refs/heads/main" {
		t.Fatalf("merge audit record = %+v", got.merges[0])
	}
}

func TestACommentIsNotAuditedAsAnApproval(t *testing.T) {
	service, _, _, got := newService(t)
	mr := openOne(t, service, "request-open")
	if _, err := service.Review(t.Context(), api.ReviewRequest{
		Context:        principal("tenant-a", "actor-b", "request-review", "member"),
		MergeRequestID: mr.ID, Disposition: api.DispositionComment,
		HeadRevision: "sha-head", ExpectedVersion: mr.Version,
	}); err != nil {
		t.Fatalf("Review: %v", err)
	}
	if len(got.approvals) != 0 {
		t.Fatalf("a comment produced %d approval audit records", len(got.approvals))
	}
	if len(got.reviews) != 1 {
		t.Fatalf("ReviewSubmitted published %d times", len(got.reviews))
	}
}

// A merged request is terminal: it cannot be reviewed afterwards.
func TestAMergedRequestCannotBeReviewed(t *testing.T) {
	service, _, _, _ := newService(t)
	ctx := t.Context()
	mr := openOne(t, service, "request-open")
	mr = approveTwo(t, service, mr)
	merged, err := service.Merge(ctx, api.MergeRequestCommand{
		Context:        principal("tenant-a", "actor-a", "request-merge", "member"),
		MergeRequestID: mr.ID, ExpectedVersion: mr.Version,
	})
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	if _, err := service.Review(ctx, api.ReviewRequest{
		Context:        principal("tenant-a", "actor-b", "request-review", "member"),
		MergeRequestID: mr.ID, Disposition: api.DispositionApprove,
		HeadRevision: "sha-head", ExpectedVersion: merged.Version,
	}); !errors.Is(err, api.ErrDenied) {
		t.Fatalf("reviewing a merged request: %v, want a denial", err)
	}
}

func TestProtectionIsAnExactRefRuleAndIsAnnounced(t *testing.T) {
	service, _, _, got := newService(t)
	ctx := t.Context()

	if _, err := service.SetProtection(ctx, api.ProtectionRequest{
		Context:   principal("tenant-a", "admin-a", "request-wildcard", "owner"),
		TargetRef: "refs/heads/*", RequiredApprovals: 1,
	}); !errors.Is(err, api.ErrDenied) {
		t.Fatal("a wildcard branch pattern was accepted; v1 is exact refs only")
	}

	protection, err := service.SetProtection(ctx, api.ProtectionRequest{
		Context:   principal("tenant-a", "admin-a", "request-protect", "owner"),
		TargetRef: "refs/heads/main", RequiredApprovals: 2,
	})
	if err != nil {
		t.Fatalf("SetProtection: %v", err)
	}
	if protection.Version != 1 {
		t.Fatalf("protection version = %d, want 1", protection.Version)
	}
	if len(got.protected) != 1 || got.protected[0].RequiredApprovals != 2 {
		t.Fatalf("BranchProtectionChanged = %+v", got.protected)
	}

	if _, err := service.SetProtection(ctx, api.ProtectionRequest{
		Context:   principal("tenant-a", "admin-a", "request-stale", "owner"),
		TargetRef: "refs/heads/main", RequiredApprovals: 3, ExpectedVersion: 0,
	}); !errors.Is(err, api.ErrVersionConflict) {
		t.Fatalf("replacing a protection rule at a stale version: %v", err)
	}
}

// Zero required approvals still protects the ref: it is what a direct push is
// refused against, while an authorized merge still passes.
func TestZeroApprovalsStillMarksTheRefProtected(t *testing.T) {
	service, pdp, _, _ := newService(t)
	ctx := t.Context()
	if _, err := service.SetProtection(ctx, api.ProtectionRequest{
		Context:   principal("tenant-a", "admin-a", "request-protect", "owner"),
		TargetRef: "refs/heads/main", RequiredApprovals: 0,
	}); err != nil {
		t.Fatalf("SetProtection: %v", err)
	}
	mr := openOne(t, service, "request-open")
	// Zero required approvals protects the ref against direct pushes; it does not
	// lower the platform's four-eyes floor (ADR-0085), so the merge still reviews.
	mr = approveTwo(t, service, mr)
	if _, err := service.Merge(ctx, api.MergeRequestCommand{
		Context:        principal("tenant-a", "actor-a", "request-merge", "member"),
		MergeRequestID: mr.ID, ExpectedVersion: mr.Version,
	}); err != nil {
		t.Fatalf("Merge into a zero-approval protected ref: %v", err)
	}
	request, _ := pdp.lastFor("merge_request.merge")
	if request.Context["protected"] != "true" {
		t.Fatalf("protected = %q, want a zero-approval rule to still mark the ref protected", request.Context["protected"])
	}
}

// A failed ref move leaves the merge request open rather than reporting a merge
// that did not happen.
func TestAFailedRefMoveDoesNotMergeTheRequest(t *testing.T) {
	service, _, refs, got := newService(t)
	ctx := t.Context()
	refs.err = errors.New("git-storaged unavailable")

	mr := openOne(t, service, "request-open")
	if _, err := service.Merge(ctx, api.MergeRequestCommand{
		Context:        principal("tenant-a", "actor-a", "request-merge", "member"),
		MergeRequestID: mr.ID, ExpectedVersion: mr.Version,
	}); !errors.Is(err, api.ErrDenied) {
		t.Fatalf("a failed ref move produced %v", err)
	}
	current, err := service.Get(ctx, principal("tenant-a", "actor-a", "request-get", "member"), mr.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if current.State != api.StateOpen {
		t.Fatalf("state = %s, want the request still OPEN", current.State)
	}
	if len(got.merged) != 0 || len(got.merges) != 0 {
		t.Fatal("a failed ref move still announced or audited a merge")
	}
}

// The move must name the revision the target ref was at when the merge was
// decided, so storage can refuse it if the ref has since moved.
func TestMergeNamesTheTargetRevisionItWasDecidedAgainst(t *testing.T) {
	service, _, refs, _ := newService(t)
	refs.current = map[string]string{"tenant-a/repo-a/refs/heads/main": "sha-target"}
	ctx := t.Context()

	mr := openOne(t, service, "request-open")
	mr = approveTwo(t, service, mr)
	if _, err := service.Merge(ctx, api.MergeRequestCommand{
		Context:        principal("tenant-a", "actor-a", "request-merge", "member"),
		MergeRequestID: mr.ID, ExpectedVersion: mr.Version,
	}); err != nil {
		t.Fatalf("Merge: %v", err)
	}
	command := refs.commands[0]
	if command.ExpectedCurrentRevision != "sha-target" {
		t.Fatalf("expected current revision = %q, want the observed target revision", command.ExpectedCurrentRevision)
	}
	if command.Revision != "sha-head" || command.TargetRef != "refs/heads/main" {
		t.Fatalf("move = %+v", command)
	}
	// The verified principal travels with the move: storage asks its own PDP.
	if command.ActorID != "actor-a" || len(command.ActorRoles) == 0 || command.RequestID != "request-merge" {
		t.Fatalf("move carried no verified principal: %+v", command)
	}
}

// A ref that moved under an open merge request is observed from RefUpdated, not
// read out of Git, and the next merge names the new revision.
func TestRefUpdatedRefreshesTheTargetRevision(t *testing.T) {
	service, _, refs, got := newService(t)
	events := got.events
	refs.current = map[string]string{"tenant-a/repo-a/refs/heads/main": "sha-moved"}
	ctx := t.Context()

	mr := openOne(t, service, "request-open")
	if err := events.Publish(ctx, repoapi.RefUpdated{
		EventID: "event-1", TenantID: "tenant-a", RepoID: "repo-a", Ref: "refs/heads/main",
		OldSha: "sha-target", NewSha: "sha-moved", ActorID: "actor-c", OccurredAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	current, err := service.Get(ctx, principal("tenant-a", "actor-a", "request-get", "member"), mr.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if current.TargetRevision != "sha-moved" {
		t.Fatalf("target revision = %q, want the revision RefUpdated announced", current.TargetRevision)
	}
	if current.Version != mr.Version {
		t.Fatalf("version = %d, want a ref move not to invalidate the caller's version", current.Version)
	}
	current = approveAs(t, service, current, "actor-b", "request-review")
	current = approveAs(t, service, current, "actor-c", "request-review-2")
	if _, err := service.Merge(ctx, api.MergeRequestCommand{
		Context:        principal("tenant-a", "actor-a", "request-merge", "member"),
		MergeRequestID: mr.ID, ExpectedVersion: current.Version,
	}); err != nil {
		t.Fatalf("Merge after the target moved: %v", err)
	}
}

// A ref update in another tenant, another repository, or on another ref must not
// touch this merge request's view of its target.
func TestRefUpdatedIsScopedToTheMergeRequestsOwnTarget(t *testing.T) {
	service, _, _, got := newService(t)
	events := got.events
	ctx := t.Context()
	mr := openOne(t, service, "request-open")

	for _, event := range []repoapi.RefUpdated{
		{EventID: "e1", TenantID: "tenant-b", RepoID: "repo-a", Ref: "refs/heads/main", NewSha: "other"},
		{EventID: "e2", TenantID: "tenant-a", RepoID: "repo-b", Ref: "refs/heads/main", NewSha: "other"},
		{EventID: "e3", TenantID: "tenant-a", RepoID: "repo-a", Ref: "refs/heads/release", NewSha: "other"},
	} {
		if err := events.Publish(ctx, event); err != nil {
			t.Fatalf("Publish: %v", err)
		}
	}

	current, err := service.Get(ctx, principal("tenant-a", "actor-a", "request-get", "member"), mr.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if current.TargetRevision != "sha-target" {
		t.Fatalf("target revision = %q, want it untouched by another scope's ref update", current.TargetRevision)
	}
}

// If storage refuses the move because the ref moved, the merge request stays open
// rather than reporting a merge that did not happen.
func TestAMergeAgainstAMovedRefIsRefusedAndLeavesTheRequestOpen(t *testing.T) {
	service, _, refs, got := newService(t)
	refs.current = map[string]string{"tenant-a/repo-a/refs/heads/main": "sha-someone-else"}
	ctx := t.Context()

	mr := openOne(t, service, "request-open")
	if _, err := service.Merge(ctx, api.MergeRequestCommand{
		Context:        principal("tenant-a", "actor-a", "request-merge", "member"),
		MergeRequestID: mr.ID, ExpectedVersion: mr.Version,
	}); !errors.Is(err, api.ErrDenied) {
		t.Fatalf("merging onto a moved ref: %v, want a denial", err)
	}
	current, err := service.Get(ctx, principal("tenant-a", "actor-a", "request-get", "member"), mr.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if current.State != api.StateOpen {
		t.Fatalf("state = %s, want the request still OPEN", current.State)
	}
	if len(got.merged) != 0 || len(got.merges) != 0 {
		t.Fatal("a refused move still announced or audited a merge")
	}
}

// The target revision is Repository/Git's fact. A merge request opened before
// this context has been told where the ref stands has no observed revision, which
// is honest — it is not a guess, and it is not something the caller supplied.
func TestTargetRevisionComesFromRepositoryGitNotTheCaller(t *testing.T) {
	service, _, _, got := newService(t)

	mr := openOne(t, service, "request-open")
	if mr.TargetRevision != "sha-target" {
		t.Fatalf("target revision = %q, want the announced revision", mr.TargetRevision)
	}

	// Nothing on the open surface can express a different one.
	announceTarget(t, got.events, "refs/heads/release", "sha-release")
	other, err := service.Open(t.Context(), api.OpenRequest{
		Context:   principal("tenant-a", "actor-a", "request-other", "member"),
		SourceRef: "refs/heads/feature", TargetRef: "refs/heads/release",
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if other.TargetRevision != "sha-release" {
		t.Fatalf("target revision = %q, want the revision announced for that ref", other.TargetRevision)
	}
}

// --- T-0025 / SPEC-0029 / SPEC-0030: the security merge gate's findings facts ---

// fakeFactsProvider assembles the findings facts from test state, exactly the
// way Security/Findings' assembler would: the merge service never knows which.
type fakeFactsProvider struct {
	facts api.FindingsGateFacts
	err   error
	calls int
	last  struct {
		tenant, repository, actor, mergeRequest string
		roles                                   []string
	}
}

func (f *fakeFactsProvider) FindingsFacts(_ context.Context, tenantID, repositoryID, actorID string, actorRoles []string, mergeRequestID string) (api.FindingsGateFacts, error) {
	f.calls++
	f.last.tenant, f.last.repository = tenantID, repositoryID
	f.last.actor, f.last.mergeRequest = actorID, mergeRequestID
	f.last.roles = actorRoles
	return f.facts, f.err
}

// protectedWithApproval sets the one-approval rule, opens a merge request, and
// records one first-party approval at the current head — the base state every
// findings-gate test composes its facts onto.
func protectedWithApproval(t *testing.T, service *Service) api.MergeRequest {
	t.Helper()
	ctx := t.Context()
	if _, err := service.SetProtection(ctx, api.ProtectionRequest{
		Context:   principal("tenant-a", "admin-a", "request-protect", "owner"),
		TargetRef: "refs/heads/main", RequiredApprovals: 1,
	}); err != nil {
		t.Fatalf("SetProtection: %v", err)
	}
	mr := openOne(t, service, "request-open")
	reviewed, err := service.Review(ctx, api.ReviewRequest{
		Context:        principal("tenant-a", "actor-b", "request-review", "member"),
		MergeRequestID: mr.ID, Disposition: api.DispositionApprove,
		HeadRevision: mr.HeadRevision, ExpectedVersion: mr.Version,
	})
	if err != nil {
		t.Fatalf("Review: %v", err)
	}
	// The floor (ADR-0085): two non-author approvals make a mergeable base state.
	return approveAs(t, service, reviewed, "actor-c", "request-review-2")
}

// The security gate COMPOSES with the approval gate (SPEC-0029 AC5): one
// decision carries both fact sets, and the findings facts ride the reviewed
// context-key vocabulary, never a caller-supplied value.
func TestMergeGateComposesFindingsFactsWithApprovalFacts(t *testing.T) {
	service, pdp, _, _ := newService(t)
	provider := &fakeFactsProvider{facts: api.FindingsGateFacts{
		Low: 2, Medium: 0, High: 1, Critical: 0,
		HighestAttributedSeverity: "HIGH",
	}}
	service.SetFindingsFacts(provider)
	mr := protectedWithApproval(t, service)

	if _, err := service.Merge(t.Context(), api.MergeRequestCommand{
		Context:        principal("tenant-a", "actor-a", "request-merge", "member"),
		MergeRequestID: mr.ID, ExpectedVersion: mr.Version,
	}); err != nil {
		t.Fatalf("Merge: %v", err)
	}
	if provider.calls != 1 {
		t.Fatalf("facts assembled %d times, want exactly one per merge decision", provider.calls)
	}
	if provider.last.tenant != "tenant-a" || provider.last.repository != "repo-a" ||
		provider.last.actor != "actor-a" || provider.last.mergeRequest != mr.ID {
		t.Fatalf("facts assembled under %+v, want the merge's own identity", provider.last)
	}
	req, ok := pdp.lastFor("merge_request.merge")
	if !ok {
		t.Fatal("no merge decision was asked")
	}
	// The SPEC-0019 facts stand, unchanged — now carrying the floor's two.
	if req.Context["valid_approvals"] != "2" || req.Context["required_approvals"] != "1" {
		t.Fatalf("approval facts = %v, want the composed SPEC-0019 facts", req.Context)
	}
	// The findings facts join them under the reviewed vocabulary.
	want := map[string]string{
		api.ContextKeyFindingsGate:            "true",
		api.ContextKeyFindingsHighestSeverity: "HIGH",
		api.ContextKeyFindingsLow:             "2",
		api.ContextKeyFindingsMedium:          "0",
		api.ContextKeyFindingsHigh:            "1",
		api.ContextKeyFindingsCritical:        "0",
	}
	for key, value := range want {
		if req.Context[key] != value {
			t.Fatalf("context[%q] = %q, want %q (full context %v)", key, req.Context[key], value, req.Context)
		}
	}
	if _, present := req.Context[api.ContextKeyReliedUponTriageIDs]; present {
		t.Fatalf("no exemption was applied, yet relied-upon triage was presented: %v", req.Context)
	}
}

// Regression (caught live by the north-star Stage D proof): the facts assemble
// under the merge's verified actor — identity AND ROLES. The merge-base read
// the comparison needs is a PDP-guarded repo.read on storage's side; the
// role-less shape denied every read live and failed every merge closed. The
// provider must therefore receive the merge context's verified roles, exactly
// as the decision receives them.
func TestMergeGatePresentsTheMergingActorsRolesToTheFactsProvider(t *testing.T) {
	service, _, _, _ := newService(t)
	provider := &fakeFactsProvider{facts: api.FindingsGateFacts{HighestAttributedSeverity: "NONE"}}
	service.SetFindingsFacts(provider)
	mr := protectedWithApproval(t, service)

	if _, err := service.Merge(t.Context(), api.MergeRequestCommand{
		Context:        principal("tenant-a", "actor-a", "request-merge", "member"),
		MergeRequestID: mr.ID, ExpectedVersion: mr.Version,
	}); err != nil {
		t.Fatalf("Merge: %v", err)
	}
	if provider.calls != 1 {
		t.Fatalf("facts assembled %d times, want exactly one", provider.calls)
	}
	if len(provider.last.roles) != 1 || provider.last.roles[0] != "member" { //arch:allow-inline-authz test asserts role PLUMBING to the facts provider, not an access decision
		t.Fatalf("facts assembled under roles %v, want the merge context's verified roles [member] — "+
			"a role-less assembly is the north-star Stage D defect", provider.last.roles)
	}
}

// An exemption the facts carry is presented as the relied-upon triage IDs, so
// the decision records WHICH triage records it relied on (SPEC-0029 AC4).
func TestMergeGatePresentsReliedUponTriageIDs(t *testing.T) {
	service, pdp, _, _ := newService(t)
	service.SetFindingsFacts(&fakeFactsProvider{facts: api.FindingsGateFacts{
		High: 1, HighestAttributedSeverity: "HIGH",
		ReliedUponTriageIDs: []string{"triage-2", "triage-1"},
	}})
	mr := protectedWithApproval(t, service)

	if _, err := service.Merge(t.Context(), api.MergeRequestCommand{
		Context:        principal("tenant-a", "actor-a", "request-merge", "member"),
		MergeRequestID: mr.ID, ExpectedVersion: mr.Version,
	}); err != nil {
		t.Fatalf("Merge: %v", err)
	}
	req, _ := pdp.lastFor("merge_request.merge")
	if got := req.Context[api.ContextKeyReliedUponTriageIDs]; got != "triage-2,triage-1" {
		t.Fatalf("relied_upon_triage_ids = %q, want the facts' IDs in their assembly order", got)
	}
}

// A fact that cannot be assembled FAILS CLOSED (SPEC-0029 AC9): the gate is
// engaged with no facts — the shape the reviewed policy denies — never a
// fail-open default and never a disengaged gate.
func TestMergeGateFailsClosedWhenFactsDoNotAssemble(t *testing.T) {
	service, pdp, _, _ := newService(t)
	service.SetFindingsFacts(&fakeFactsProvider{err: errors.New("facts unavailable")})
	mr := protectedWithApproval(t, service)

	if _, err := service.Merge(t.Context(), api.MergeRequestCommand{
		Context:        principal("tenant-a", "actor-a", "request-merge", "member"),
		MergeRequestID: mr.ID, ExpectedVersion: mr.Version,
	}); err != nil {
		t.Fatalf("Merge: %v", err)
	}
	req, _ := pdp.lastFor("merge_request.merge")
	if req.Context[api.ContextKeyFindingsGate] != "true" {
		t.Fatalf("a failed assembly must still engage the gate: %v", req.Context)
	}
	if _, present := req.Context[api.ContextKeyFindingsHighestSeverity]; present {
		t.Fatalf("a failed assembly must present NO facts: %v", req.Context)
	}
}

// No provider wired: the SPEC-0019 gate stands alone, exactly as before
// T-0025 — the security gate applies only when engaged.
func TestMergeGateDisengagedWithoutAFactsProvider(t *testing.T) {
	service, pdp, _, _ := newService(t)
	mr := protectedWithApproval(t, service)

	if _, err := service.Merge(t.Context(), api.MergeRequestCommand{
		Context:        principal("tenant-a", "actor-a", "request-merge", "member"),
		MergeRequestID: mr.ID, ExpectedVersion: mr.Version,
	}); err != nil {
		t.Fatalf("Merge: %v", err)
	}
	req, _ := pdp.lastFor("merge_request.merge")
	if _, present := req.Context[api.ContextKeyFindingsGate]; present {
		t.Fatalf("an unwired provider must leave the gate disengaged: %v", req.Context)
	}
}

// approvingHistoryImporter imports one merge request whose approval names the
// first-party merge request under review: history the platform did not
// witness, as ATTESTED_IMPORT (ADR-0029).
type approvingHistoryImporter struct {
	records        api.ImportedRecordStore
	mergeRequestID string
}

func (a approvingHistoryImporter) ImportHistory(ctx context.Context, command ImportHistoryCommand) (HistoryResult, error) {
	err := a.records.PutImport(ctx, command.ImportID, []api.ImportedMergeRequest{{
		MergeRequestID: "source-mr-9",
		State:          "merged",
		Approvals: []api.ImportedApproval{{
			ApprovalID:     "approval-1",
			MergeRequestID: a.mergeRequestID,
			DeclaredActor:  "imported-approver",
			DeclaredAt:     time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC),
			Provenance:     api.Provenance{Class: api.AttestImported, ImportID: command.ImportID, SourceSystem: "github"},
		}},
		Provenance: api.Provenance{Class: api.AttestImported, ImportID: command.ImportID, SourceSystem: "github"},
	}})
	return HistoryResult{Counts: map[string]int64{"merge_requests": 1, "approvals": 1}}, err
}

// An imported approval NEVER satisfies the approval requirement (ADR-0029 §4,
// SPEC-0029 AC6): a merge whose only approval is imported presents
// valid_approvals=0 and is denied. This is the structural proof — the
// ATTESTED_IMPORT record exists in this context's own import store, named to
// the very merge request, and still no context fact makes it count.
func TestMergeWhoseOnlyApprovalIsImportedIsDenied(t *testing.T) {
	service, pdp, _, got := newService(t)
	ctx := t.Context()
	if _, err := service.SetProtection(ctx, api.ProtectionRequest{
		Context:   principal("tenant-a", "admin-a", "request-protect", "owner"),
		TargetRef: "refs/heads/main", RequiredApprovals: 1,
	}); err != nil {
		t.Fatalf("SetProtection: %v", err)
	}
	mr := openOne(t, service, "request-open")

	// The import completes on this plane's bus with an approval naming the
	// first-party merge request.
	records := NewMemoryRecordStore()
	imports := NewImportService(newStubImportStore(), records,
		&stubGitImporter{moved: []RefUpdate{{Ref: "refs/heads/main", Revision: "abc123"}}},
		approvingHistoryImporter{records: records, mergeRequestID: mr.ID},
		stubPDP{}, got.events)
	imp, err := imports.Create(ctx, importRequest())
	if err != nil || imp.State != api.ImportComplete {
		t.Fatalf("import did not complete: %+v, %v", imp, err)
	}
	stored, err := records.ListImport(ctx, imp.ID)
	if err != nil || len(stored) != 1 || len(stored[0].Approvals) != 1 {
		t.Fatalf("the imported approval is not in this context's record store: %+v, %v", stored, err)
	}

	if _, err := service.Merge(ctx, api.MergeRequestCommand{
		Context:        principal("tenant-a", "actor-a", "request-merge", "member"),
		MergeRequestID: mr.ID, ExpectedVersion: mr.Version,
	}); !errors.Is(err, api.ErrDenied) {
		t.Fatalf("a merge whose only approval is imported must be denied, got %v", err)
	}
	req, ok := pdp.lastFor("merge_request.merge")
	if !ok {
		t.Fatal("no merge decision was asked")
	}
	if req.Context["valid_approvals"] != "0" || req.Context["required_approvals"] != "1" {
		t.Fatalf("an imported approval must present valid_approvals=0: %v", req.Context)
	}
}
