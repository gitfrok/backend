package app

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/gitfrok/backend/modules/codereview/api"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
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
	// The merge rule is the one the PDP evaluates from server-derived counts.
	if req.Action == "merge_request.merge" {
		valid, _ := strconv.Atoi(req.Context["valid_approvals"])
		required, _ := strconv.Atoi(req.Context["required_approvals"])
		if valid < required {
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
	moves []string
	err   error
}

func (r *recordingRefs) MoveRef(_ context.Context, tenantID, repositoryID, targetRef, revision string) error {
	if r.err != nil {
		return r.err
	}
	r.moves = append(r.moves, tenantID+"/"+repositoryID+"/"+targetRef+"@"+revision)
	return nil
}

type collector struct {
	approvals []audit.MergeRequestApproved
	merges    []audit.MergeRequestMerged
	opened    []api.MergeRequestOpened
	reviews   []api.ReviewSubmitted
	merged    []api.MergeRequestMerged
	protected []api.BranchProtectionChanged
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
	return service, pdp, refs, got
}

func principal(tenant, actor, request string, roles ...string) api.Context {
	return api.Context{TenantID: tenant, RepositoryID: "repo-a", ActorID: actor, RequestID: request, ActorRoles: roles}
}

func openOne(t *testing.T, s *Service, requestID string) api.MergeRequest {
	t.Helper()
	mr, err := s.Open(context.Background(), api.OpenRequest{
		Context:   principal("tenant-a", "actor-a", requestID, "member"),
		SourceRef: "refs/heads/feature", TargetRef: "refs/heads/main",
		Title: "Add a thing", HeadRevision: "sha-head",
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return mr
}

// AC1: open, review, and merge at the current expected version; a replayed
// request ID is idempotent and a stale version changes nothing.
func TestOpenReviewMergeAtTheExpectedVersion(t *testing.T) {
	service, _, refs, got := newService(t)
	ctx := context.Background()

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
	ctx := context.Background()
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
	ctx := context.Background()
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
	ctx := context.Background()

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
	ctx := context.Background()
	mr := openOne(t, service, "request-open")

	reviewed, err := service.Review(ctx, api.ReviewRequest{
		Context:        principal("tenant-a", "actor-b", "request-review", "member"),
		MergeRequestID: mr.ID, Disposition: api.DispositionApprove,
		HeadRevision: "sha-old", ExpectedVersion: mr.Version,
	})
	if err != nil {
		t.Fatalf("Review: %v", err)
	}
	if _, err := service.Merge(ctx, api.MergeRequestCommand{
		Context:        principal("tenant-a", "actor-a", "request-merge", "member"),
		MergeRequestID: mr.ID, ExpectedVersion: reviewed.Version,
	}); err != nil {
		t.Fatalf("Merge: %v", err)
	}
	request, _ := pdp.lastFor("merge_request.merge")
	if request.Context["valid_approvals"] != "0" {
		t.Fatalf("valid_approvals = %q, want an approval from another head to count for nothing", request.Context["valid_approvals"])
	}
}

func TestALaterReviewSupersedesTheSameActorsEarlierOne(t *testing.T) {
	service, pdp, _, _ := newService(t)
	ctx := context.Background()
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

	if _, err := service.Merge(ctx, api.MergeRequestCommand{
		Context:        principal("tenant-a", "actor-a", "request-merge", "member"),
		MergeRequestID: mr.ID, ExpectedVersion: reviewed.Version,
	}); err != nil {
		t.Fatalf("Merge: %v", err)
	}
	request, _ := pdp.lastFor("merge_request.merge")
	if request.Context["valid_approvals"] != "0" {
		t.Fatalf("valid_approvals = %q, want the superseded approval not to count", request.Context["valid_approvals"])
	}
}

// AC5: every authorization-sensitive command asks the PDP, with roles taken from
// the verified context rather than from anything the caller could assert.
func TestEveryMutationAsksThePDP(t *testing.T) {
	service, pdp, _, _ := newService(t)
	ctx := context.Background()

	mr := openOne(t, service, "request-open")
	if _, err := service.Review(ctx, api.ReviewRequest{
		Context:        principal("tenant-a", "actor-b", "request-review", "member"),
		MergeRequestID: mr.ID, Disposition: api.DispositionApprove,
		HeadRevision: "sha-head", ExpectedVersion: mr.Version,
	}); err != nil {
		t.Fatalf("Review: %v", err)
	}
	if _, err := service.SetProtection(ctx, api.ProtectionRequest{
		Context:   principal("tenant-a", "admin-a", "request-protect", "owner"),
		TargetRef: "refs/heads/main", RequiredApprovals: 0,
	}); err != nil {
		t.Fatalf("SetProtection: %v", err)
	}
	if _, err := service.Merge(ctx, api.MergeRequestCommand{
		Context:        principal("tenant-a", "actor-a", "request-merge", "member"),
		MergeRequestID: mr.ID, ExpectedVersion: mr.Version + 1,
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
	ctx := context.Background()
	pdp.deny["merge_request.open"] = true

	if _, err := service.Open(ctx, api.OpenRequest{
		Context:   principal("tenant-a", "actor-a", "request-open", "reader"),
		SourceRef: "refs/heads/feature", TargetRef: "refs/heads/main", HeadRevision: "sha-head",
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
	ctx := context.Background()
	mr := openOne(t, service, "request-open")

	reviewed, err := service.Review(ctx, api.ReviewRequest{
		Context:        principal("tenant-a", "actor-b", "request-review", "member"),
		MergeRequestID: mr.ID, Disposition: api.DispositionApprove,
		HeadRevision: "sha-head", ExpectedVersion: mr.Version,
	})
	if err != nil {
		t.Fatalf("Review: %v", err)
	}
	if _, err := service.Merge(ctx, api.MergeRequestCommand{
		Context:        principal("tenant-a", "actor-a", "request-merge", "member"),
		MergeRequestID: mr.ID, ExpectedVersion: reviewed.Version,
	}); err != nil {
		t.Fatalf("Merge: %v", err)
	}

	if len(got.approvals) != 1 {
		t.Fatalf("approval audit records = %d, want exactly 1", len(got.approvals))
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
	if _, err := service.Review(context.Background(), api.ReviewRequest{
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
	ctx := context.Background()
	mr := openOne(t, service, "request-open")
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
	ctx := context.Background()

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
	ctx := context.Background()
	if _, err := service.SetProtection(ctx, api.ProtectionRequest{
		Context:   principal("tenant-a", "admin-a", "request-protect", "owner"),
		TargetRef: "refs/heads/main", RequiredApprovals: 0,
	}); err != nil {
		t.Fatalf("SetProtection: %v", err)
	}
	mr := openOne(t, service, "request-open")
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
	ctx := context.Background()
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
