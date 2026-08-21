package app

import (
	"errors"
	"testing"
	"time"

	"github.com/gitfrok/backend/modules/codereview/api"
	repoapi "github.com/gitfrok/backend/modules/repository/api"
	"github.com/gitfrok/backend/platform/bus"
)

// ADR-0087 / SPEC-0064 and ADR-0085 / SPEC-0062 AC3, asserted at the service
// edge over the memory store: the author's approval never counts toward the
// gate, and a draft is quiet until it is marked ready.

// SPEC-0062 AC3: the author's own approval is recorded but never counted — the
// fact the PDP is asked with still reads zero.
func TestTheAuthorsApprovalNeverCounts(t *testing.T) {
	service, pdp, _, _ := newService(t)
	ctx := t.Context()
	mr := openOne(t, service, "request-open")

	selfReviewed, err := service.Review(ctx, api.ReviewRequest{
		Context:        principal("tenant-a", "actor-a", "request-self-review", "member"),
		MergeRequestID: mr.ID, Disposition: api.DispositionApprove,
		HeadRevision: mr.HeadRevision, ExpectedVersion: mr.Version,
	})
	if err != nil {
		t.Fatalf("the author's own Review was refused: %v", err)
	}

	if _, err := service.Merge(ctx, api.MergeRequestCommand{
		Context:        principal("tenant-a", "actor-a", "request-merge", "member"),
		MergeRequestID: mr.ID, ExpectedVersion: mr.Version + 1,
	}); !errors.Is(err, api.ErrDenied) {
		t.Fatal("a merge whose only approval is the author's own was allowed")
	}
	request, ok := pdp.lastFor("merge_request.merge")
	if !ok {
		t.Fatal("the merge was refused without asking the PDP")
	}
	if request.Context["valid_approvals"] != "0" {
		t.Fatalf("valid_approvals = %q with only the author's approval, want 0", request.Context["valid_approvals"])
	}

	// Two non-author approvals satisfy the floor even though the author also
	// approved: three recorded reviews, two of them counting.
	mr = approveAs(t, service, selfReviewed, "actor-b", "request-review")
	mr = approveAs(t, service, mr, "actor-c", "request-review-2")
	if _, err := service.Merge(ctx, api.MergeRequestCommand{
		Context:        principal("tenant-a", "actor-a", "request-merge", "member"),
		MergeRequestID: mr.ID, ExpectedVersion: mr.Version,
	}); err != nil {
		t.Fatalf("Merge with the floor satisfied beside a self-approval: %v", err)
	}
}

func openDraft(t *testing.T, s *Service, requestID string) api.MergeRequest {
	t.Helper()
	draft, err := s.Open(t.Context(), api.OpenRequest{
		Context:   principal("tenant-a", "actor-a", requestID, "member"),
		SourceRef: "refs/heads/feature", TargetRef: "refs/heads/main",
		Title: "WIP: the thing", Draft: true,
	})
	if err != nil {
		t.Fatalf("Open draft: %v", err)
	}
	return draft
}

// SPEC-0064 AC1: opening as a draft yields DRAFT and announces nothing; the
// default yields OPEN exactly as before.
func TestADraftOpensQuiet(t *testing.T) {
	service, _, refs, got := newService(t)

	draft := openDraft(t, service, "request-draft")
	if draft.State != api.StateDraft {
		t.Fatalf("state = %s, want DRAFT", draft.State)
	}
	if len(got.opened) != 0 {
		t.Fatalf("a draft announced itself %d times", len(got.opened))
	}

	open := openOne(t, service, "request-open")
	if open.State != api.StateOpen {
		t.Fatalf("the default open changed: state=%s", open.State)
	}
	if len(got.opened) != 1 {
		t.Fatalf("an open merge request announced %d times, want 1", len(got.opened))
	}
	if refs.moves != nil {
		t.Fatalf("opening moved something: %v", refs.moves)
	}
}

// SPEC-0064 AC2 + AC3: a draft cannot merge; ready is its one door out, under
// its own version bump, refusing every other state and a stale version.
func TestReadyIsTheDraftsOnlyDoorOut(t *testing.T) {
	service, _, refs, got := newService(t)
	draft := openDraft(t, service, "request-draft")

	if _, err := service.Merge(t.Context(), api.MergeRequestCommand{
		Context:        principal("tenant-a", "actor-a", "request-merge", "member"),
		MergeRequestID: draft.ID, ExpectedVersion: draft.Version,
	}); !errors.Is(err, api.ErrDenied) {
		t.Fatal("a draft was merged")
	}
	if len(refs.moves) != 0 {
		t.Fatalf("merging a draft moved a ref: %v", refs.moves)
	}

	if _, err := service.MarkReady(t.Context(), api.ReadyRequest{
		Context:        principal("tenant-a", "actor-a", "request-ready-stale", "member"),
		MergeRequestID: draft.ID, ExpectedVersion: draft.Version + 7,
	}); !errors.Is(err, api.ErrVersionConflict) {
		t.Fatalf("ready at a stale version: %v, want the version conflict", err)
	}

	ready, err := service.MarkReady(t.Context(), api.ReadyRequest{
		Context:        principal("tenant-a", "actor-a", "request-ready", "member"),
		MergeRequestID: draft.ID, ExpectedVersion: draft.Version,
	})
	if err != nil {
		t.Fatalf("MarkReady: %v", err)
	}
	if ready.State != api.StateOpen || ready.Version != draft.Version+1 {
		t.Fatalf("ready = state %s version %d, want OPEN at one bump", ready.State, ready.Version)
	}
	// Readiness re-reads both revisions from what Repository/Git announced.
	if ready.HeadRevision != "sha-head" || ready.TargetRevision != "sha-target" {
		t.Fatalf("revisions after ready = %q/%q", ready.HeadRevision, ready.TargetRevision)
	}

	if _, err := service.MarkReady(t.Context(), api.ReadyRequest{
		Context:        principal("tenant-a", "actor-a", "request-ready-again", "member"),
		MergeRequestID: draft.ID, ExpectedVersion: ready.Version,
	}); !errors.Is(err, api.ErrDenied) {
		t.Fatal("marking an OPEN merge request ready was accepted")
	}
	if len(got.opened) != 0 {
		t.Fatalf("readiness announced an open event: %+v", got.opened)
	}
}

// SPEC-0064 AC4: while DRAFT a push lands no projection on the merge request;
// after readiness the same push shape projects as for any OPEN request.
func TestADraftReceivesNoProjectionsUntilReady(t *testing.T) {
	service, _, _, got := newService(t)
	events := got.events
	draft := openDraft(t, service, "request-draft")

	if err := events.Publish(t.Context(), repoapi.RefUpdated{
		EventID: "event-move-1", TenantID: "tenant-a", RepoID: "repo-a", Ref: "refs/heads/main",
		OldSha: "sha-target", NewSha: "sha-moved", ActorID: "actor-c",
		OccurredAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	current, err := service.Get(t.Context(), principal("tenant-a", "actor-a", "request-get", "member"), draft.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if current.TargetRevision == "sha-moved" {
		t.Fatal("a push projected onto a draft")
	}

	ready, err := service.MarkReady(t.Context(), api.ReadyRequest{
		Context:        principal("tenant-a", "actor-a", "request-ready", "member"),
		MergeRequestID: draft.ID, ExpectedVersion: current.Version,
	})
	if err != nil {
		t.Fatalf("MarkReady: %v", err)
	}
	if ready.TargetRevision != "sha-moved" {
		t.Fatalf("ready against a moved target read %q, want sha-moved", ready.TargetRevision)
	}

	if err := events.Publish(t.Context(), repoapi.RefUpdated{
		EventID: "event-move-2", TenantID: "tenant-a", RepoID: "repo-a", Ref: "refs/heads/main",
		OldSha: "sha-moved", NewSha: "sha-moved-2", ActorID: "actor-c",
		OccurredAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	final, err := service.Get(t.Context(), principal("tenant-a", "actor-a", "request-get-2", "member"), draft.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if final.TargetRevision != "sha-moved-2" {
		t.Fatalf("after readiness the projection stopped: target = %q", final.TargetRevision)
	}
}

// SPEC-0064 AC5: reviews may be submitted against a draft — early feedback is
// the point — and reviewing does not move the state.
func TestADraftCanBeReviewed(t *testing.T) {
	service, _, _, got := newService(t)
	draft := openDraft(t, service, "request-draft")

	reviewed, err := service.Review(t.Context(), api.ReviewRequest{
		Context:        principal("tenant-a", "actor-b", "request-review", "member"),
		MergeRequestID: draft.ID, Disposition: api.DispositionComment,
		HeadRevision: draft.HeadRevision, ExpectedVersion: draft.Version,
	})
	if err != nil {
		t.Fatalf("Review on a draft: %v", err)
	}
	if reviewed.State != api.StateDraft {
		t.Fatalf("reviewing moved the state to %s", reviewed.State)
	}
	if len(got.reviews) != 1 {
		t.Fatalf("ReviewSubmitted published %d times, want 1", len(got.reviews))
	}
}

var _ = bus.Event(nil)
