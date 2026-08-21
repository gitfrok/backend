package app_test

import (
	"context"
	"slices"
	"testing"
	"time"

	codereviewapi "github.com/gitfrok/backend/modules/codereview/api"
	"github.com/gitfrok/backend/modules/notifications/api"
	"github.com/gitfrok/backend/modules/notifications/internal/adapters/memory"
	notificationsapp "github.com/gitfrok/backend/modules/notifications/internal/app"
	securityapi "github.com/gitfrok/backend/modules/security/api"
	"github.com/gitfrok/backend/platform/bus"
)

// The handlers are pure derivation over events; every test here runs against
// the same in-memory store whose durable twin grants identical scoping.

func newService(dir *memory.Directory) (*notificationsapp.Service, *memory.Store) {
	store := memory.New()
	return notificationsapp.New(store, store, dir), store
}

var at = time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)

func opened(eventID string) codereviewapi.MergeRequestOpened {
	return codereviewapi.MergeRequestOpened{
		EventID: eventID, MergeRequestID: "mr-1", TenantID: "t1", RepositoryID: "repo-1",
		SourceRef: "refs/heads/feature", TargetRef: "refs/heads/main",
		CreatorID: "author", OccurredAt: at,
	}
}

// AC4 first — everything else leans on it. Replaying the same event makes no
// second row.
func TestAReplayedEventMakesOneRow(t *testing.T) {
	svc, store := newService(memory.NewDirectory())
	ctx := context.Background()

	if err := svc.OnMergeRequestMerged(ctx, codereviewapi.MergeRequestMerged{
		EventID: "evt-9", MergeRequestID: "mr-1", TenantID: "t1", RepositoryID: "repo-1",
		ActorID: "merger", CreatorID: "author", CountedApprovalActors: []string{"rev-a", "rev-b"},
		OccurredAt: at,
	}); err != nil {
		t.Fatal(err)
	}
	if err := svc.OnMergeRequestMerged(ctx, codereviewapi.MergeRequestMerged{
		EventID: "evt-9", MergeRequestID: "mr-1", TenantID: "t1", RepositoryID: "repo-1",
		ActorID: "merger", CreatorID: "author", CountedApprovalActors: []string{"rev-a", "rev-b"},
		OccurredAt: at,
	}); err != nil {
		t.Fatal(err)
	}

	page, err := store.List(ctx, "t1", "author", 100, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Notifications) != 1 {
		t.Fatalf("author rows = %d, want 1 (exactly-once rows)", len(page.Notifications))
	}
	page, err = store.List(ctx, "t1", "rev-a", 100, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Notifications) != 1 {
		t.Fatalf("rev-a rows = %d, want 1", len(page.Notifications))
	}
}

// AC2 — a review notifies the author, never the reviewer; a self-review
// notifies nobody.
func TestAReviewNotifiesTheAuthorNeverTheReviewer(t *testing.T) {
	svc, _ := newService(memory.NewDirectory())
	ctx := context.Background()

	review := func(actor string) error {
		return svc.OnReviewSubmitted(ctx, codereviewapi.ReviewSubmitted{
			EventID: "evt-r-" + actor, MergeRequestID: "mr-1", TenantID: "t1", RepositoryID: "repo-1",
			ActorID: actor, Disposition: codereviewapi.DispositionApprove, HeadRevision: "abc",
			OccurredAt: at, CreatorID: "author",
		})
	}
	if err := review("reviewer"); err != nil {
		t.Fatal(err)
	}
	if err := review("author"); err != nil { // self-review: nobody hears about it
		t.Fatal(err)
	}

	svcPage := func(recipient string) api.Page {
		p, err := svc.List(ctx, api.ListRequest{Context: api.Context{TenantID: "t1", ActorID: recipient}})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	if got := svcPage("author"); len(got.Notifications) != 1 || got.Notifications[0].Kind != api.KindReviewSubmitted {
		t.Fatalf("author notifications = %+v, want exactly one review notification", got.Notifications)
	}
	if got := svcPage("reviewer"); len(got.Notifications) != 0 {
		t.Fatalf("reviewer notifications = %+v, want none (never the reviewer)", got.Notifications)
	}
}

// AC2 — a merge notifies author + everyone whose approval counted, minus the
// acting merger; names come from the gate snapshot on the event.
func TestAMergeNotifiesAuthorAndCountedApprovers(t *testing.T) {
	svc, _ := newService(memory.NewDirectory())
	ctx := context.Background()
	if err := svc.OnMergeRequestMerged(ctx, codereviewapi.MergeRequestMerged{
		EventID: "evt-m", MergeRequestID: "mr-1", TenantID: "t1", RepositoryID: "repo-1",
		ActorID: "merger", TargetRef: "refs/heads/main", HeadRevision: "def",
		CreatorID: "author", CountedApprovalActors: []string{"rev-a", "rev-b", "merger"},
		OccurredAt: at,
	}); err != nil {
		t.Fatal(err)
	}
	for recipient, want := range map[string]bool{"author": true, "rev-a": true, "rev-b": true, "merger": false} {
		page, err := svc.List(ctx, api.ListRequest{Context: api.Context{TenantID: "t1", ActorID: recipient}})
		if err != nil {
			t.Fatal(err)
		}
		got := len(page.Notifications) > 0
		if got != want {
			t.Fatalf("%s notified = %v, want %v", recipient, got, want)
		}
	}
}

// AC3 — findings attributed notify the MR's author once per batch, never per
// finding. One attribution event IS one batch.
func TestAFindingsBatchNotifiesTheAuthorOnce(t *testing.T) {
	dir := memory.NewDirectory()
	svc, store := newService(dir)
	ctx := context.Background()
	if err := store.PutCreator(ctx, "t1", "repo-1", "mr-1", "author"); err != nil {
		t.Fatal(err)
	}
	if err := svc.OnFindingsAttributed(ctx, securityapi.FindingsAttributed{
		EventID: "evt-f", TenantID: "t1", RepositoryID: "repo-1", MergeRequestID: "mr-1",
		HeadRevision: "abc", AttributedHigh: 7, AttributedCritical: 1, OccurredAt: at,
	}); err != nil {
		t.Fatal(err)
	}
	page, err := svc.List(ctx, api.ListRequest{Context: api.Context{TenantID: "t1", ActorID: "author"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Notifications) != 1 || page.Notifications[0].Kind != api.KindFindingsAttributed {
		t.Fatalf("author notifications = %+v, want exactly one findings notification", page.Notifications)
	}
}

// AC1/ready — reviewers-to-be are the tenant's review-capable members minus
// the actor, resolved server-side from identity's membership view.
func TestAReadyNotifiesReviewCapableMembersMinusActor(t *testing.T) {
	dir := memory.NewDirectory()
	dir.Put("t1", "owner-1", "owner")
	dir.Put("t1", "member-1", "member")
	dir.Put("t1", "reader-1", "reader") // cannot review, never notified
	dir.Put("t2", "outsider", "owner")  // another tenant, absent entirely

	svc, _ := newService(dir)
	ctx := context.Background()
	if err := svc.OnMergeRequestReady(ctx, codereviewapi.MergeRequestReady{
		EventID: "evt-y", MergeRequestID: "mr-1", TenantID: "t1", RepositoryID: "repo-1",
		ActorID: "member-1", HeadRevision: "abc", TargetRef: "refs/heads/main", OccurredAt: at,
	}); err != nil {
		t.Fatal(err)
	}
	for recipient, want := range map[string]bool{
		"owner-1": true, "member-1": false, // the actor is excluded
		"reader-1": false, "outsider": false,
	} {
		page, err := svc.List(ctx, api.ListRequest{Context: api.Context{TenantID: "t1", ActorID: recipient}})
		if err != nil && recipient == "outsider" {
			continue // cross-tenant reads are refused coarsely; absence holds either way
		}
		if err != nil {
			t.Fatal(err)
		}
		if got := len(page.Notifications) > 0; got != want {
			t.Fatalf("%s notified = %v, want %v", recipient, got, want)
		}
	}
}

// AC5 — another tenant's notifications are absent from every read.
func TestAnotherTenantsRowsAreAbsent(t *testing.T) {
	svc, _ := newService(memory.NewDirectory())
	ctx := context.Background()
	if err := svc.OnMergeRequestMerged(ctx, codereviewapi.MergeRequestMerged{
		EventID: "evt-x", MergeRequestID: "mr-1", TenantID: "t1", RepositoryID: "repo-1",
		ActorID: "m", CreatorID: "author", OccurredAt: at,
	}); err != nil {
		t.Fatal(err)
	}
	page, err := svc.List(ctx, api.ListRequest{Context: api.Context{TenantID: "other", ActorID: "author"}})
	if err != nil {
		t.Fatal(err) // same actor name, different tenant: still nothing
	}
	if len(page.Notifications) != 0 {
		t.Fatalf("cross-tenant rows leaked: %+v", page.Notifications)
	}
}

// AC6 — marking one marks one, and the count tracks exactly.
func TestMarkReadMarksExactlyOne(t *testing.T) {
	svc, _ := newService(memory.NewDirectory())
	ctx := context.Background()
	for _, n := range []string{"one", "two"} {
		if err := svc.OnMergeRequestMerged(ctx, codereviewapi.MergeRequestMerged{
			EventID: "evt-" + n, MergeRequestID: "mr-1", TenantID: "t1", RepositoryID: "repo-1",
			ActorID: "m", CreatorID: "author", CountedApprovalActors: []string{"rev-a"}, OccurredAt: at,
		}); err != nil {
			t.Fatal(err)
		}
	}
	c := api.Context{TenantID: "t1", ActorID: "rev-a"}
	if n, err := svc.UnreadCount(ctx, c); err != nil || n != 2 {
		t.Fatalf("unread = %d, %v; want 2 (two merges counted rev-a)", n, err)
	}
	page, err := svc.List(ctx, api.ListRequest{Context: c})
	if err != nil {
		t.Fatal(err)
	}
	marked, err := svc.MarkRead(ctx, c, page.Notifications[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if !marked.Read {
		t.Fatal("marked row reports unread")
	}
	if n, err := svc.UnreadCount(ctx, c); err != nil || n != 1 {
		t.Fatalf("unread after mark = %d, %v; want 1", n, err)
	}
	// Marking again is idempotent, not a second state change.
	if _, err := svc.MarkRead(ctx, c, page.Notifications[0].ID); err != nil {
		t.Fatal(err)
	}
	if n, _ := svc.UnreadCount(ctx, c); n != 1 {
		t.Fatalf("unread after re-mark = %d, want 1", n)
	}
	// Another recipient's row is not this caller's to mark, even when the
	// caller holds a row with the same event underneath it.
	cAuthor := api.Context{TenantID: "t1", ActorID: "author"}
	if n, _ := svc.UnreadCount(ctx, cAuthor); n != 2 {
		t.Fatalf("author unread = %d, want 2", n)
	}
}

// ADR-0086's named risk, pinned by test: every subscribed event type names its
// recipients, and no known producer event type is silently uncovered.
func TestCoverageTableAccountsForEveryKnownEvent(t *testing.T) {
	known := map[string]bool{
		codereviewapi.EventMergeRequestOpened:      false,
		codereviewapi.EventMergeRequestUpdated:     false,
		codereviewapi.EventMergeRequestReady:       false,
		codereviewapi.EventReviewSubmitted:         false,
		codereviewapi.EventMergeRequestMerged:      false,
		codereviewapi.EventBranchProtectionChanged: false,
		securityapi.EventScanIngested:              false,
		securityapi.EventFindingsAttributed:        false,
	}
	for name := range notificationsapp.Coverage() {
		if _, ok := known[name]; !ok {
			t.Errorf("coverage table names %q, which no producer emits", name)
		}
	}
	for name := range known {
		if _, covered := notificationsapp.Coverage()[name]; !covered {
			t.Errorf("event %q is emitted today but absent from the coverage table", name)
		}
	}
}

// The subscriber wiring registers a handler for every rule the table claims.
func TestSubscribeRegistersEveryCoveredEvent(t *testing.T) {
	b := newRecordingBus()
	svc, _ := newService(memory.NewDirectory())
	notificationsapp.Subscribe(b, svc)
	for name, rule := range notificationsapp.Coverage() {
		if !rule.Notifies {
			continue // a deliberate no-rule entry subscribes nothing
		}
		if !slices.Contains(b.subscribed, name) {
			t.Errorf("coverage table claims %q notifies %q but Subscribe registered no handler", name, rule.Recipients)
		}
	}
	if got, want := len(b.subscribed), 5; got != want {
		t.Fatalf("Subscribe registered %d handlers, want %d", got, want)
	}
}

type recordingBus struct {
	subscribed []string
}

func newRecordingBus() *recordingBus { return &recordingBus{} }

func (b *recordingBus) Publish(_ context.Context, _ bus.Event) error { return nil }
func (b *recordingBus) Subscribe(name string, _ bus.Handler) {
	b.subscribed = append(b.subscribed, name)
}
