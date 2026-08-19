package app

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/gitfrok/backend/modules/codereview/api"
	"github.com/gitfrok/backend/platform/audit"
	"github.com/gitfrok/backend/platform/bus"
)

// SPEC-0059 AC1–AC7: what a reference is, what a repeated act does, which URLs are
// refused, and the fact that nothing here reads the tracker.

// referenceRecords collects the audit records this surface leaves. They travel under
// one event name, so they are sorted by concrete type rather than by subscription.
func referenceRecords(t *testing.T, events bus.Bus) *[]audit.MergeRequestExternalIssue {
	t.Helper()
	records := &[]audit.MergeRequestExternalIssue{}
	events.Subscribe(audit.EventAudit, func(_ context.Context, e bus.Event) error {
		if record, ok := e.(audit.MergeRequestExternalIssue); ok {
			*records = append(*records, record)
		}
		return nil
	})
	return records
}

func linkOne(t *testing.T, s *Service, mrID, tracker, key, issueURL string) (api.MergeRequest, error) {
	t.Helper()
	return s.LinkExternalIssue(t.Context(), api.LinkExternalIssueRequest{
		Context:        principal("tenant-a", "actor-a", "request-link", "member"),
		MergeRequestID: mrID, Tracker: tracker, IssueKey: key, URL: issueURL,
	})
}

// AC1: a reference is a tracker, a key, a URL, and who linked it when.
func TestLinkRecordsTheReference(t *testing.T) {
	service, _, _, got := newService(t)
	records := referenceRecords(t, got.events)
	mr := openOne(t, service, "request-open")

	linked, err := linkOne(t, service, mr.ID, "JIRA", "PLAT-1421", "https://tracker.example.test/browse/PLAT-1421")
	if err != nil {
		t.Fatalf("LinkExternalIssue: %v", err)
	}
	if len(linked.ExternalIssues) != 1 {
		t.Fatalf("want one reference, got %d", len(linked.ExternalIssues))
	}
	reference := linked.ExternalIssues[0]
	if reference.Tracker != "JIRA" || reference.IssueKey != "PLAT-1421" {
		t.Errorf("unexpected reference %+v", reference)
	}
	if reference.LinkedBy != "actor-a" || reference.LinkedAt.IsZero() {
		t.Errorf("the who and the when must be recorded: %+v", reference)
	}
	if linked.Version != mr.Version+1 {
		t.Errorf("a change must move the version: %d then %d", mr.Version, linked.Version)
	}
	if len(*records) != 1 || !(*records)[0].Linked {
		t.Fatalf("want one link record, got %+v", *records)
	}
	// AC6/decision 2: the record names the identifier. The URL is customer-supplied
	// text and does not enter a control record.
	if (*records)[0].IssueKey != "PLAT-1421" || (*records)[0].Tracker != "JIRA" {
		t.Errorf("the record must name the identifier: %+v", (*records)[0])
	}
	if strings.Contains((*records)[0].Action(), "unlink") {
		t.Errorf("a link recorded the unlink action: %q", (*records)[0].Action())
	}
}

// AC6: the merge request changed, so MergeRequestUpdated is published — and there is
// no new domain event, because a reference is inert and nothing else happened.
func TestLinkPublishesTheMergeRequestUpdate(t *testing.T) {
	service, _, _, got := newService(t)
	updates := &[]api.MergeRequestUpdated{}
	bus.SubscribeTyped(got.events, func(_ context.Context, e api.MergeRequestUpdated) error {
		*updates = append(*updates, e)
		return nil
	})
	mr := openOne(t, service, "request-open")
	before := len(*updates)

	if _, err := linkOne(t, service, mr.ID, "JIRA", "PLAT-1", "https://tracker.example.test/PLAT-1"); err != nil {
		t.Fatalf("LinkExternalIssue: %v", err)
	}
	if len(*updates) != before+1 {
		t.Fatalf("want exactly one MergeRequestUpdated, got %d", len(*updates)-before)
	}
}

// AC2: the same reference twice is one reference and one record.
func TestLinkingTheSameIssueTwiceChangesNothing(t *testing.T) {
	service, _, _, got := newService(t)
	records := referenceRecords(t, got.events)
	mr := openOne(t, service, "request-open")

	first, err := linkOne(t, service, mr.ID, "JIRA", "PLAT-1421", "https://tracker.example.test/PLAT-1421")
	if err != nil {
		t.Fatalf("first link: %v", err)
	}
	// A different URL for the same issue does not replace the first: the reference
	// that was recorded is the one a reader already saw.
	second, err := linkOne(t, service, mr.ID, "jira", "PLAT-1421", "https://tracker.example.test/short/1")
	if err != nil {
		t.Fatalf("second link: %v", err)
	}
	if len(second.ExternalIssues) != 1 {
		t.Fatalf("want one reference, got %d", len(second.ExternalIssues))
	}
	if second.ExternalIssues[0].URL != first.ExternalIssues[0].URL {
		t.Errorf("the recorded URL was silently repointed: %q", second.ExternalIssues[0].URL)
	}
	if second.Version != first.Version {
		t.Errorf("a repeated act moved the version: %d then %d", first.Version, second.Version)
	}
	if len(*records) != 1 {
		t.Errorf("want one audit record for two identical links, got %d", len(*records))
	}
}

// AC3: the URL rule. This is a link a person clicks from inside the product.
func TestOnlyAbsoluteHTTPSURLsAreStored(t *testing.T) {
	service, _, _, _ := newService(t)
	mr := openOne(t, service, "request-open")

	for name, hostile := range map[string]string{
		"javascript":  "javascript:alert(1)",
		"data":        "data:text/html,<script>alert(1)</script>",
		"plain http":  "http://tracker.example.test/PLAT-1",
		"relative":    "/browse/PLAT-1",
		"scheme only": "https://",
		"empty":       "",
	} {
		_, err := linkOne(t, service, mr.ID, "JIRA", "PLAT-1", hostile)
		if !errors.Is(err, api.ErrInvalidExternalIssue) {
			t.Errorf("%s: want ErrInvalidExternalIssue, got %v", name, err)
		}
	}
	after, err := service.Get(t.Context(), principal("tenant-a", "actor-a", "request-get", "member"), mr.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(after.ExternalIssues) != 0 {
		t.Errorf("a refused reference was stored: %+v", after.ExternalIssues)
	}
}

// AC3/AC4: a tracker or key that is missing or oversized is refused, and so is a
// reference past the count bound.
func TestTheReferenceFieldsAreBounded(t *testing.T) {
	service, _, _, _ := newService(t)
	mr := openOne(t, service, "request-open")
	url := "https://tracker.example.test/PLAT-1"

	if _, err := linkOne(t, service, mr.ID, "", "PLAT-1", url); !errors.Is(err, api.ErrInvalidExternalIssue) {
		t.Errorf("a reference with no tracker must be refused, got %v", err)
	}
	if _, err := linkOne(t, service, mr.ID, "JIRA", "  ", url); !errors.Is(err, api.ErrInvalidExternalIssue) {
		t.Errorf("a reference with no key must be refused, got %v", err)
	}
	if _, err := linkOne(t, service, mr.ID, strings.Repeat("t", api.MaxTrackerBytes+1), "PLAT-1", url); !errors.Is(err, api.ErrInvalidExternalIssue) {
		t.Errorf("an oversized tracker must be refused, got %v", err)
	}
	if _, err := linkOne(t, service, mr.ID, "JIRA", "PLAT-2", "https://tracker.example.test/"+strings.Repeat("x", api.MaxIssueURLBytes)); !errors.Is(err, api.ErrInvalidExternalIssue) {
		t.Errorf("an oversized URL must be refused, got %v", err)
	}
}

func TestAReferenceListIsBoundedInCount(t *testing.T) {
	service, _, _, _ := newService(t)
	mr := openOne(t, service, "request-open")

	for i := 0; i < api.MaxExternalIssues; i++ {
		if _, err := linkOne(t, service, mr.ID, "JIRA", "PLAT-"+strings.Repeat("1", i+1), "https://tracker.example.test/x"); err != nil {
			t.Fatalf("link %d: %v", i, err)
		}
	}
	if _, err := linkOne(t, service, mr.ID, "JIRA", "ONE-MORE", "https://tracker.example.test/x"); !errors.Is(err, api.ErrTooManyExternalIssues) {
		t.Fatalf("want ErrTooManyExternalIssues, got %v", err)
	}
}

// AC5: both acts are the link action, and a refusal is coarse.
func TestBothActsAreTheLinkActionAndRefusalIsCoarse(t *testing.T) {
	service, pdp, _, _ := newService(t)
	mr := openOne(t, service, "request-open")

	if _, err := linkOne(t, service, mr.ID, "JIRA", "PLAT-1", "https://tracker.example.test/PLAT-1"); err != nil {
		t.Fatalf("LinkExternalIssue: %v", err)
	}
	asked := false
	for _, req := range pdp.requests {
		if req.Action == "merge_request.external_issue.link" {
			asked = true
			if req.Resource.Type != "merge_request" || req.Resource.ID != mr.ID {
				t.Errorf("the action was asked about %+v", req.Resource)
			}
		}
	}
	if !asked {
		t.Fatal("the link action was never asked of the PDP")
	}

	pdp.deny["merge_request.external_issue.link"] = true
	_, err := linkOne(t, service, mr.ID, "JIRA", "PLAT-2", "https://tracker.example.test/PLAT-2")
	if !errors.Is(err, api.ErrDenied) {
		t.Fatalf("want the coarse refusal, got %v", err)
	}
	_, err = service.UnlinkExternalIssue(t.Context(), api.UnlinkExternalIssueRequest{
		Context:        principal("tenant-a", "actor-a", "request-unlink", "member"),
		MergeRequestID: mr.ID, Tracker: "JIRA", IssueKey: "PLAT-1",
	})
	if !errors.Is(err, api.ErrDenied) {
		t.Fatalf("unlink must ask the same action: %v", err)
	}
}

// AC1/AC2: unlink removes by identity, and removing what is not there changes
// nothing and records nothing.
func TestUnlinkRemovesByIdentity(t *testing.T) {
	service, _, _, got := newService(t)
	records := referenceRecords(t, got.events)
	mr := openOne(t, service, "request-open")

	if _, err := linkOne(t, service, mr.ID, "JIRA", "PLAT-1", "https://tracker.example.test/PLAT-1"); err != nil {
		t.Fatalf("link: %v", err)
	}
	if _, err := linkOne(t, service, mr.ID, "Linear", "ENG-9", "https://linear.example.test/ENG-9"); err != nil {
		t.Fatalf("link: %v", err)
	}

	after, err := service.UnlinkExternalIssue(t.Context(), api.UnlinkExternalIssueRequest{
		Context:        principal("tenant-a", "actor-a", "request-unlink", "member"),
		MergeRequestID: mr.ID, Tracker: "JIRA", IssueKey: "PLAT-1",
	})
	if err != nil {
		t.Fatalf("UnlinkExternalIssue: %v", err)
	}
	if len(after.ExternalIssues) != 1 || after.ExternalIssues[0].IssueKey != "ENG-9" {
		t.Fatalf("unexpected references %+v", after.ExternalIssues)
	}
	if n := len(*records); n != 3 {
		t.Fatalf("want two links and one unlink, got %d records", n)
	}
	if (*records)[2].Linked {
		t.Error("the third record must be the unlink")
	}

	version := after.Version
	again, err := service.UnlinkExternalIssue(t.Context(), api.UnlinkExternalIssueRequest{
		Context:        principal("tenant-a", "actor-a", "request-unlink-2", "member"),
		MergeRequestID: mr.ID, Tracker: "JIRA", IssueKey: "PLAT-1",
	})
	if err != nil {
		t.Fatalf("removing a reference that is gone must be accepted: %v", err)
	}
	if again.Version != version || len(*records) != 3 {
		t.Errorf("a no-op unlink changed something: version %d, %d records", again.Version, len(*records))
	}
}

// AC7: nothing on this path reads the tracker. The reference is stored exactly as
// given, and the service has no client that could ask.
//
// The assertion is about the shape rather than about a call count: a service with no
// HTTP port cannot make an outbound call, and this test pins the reference's
// integrity so a future "helpful" normalisation is visible.
func TestTheReferenceIsStoredExactlyAsGiven(t *testing.T) {
	service, _, _, _ := newService(t)
	mr := openOne(t, service, "request-open")
	exact := "https://tracker.example.test/browse/PLAT-1421?focus=comment-88#reply"

	linked, err := linkOne(t, service, mr.ID, "JIRA", "PLAT-1421", exact)
	if err != nil {
		t.Fatalf("LinkExternalIssue: %v", err)
	}
	if linked.ExternalIssues[0].URL != exact {
		t.Errorf("the URL was rewritten: %q", linked.ExternalIssues[0].URL)
	}
	// Nothing was fetched, so nothing about the issue is known. The reference
	// carries no field that could hold what the issue says.
	if got := linked.ExternalIssues[0]; got.Tracker == "" || got.IssueKey == "" {
		t.Errorf("unexpected reference %+v", got)
	}
}
