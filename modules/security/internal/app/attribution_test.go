package app_test

import (
	"context"
	"errors"
	"testing"
	"time"

	codereviewapi "github.com/gitfrok/backend/modules/codereview/api"
	"github.com/gitfrok/backend/modules/security/api"
)

// The attribution engine tests (SPEC-0028): attribution is the set difference
// between what the MR's head revision reports and what its merge base
// reports, by SPEC-0024 identity; an UNAVAILABLE comparison is reported with
// its reason, never degraded to an empty result set.

// fakeResolver answers merge-base resolution from test state. It captures
// the roles it was asked under: storage decides repo.read over the subject
// it is handed, so the threading of the actor's verified roles is part of
// the contract under test (north-star Stage D).
type fakeResolver struct {
	base  string
	found bool
	err   error
	calls int
	roles []string
}

func (f *fakeResolver) MergeBase(_ context.Context, _, _, _ string, actorRoles []string, _, _ string) (string, bool, error) {
	f.calls++
	f.roles = actorRoles
	return f.base, f.found, f.err
}

// chunkAt is a completed single-chunk scan pinned to one revision.
func chunkAt(rev, reqID string, offset time.Duration, findings ...api.RawFinding) api.IngestChunk {
	c := singleChunk(sastScan(offset), reqID, findings...)
	c.Revision = rev
	return c
}

// secretsScan is a secrets-class scan by gitleaks — a different scanner
// class and tool than the SAST default, so its findings live in their own
// lifecycle scope.
func secretsScan(startOffset time.Duration) api.Scan {
	return api.Scan{
		ScannerClass: api.ScannerClassSecrets,
		ToolName:     "gitleaks",
		ToolVersion:  "8.21.0",
		StartedAt:    baseTime.Add(startOffset),
		EndedAt:      baseTime.Add(startOffset + time.Minute),
	}
}

// chunkAtClass is chunkAt with an explicit scan descriptor.
func chunkAtClass(scan api.Scan, rev, reqID string, findings ...api.RawFinding) api.IngestChunk {
	c := singleChunk(scan, reqID, findings...)
	c.Revision = rev
	return c
}

// announceMR feeds the tenant-scoped projection the way Code Review does.
func announceMR(h *harness, head string) {
	_ = h.bus.Publish(context.Background(), codereviewapi.MergeRequestUpdated{
		EventID: "evt-mr", MergeRequestID: "mr-1", TenantID: "t-1", RepositoryID: "repo-1",
		ActorID: "actor-1", HeadRevision: head,
		SourceRef: "refs/heads/feature", TargetRef: "refs/heads/main",
		OccurredAt: baseTime,
	})
}

func mrRequest() api.MergeRequestFindingsRequest {
	return api.MergeRequestFindingsRequest{Context: validContext(), MergeRequestID: "mr-1"}
}

// Attribution is the head/base set difference by identity: a defect the base
// scan already reports is PRE_EXISTING whatever its first-seen time, and only
// a defect absent at the base is ATTRIBUTED to the merge request (SPEC-0028
// AC1/AC2).
func TestAttributionIsHeadMinusBaseByIdentity(t *testing.T) {
	h := newHarness(true)
	ctx := context.Background()
	resolver := &fakeResolver{base: "rev-base", found: true}
	h.svc.SetMergeBaseResolver(resolver)

	if _, err := h.svc.IngestScanResults(ctx, chunkAt("rev-base", "req-b", 0,
		rawFinding("rule-old", "old.py", "fn-old"))); err != nil {
		t.Fatalf("base scan: %v", err)
	}
	if _, err := h.svc.IngestScanResults(ctx, chunkAt("rev-head", "req-h", time.Hour,
		rawFinding("rule-old", "old.py", "fn-old"), rawFinding("rule-new", "new.py", "fn-new"))); err != nil {
		t.Fatalf("head scan: %v", err)
	}
	announceMR(h, "rev-head")

	page, err := h.svc.ListMergeRequestFindings(ctx, mrRequest())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(page.Views) != 2 {
		t.Fatalf("expected both head findings rendered, got %d", len(page.Views))
	}
	for _, v := range page.Views {
		switch v.Finding.RuleID {
		case "rule-new":
			if v.Attribution != api.AttributionAttributed {
				t.Fatalf("new defect must be ATTRIBUTED, got %s", v.Attribution)
			}
		case "rule-old":
			if v.Attribution != api.AttributionPreExisting {
				t.Fatalf("base defect must be PRE_EXISTING, got %s", v.Attribution)
			}
		default:
			t.Fatalf("unexpected finding %s", v.Finding.RuleID)
		}
		if v.HeadLocation != v.Finding.Location {
			t.Fatalf("head location must resolve from the finding: %+v", v)
		}
	}
	s := page.Summary
	if s.Status != api.AttributionAttributed || s.Stale ||
		s.HeadRevision != "rev-head" || s.MergeBaseRevision != "rev-base" ||
		s.AttributedHigh != 1 || s.AttributedLow != 0 || s.AttributedMedium != 0 || s.AttributedCritical != 0 {
		t.Fatalf("summary mismatch: %+v", s)
	}

	// The comparison emits FindingsAttributed exactly once per (MR, head,
	// base) triple, whatever how many times it is served (SPEC-0028
	// idempotency).
	if len(h.attributed) != 1 {
		t.Fatalf("expected one FindingsAttributed, got %d", len(h.attributed))
	}
	e := h.attributed[0]
	if e.TenantID != "t-1" || e.RepositoryID != "repo-1" || e.MergeRequestID != "mr-1" ||
		e.HeadRevision != "rev-head" || e.BaseRevision != "rev-base" || e.AttributedHigh != 1 {
		t.Fatalf("FindingsAttributed mismatch: %+v", e)
	}
	if _, err := h.svc.ListMergeRequestFindings(ctx, mrRequest()); err != nil {
		t.Fatalf("relist: %v", err)
	}
	if len(h.attributed) != 1 {
		t.Fatalf("a repeat serving must not re-emit, got %d events", len(h.attributed))
	}
}

// A moved head with no scan yet serves the earlier materialization as stale,
// never as current and never as empty (SPEC-0028 non-functional).
func TestAttributionMovedHeadServesStale(t *testing.T) {
	h := newHarness(true)
	ctx := context.Background()
	h.svc.SetMergeBaseResolver(&fakeResolver{base: "rev-base", found: true})
	if _, err := h.svc.IngestScanResults(ctx, chunkAt("rev-base", "req-b", 0,
		rawFinding("rule-old", "old.py", "fn-old"))); err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.IngestScanResults(ctx, chunkAt("rev-head", "req-h", time.Hour,
		rawFinding("rule-new", "new.py", "fn-new"))); err != nil {
		t.Fatal(err)
	}
	announceMR(h, "rev-head")
	if _, err := h.svc.ListMergeRequestFindings(ctx, mrRequest()); err != nil {
		t.Fatal(err)
	}

	// The push moves the head; no scan of the new head exists yet.
	announceMR(h, "rev-head2")
	page, err := h.svc.ListMergeRequestFindings(ctx, mrRequest())
	if err != nil {
		t.Fatalf("list after head move: %v", err)
	}
	if !page.Summary.Stale || page.Summary.HeadRevision != "rev-head" || len(page.Views) != 1 {
		t.Fatalf("the earlier triple must serve as stale: %+v", page.Summary)
	}
}

// An UNAVAILABLE comparison reports its reason with an empty list; it never
// degrades to "no findings" (SPEC-0028 AC7).
func TestAttributionUnavailableReasons(t *testing.T) {
	t.Run("head scan not run", func(t *testing.T) {
		h := newHarness(true)
		h.svc.SetMergeBaseResolver(&fakeResolver{base: "rev-base", found: true})
		announceMR(h, "rev-head")
		page, err := h.svc.ListMergeRequestFindings(context.Background(), mrRequest())
		if err != nil || len(page.Views) != 0 {
			t.Fatalf("expected empty views, got %d err=%v", len(page.Views), err)
		}
		if page.Summary.Status != api.AttributionUnavailable ||
			page.Summary.UnavailableReason != api.AttributionUnavailableHeadScanNotRun ||
			page.Summary.HeadRevision != "rev-head" {
			t.Fatalf("summary mismatch: %+v", page.Summary)
		}
	})
	t.Run("base not scanned", func(t *testing.T) {
		h := newHarness(true)
		h.svc.SetMergeBaseResolver(&fakeResolver{base: "rev-base", found: true})
		if _, err := h.svc.IngestScanResults(context.Background(), chunkAt("rev-head", "req-h", 0,
			rawFinding("rule-new", "new.py", "fn-new"))); err != nil {
			t.Fatal(err)
		}
		announceMR(h, "rev-head")
		page, err := h.svc.ListMergeRequestFindings(context.Background(), mrRequest())
		if err != nil || len(page.Views) != 0 {
			t.Fatalf("expected empty views, got %d err=%v", len(page.Views), err)
		}
		if page.Summary.Status != api.AttributionUnavailable ||
			page.Summary.UnavailableReason != api.AttributionUnavailableBaseNotScanned ||
			page.Summary.MergeBaseRevision != "rev-base" {
			t.Fatalf("summary mismatch: %+v", page.Summary)
		}
	})
	t.Run("no merge base", func(t *testing.T) {
		h := newHarness(true)
		h.svc.SetMergeBaseResolver(&fakeResolver{found: false})
		if _, err := h.svc.IngestScanResults(context.Background(), chunkAt("rev-head", "req-h", 0,
			rawFinding("rule-new", "new.py", "fn-new"))); err != nil {
			t.Fatal(err)
		}
		announceMR(h, "rev-head")
		page, err := h.svc.ListMergeRequestFindings(context.Background(), mrRequest())
		if err != nil || len(page.Views) != 0 {
			t.Fatalf("expected empty views, got %d err=%v", len(page.Views), err)
		}
		if page.Summary.Status != api.AttributionUnavailable ||
			page.Summary.UnavailableReason != api.AttributionUnavailableNoMergeBase {
			t.Fatalf("summary mismatch: %+v", page.Summary)
		}
	})
	t.Run("no resolver attached", func(t *testing.T) {
		h := newHarness(true)
		if _, err := h.svc.IngestScanResults(context.Background(), chunkAt("rev-head", "req-h", 0,
			rawFinding("rule-new", "new.py", "fn-new"))); err != nil {
			t.Fatal(err)
		}
		announceMR(h, "rev-head")
		page, err := h.svc.ListMergeRequestFindings(context.Background(), mrRequest())
		if err != nil || len(page.Views) != 0 || page.Summary.Status != api.AttributionUnavailable ||
			page.Summary.UnavailableReason != api.AttributionUnavailableMergeBaseResolverNotComposed {
			t.Fatalf("a plane without the Git route must report UNAVAILABLE with its reason: %+v err=%v", page.Summary, err)
		}
	})
}

// An infrastructure failure with no materialization to fall back on is a
// coarse denial — never an empty success (SPEC-0001).
func TestAttributionResolverErrorDenies(t *testing.T) {
	h := newHarness(true)
	h.svc.SetMergeBaseResolver(&fakeResolver{err: errors.New("git unreachable")})
	if _, err := h.svc.IngestScanResults(context.Background(), chunkAt("rev-head", "req-h", 0,
		rawFinding("rule-new", "new.py", "fn-new"))); err != nil {
		t.Fatal(err)
	}
	announceMR(h, "rev-head")
	if _, err := h.svc.ListMergeRequestFindings(context.Background(), mrRequest()); !errors.Is(err, api.ErrDenied) {
		t.Fatalf("expected coarse denial, got %v", err)
	}
}

// Unknown, cross-tenant, and cross-repository merge requests are the same
// coarse denial; so is a PDP refusal (SPEC-0001).
func TestAttributionDenialsAreCoarse(t *testing.T) {
	h := newHarness(true)
	announceMR(h, "rev-head")

	if _, err := h.svc.ListMergeRequestFindings(context.Background(),
		api.MergeRequestFindingsRequest{Context: validContext(), MergeRequestID: "mr-nope"}); !errors.Is(err, api.ErrDenied) {
		t.Fatalf("unknown MR must deny, got %v", err)
	}
	crossTenant := validContext()
	crossTenant.TenantID = "t-2"
	if _, err := h.svc.ListMergeRequestFindings(context.Background(),
		api.MergeRequestFindingsRequest{Context: crossTenant, MergeRequestID: "mr-1"}); !errors.Is(err, api.ErrDenied) {
		t.Fatalf("cross-tenant must deny, got %v", err)
	}
	crossRepo := validContext()
	crossRepo.RepositoryID = "repo-2"
	if _, err := h.svc.ListMergeRequestFindings(context.Background(),
		api.MergeRequestFindingsRequest{Context: crossRepo, MergeRequestID: "mr-1"}); !errors.Is(err, api.ErrDenied) {
		t.Fatalf("cross-repository must deny, got %v", err)
	}

	deny := newHarness(false)
	announceMR(deny, "rev-head")
	if _, err := deny.svc.ListMergeRequestFindings(context.Background(), mrRequest()); !errors.Is(err, api.ErrDenied) {
		t.Fatalf("PDP denial must deny, got %v", err)
	}
}

// Filters combine and narrow; the attribution filter selects by status
// (SPEC-0026 AC2 pattern).
func TestAttributionFilters(t *testing.T) {
	h := newHarness(true)
	ctx := context.Background()
	h.svc.SetMergeBaseResolver(&fakeResolver{base: "rev-base", found: true})
	pre := rawFinding("rule-old", "old.py", "fn-old")
	if _, err := h.svc.IngestScanResults(ctx, chunkAt("rev-base", "req-b", 0, pre)); err != nil {
		t.Fatal(err)
	}
	low := rawFinding("rule-low", "low.py", "fn-low")
	low.Severity = api.SeverityLow
	if _, err := h.svc.IngestScanResults(ctx, chunkAt("rev-head", "req-h", time.Hour,
		pre, rawFinding("rule-high", "high.py", "fn-high"), low)); err != nil {
		t.Fatal(err)
	}
	announceMR(h, "rev-head")

	attrOnly := mrRequest()
	attrOnly.AttributionFilter = api.AttributionAttributed
	page, err := h.svc.ListMergeRequestFindings(ctx, attrOnly)
	if err != nil || len(page.Views) != 2 {
		t.Fatalf("attribution filter: %d views err=%v", len(page.Views), err)
	}
	for _, v := range page.Views {
		if v.Attribution != api.AttributionAttributed {
			t.Fatalf("filter leaked %s", v.Attribution)
		}
	}

	sev := mrRequest()
	sev.SeverityFilter = api.SeverityLow
	page, err = h.svc.ListMergeRequestFindings(ctx, sev)
	if err != nil || len(page.Views) != 1 || page.Views[0].Finding.RuleID != "rule-low" {
		t.Fatalf("severity filter: %+v err=%v", page.Views, err)
	}

	if _, err := h.svc.ListMergeRequestFindings(ctx,
		api.MergeRequestFindingsRequest{Context: validContext(), MergeRequestID: "mr-1", AttributionFilter: "BOGUS"}); !errors.Is(err, api.ErrMalformed) {
		t.Fatalf("invalid attribution filter must be malformed, got %v", err)
	}
}

// Paging walks attributed views by finding ID with signed cursors bound to
// the tenant, the merge request, and the issuing filters; a forged token
// yields no content but the summary still names the comparison (SPEC-0025).
func TestAttributionPagingAndCursorBinding(t *testing.T) {
	h := newHarness(true)
	ctx := context.Background()
	h.svc.SetMergeBaseResolver(&fakeResolver{base: "rev-base", found: true})
	if _, err := h.svc.IngestScanResults(ctx, chunkAt("rev-base", "req-b", 0,
		rawFinding("rule-gone", "gone.py", "fn-gone"))); err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.IngestScanResults(ctx, chunkAt("rev-head", "req-h", time.Hour,
		rawFinding("rule-a", "a.py", "fn-a"), rawFinding("rule-b", "b.py", "fn-b"), rawFinding("rule-c", "c.py", "fn-c"))); err != nil {
		t.Fatal(err)
	}
	announceMR(h, "rev-head")

	req := mrRequest()
	req.PageSize = 2
	page1, err := h.svc.ListMergeRequestFindings(ctx, req)
	if err != nil || len(page1.Views) != 2 || page1.NextPageToken == "" {
		t.Fatalf("page 1: %d views err=%v", len(page1.Views), err)
	}
	req.PageToken = page1.NextPageToken
	page2, err := h.svc.ListMergeRequestFindings(ctx, req)
	if err != nil || len(page2.Views) != 1 || page2.NextPageToken != "" {
		t.Fatalf("page 2: %d views err=%v", len(page2.Views), err)
	}
	if page1.Views[0].Finding.ID == page2.Views[0].Finding.ID {
		t.Fatalf("pages must not repeat findings")
	}

	req.PageToken = "forged"
	forged, err := h.svc.ListMergeRequestFindings(ctx, req)
	if err != nil || len(forged.Views) != 0 || forged.Summary.Status != api.AttributionAttributed {
		t.Fatalf("a forged token yields no content but keeps the summary: %+v err=%v", forged, err)
	}
}

// A scan landing after the MR announcement completes the comparison: the
// event-fed precompute lights up without a read (SPEC-0028).
func TestAttributionCompletesWhenScanLands(t *testing.T) {
	h := newHarness(true)
	ctx := context.Background()
	h.svc.SetMergeBaseResolver(&fakeResolver{base: "rev-base", found: true})
	if _, err := h.svc.IngestScanResults(ctx, chunkAt("rev-base", "req-b", 0,
		rawFinding("rule-old", "old.py", "fn-old"))); err != nil {
		t.Fatal(err)
	}
	announceMR(h, "rev-head")
	if len(h.attributed) != 0 {
		t.Fatalf("no scan of the head yet: nothing attributed, got %d", len(h.attributed))
	}
	if _, err := h.svc.IngestScanResults(ctx, chunkAt("rev-head", "req-h", time.Hour,
		rawFinding("rule-old", "old.py", "fn-old"), rawFinding("rule-new", "new.py", "fn-new"))); err != nil {
		t.Fatal(err)
	}
	if len(h.attributed) != 1 || h.attributed[0].HeadRevision != "rev-head" {
		t.Fatalf("the landing scan must complete the comparison: %+v", h.attributed)
	}
	page, err := h.svc.ListMergeRequestFindings(ctx, mrRequest())
	if err != nil || page.Summary.Status != api.AttributionAttributed || page.Summary.Stale {
		t.Fatalf("post-scan serving: %+v err=%v", page.Summary, err)
	}
}

// The reported set at a revision spans every ingested scanner class:
// semgrep AND gitleaks scanning the same head both contribute to the MR
// view — attribution never sees just one scan per revision (SPEC-0026 AC1,
// SPEC-0028 AC1; phase-2 review H5).
func TestAttributionSpansScannerClasses(t *testing.T) {
	h := newHarness(true)
	ctx := context.Background()
	h.svc.SetMergeBaseResolver(&fakeResolver{base: "rev-base", found: true})

	// An empty base scan gives the comparison its base side.
	if _, err := h.svc.IngestScanResults(ctx, chunkAt("rev-base", "req-b", 0)); err != nil {
		t.Fatalf("base scan: %v", err)
	}
	// Two scanner classes at the same head revision.
	if _, err := h.svc.IngestScanResults(ctx, chunkAt("rev-head", "req-h1", time.Hour,
		rawFinding("rule-sast", "app.py", "fn-sast"))); err != nil {
		t.Fatalf("sast scan: %v", err)
	}
	if _, err := h.svc.IngestScanResults(ctx, chunkAtClass(secretsScan(time.Hour), "rev-head", "req-h2",
		rawFinding("rule-secret", "creds.env", "fn-secret"))); err != nil {
		t.Fatalf("secrets scan: %v", err)
	}
	announceMR(h, "rev-head")

	page, err := h.svc.ListMergeRequestFindings(ctx, mrRequest())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	rules := map[string]api.AttributionStatus{}
	for _, v := range page.Views {
		rules[v.Finding.RuleID] = v.Attribution
	}
	if len(page.Views) != 2 ||
		rules["rule-sast"] != api.AttributionAttributed ||
		rules["rule-secret"] != api.AttributionAttributed {
		t.Fatalf("both scanner classes must contribute: %+v", page.Views)
	}
	if page.Summary.AttributedHigh != 2 {
		t.Fatalf("summary must count both classes: %+v", page.Summary)
	}
}

// A later scan at the same head/base replaces the stored materialization:
// the served MR view and the gate facts reflect the fresh computation,
// never the earlier one (phase-2 review H6). An unchanged recompute stays
// silent; the changed one re-emits honestly.
func TestAttributionSecondScanAtSameHeadUpdatesMaterialization(t *testing.T) {
	h := newHarness(true)
	ctx := context.Background()
	h.svc.SetMergeBaseResolver(&fakeResolver{base: "rev-base", found: true})

	if _, err := h.svc.IngestScanResults(ctx, chunkAt("rev-base", "req-b", 0)); err != nil {
		t.Fatalf("base scan: %v", err)
	}
	if _, err := h.svc.IngestScanResults(ctx, chunkAt("rev-head", "req-h1", time.Hour,
		rawFinding("rule-old", "old.py", "fn-old"))); err != nil {
		t.Fatalf("head scan 1: %v", err)
	}
	announceMR(h, "rev-head")
	page, err := h.svc.ListMergeRequestFindings(ctx, mrRequest())
	if err != nil || len(page.Views) != 1 || page.Summary.AttributedHigh != 1 {
		t.Fatalf("first materialization: %+v err=%v", page.Summary, err)
	}
	if len(h.attributed) != 1 {
		t.Fatalf("expected one FindingsAttributed, got %d", len(h.attributed))
	}

	// A second scan of the same head by the same tool reports a different
	// set: the first scan's finding resolves, the new one opens, and the
	// materialization must move with them.
	if _, err := h.svc.IngestScanResults(ctx, chunkAt("rev-head", "req-h2", 2*time.Hour,
		rawFinding("rule-newer", "newer.py", "fn-newer"))); err != nil {
		t.Fatalf("head scan 2: %v", err)
	}
	page, err = h.svc.ListMergeRequestFindings(ctx, mrRequest())
	if err != nil {
		t.Fatalf("list after rescan: %v", err)
	}
	if len(page.Views) != 1 || page.Views[0].Finding.RuleID != "rule-newer" ||
		page.Views[0].Attribution != api.AttributionAttributed {
		t.Fatalf("the rescan must replace the materialized view: %+v", page.Views)
	}
	if page.Summary.AttributedHigh != 1 || page.Summary.Stale {
		t.Fatalf("summary must follow the rescan: %+v", page.Summary)
	}
	if len(h.attributed) != 2 || h.attributed[1].AttributedHigh != 1 {
		t.Fatalf("a changed materialization must re-emit honestly: %+v", h.attributed)
	}

	facts, err := h.svc.MergeFindingsFacts(ctx, "t-1", "repo-1", "actor-1", []string{"owner"}, "mr-1")
	if err != nil || facts.High != 1 || facts.HighestAttributedSeverity != "HIGH" {
		t.Fatalf("gate facts must follow the rescan: %+v err=%v", facts, err)
	}
}

// A merge-request cursor is bound to the issuing principal: the same
// tenant's second actor replaying the token gets no content, while the
// summary still names the comparison (phase-2 review L17).
func TestMRCursorIsBoundToTheIssuingActor(t *testing.T) {
	h := newHarness(true)
	ctx := context.Background()
	h.svc.SetMergeBaseResolver(&fakeResolver{base: "rev-base", found: true})
	if _, err := h.svc.IngestScanResults(ctx, chunkAt("rev-base", "req-b", 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.IngestScanResults(ctx, chunkAt("rev-head", "req-h", time.Hour,
		rawFinding("rule-a", "a.py", "fn-a"), rawFinding("rule-b", "b.py", "fn-b"))); err != nil {
		t.Fatal(err)
	}
	announceMR(h, "rev-head")

	req := mrRequest()
	req.PageSize = 1
	page1, err := h.svc.ListMergeRequestFindings(ctx, req)
	if err != nil || page1.NextPageToken == "" {
		t.Fatalf("page 1 must carry a next token: %+v err=%v", page1, err)
	}

	other := mrRequest()
	other.PageSize = 1
	other.ActorID = "actor-2"
	other.PageToken = page1.NextPageToken
	page2, err := h.svc.ListMergeRequestFindings(ctx, other)
	if err != nil || len(page2.Views) != 0 || page2.NextPageToken != "" {
		t.Fatalf("another actor's replay of the token must yield nothing: %+v err=%v", page2, err)
	}
	if page2.Summary.Status != api.AttributionAttributed {
		t.Fatalf("the summary still names the comparison: %+v", page2.Summary)
	}

	req.PageToken = page1.NextPageToken
	own, err := h.svc.ListMergeRequestFindings(ctx, req)
	if err != nil || len(own.Views) != 1 {
		t.Fatalf("the issuing actor's own token must still page: %+v err=%v", own, err)
	}
}
