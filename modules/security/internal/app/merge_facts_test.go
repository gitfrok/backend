package app_test

import (
	"context"
	"testing"
	"time"

	"github.com/gitfrok/backend/modules/security/api"
)

// The merge-gate findings-facts assembler tests (T-0025, SPEC-0029,
// SPEC-0030): the facts are the SPEC-0028 attribution this context already
// materializes, rendered as gate facts — counts by severity, the highest
// attributed severity, and the ACCEPT/FALSE_POSITIVE triage records an
// exemption relies on, and ONLY when they fully cover the breach. Every way
// the facts cannot assemble is the same coarse error: the merge gate fails
// closed on it (SPEC-0029 AC9).

// factsSetup materializes an ATTRIBUTED comparison at rev-head against an
// empty base and returns the rendered views so the tests can name finding
// identities.
func factsSetup(t *testing.T, h *harness, head ...api.RawFinding) []api.MergeRequestFindingView {
	t.Helper()
	ctx := context.Background()
	h.svc.SetMergeBaseResolver(&fakeResolver{base: "rev-base", found: true})
	if _, err := h.svc.IngestScanResults(ctx, chunkAt("rev-base", "req-b", 0)); err != nil {
		t.Fatalf("base scan: %v", err)
	}
	if _, err := h.svc.IngestScanResults(ctx, chunkAt("rev-head", "req-h", time.Hour, head...)); err != nil {
		t.Fatalf("head scan: %v", err)
	}
	announceMR(h, "rev-head")
	page, err := h.svc.ListMergeRequestFindings(ctx, mrRequest())
	if err != nil || page.Summary.Status != api.AttributionAttributed {
		t.Fatalf("comparison must be attributed: %+v err=%v", page.Summary, err)
	}
	return page.Views
}

// acceptTriage records an ACCEPT triage on one finding identity.
func acceptTriage(t *testing.T, h *harness, reqID, findingID string) string {
	t.Helper()
	ctx := validContext()
	ctx.RequestID = reqID
	out, err := h.svc.SetTriage(context.Background(), api.TriageTransition{
		Context: ctx, FindingID: findingID, State: api.TriageAccept,
		Justification: "covered for the gate", ExpectedVersion: 0,
	})
	if err != nil || out.Replayed || out.Mismatch {
		t.Fatalf("SetTriage: %+v err=%v", out, err)
	}
	return out.Record.TriageID
}

// Below the reviewed threshold the facts render the attributed counts and
// highest severity with no exemption (SPEC-0029 AC3 input shape).
func TestMergeFactsBelowThreshold(t *testing.T) {
	h := newHarness(true)
	low := rawFinding("rule-low", "low.py", "fn-low")
	low.Severity = api.SeverityLow
	med := rawFinding("rule-med", "med.py", "fn-med")
	med.Severity = api.SeverityMedium
	factsSetup(t, h, low, med)

	facts, err := h.svc.MergeFindingsFacts(context.Background(), "t-1", "repo-1", "actor-1", "mr-1")
	if err != nil {
		t.Fatalf("facts must assemble: %v", err)
	}
	if facts.Low != 1 || facts.Medium != 1 || facts.High != 0 || facts.Critical != 0 {
		t.Fatalf("counts mismatch: %+v", facts)
	}
	if facts.HighestAttributedSeverity != "MEDIUM" || len(facts.ReliedUponTriageIDs) != 0 {
		t.Fatalf("highest/exemption mismatch: %+v", facts)
	}
}

// A clean comparison renders NONE with zero counts — the gate engages and
// allows (SPEC-0029 AC3).
func TestMergeFactsCleanComparison(t *testing.T) {
	h := newHarness(true)
	factsSetup(t, h)
	facts, err := h.svc.MergeFindingsFacts(context.Background(), "t-1", "repo-1", "actor-1", "mr-1")
	if err != nil {
		t.Fatalf("facts must assemble: %v", err)
	}
	if facts.HighestAttributedSeverity != "NONE" || facts.Low+facts.Medium+facts.High+facts.Critical != 0 {
		t.Fatalf("a clean comparison must render NONE: %+v", facts)
	}
}

// A breach no triage covers renders uncovered: the facts carry the breach and
// no ReliedUponTriageIDs, so the gate denies (SPEC-0029 AC3/AC4).
func TestMergeFactsUncoveredBreach(t *testing.T) {
	h := newHarness(true)
	factsSetup(t, h, rawFinding("rule-high", "high.py", "fn-high"))
	facts, err := h.svc.MergeFindingsFacts(context.Background(), "t-1", "repo-1", "actor-1", "mr-1")
	if err != nil {
		t.Fatalf("facts must assemble: %v", err)
	}
	if facts.High != 1 || facts.HighestAttributedSeverity != "HIGH" || len(facts.ReliedUponTriageIDs) != 0 {
		t.Fatalf("an uncovered breach must render uncovered: %+v", facts)
	}
}

// An ACCEPT triage covering EVERY breach-level finding is the exemption: the
// facts carry the relied-upon triage records, and the counts still report the
// breach the exemption covers (SPEC-0029 AC4).
func TestMergeFactsFullExemption(t *testing.T) {
	h := newHarness(true)
	views := factsSetup(t, h,
		rawFinding("rule-h1", "h1.py", "fn-h1"), rawFinding("rule-h2", "h2.py", "fn-h2"))
	triageIDs := map[string]bool{}
	for i, v := range views {
		triageIDs[acceptTriage(t, h, "req-triage-"+string(rune('a'+i)), v.Finding.ID)] = true
	}

	facts, err := h.svc.MergeFindingsFacts(context.Background(), "t-1", "repo-1", "actor-1", "mr-1")
	if err != nil {
		t.Fatalf("facts must assemble: %v", err)
	}
	if facts.High != 2 || facts.HighestAttributedSeverity != "HIGH" {
		t.Fatalf("the exemption does not change the counts: %+v", facts)
	}
	if len(facts.ReliedUponTriageIDs) != 2 {
		t.Fatalf("expected both triage records relied upon: %+v", facts)
	}
	for _, id := range facts.ReliedUponTriageIDs {
		if !triageIDs[id] {
			t.Fatalf("unexpected triage ID %s", id)
		}
	}
}

// Partial coverage is no coverage: one uncovered breach-level finding keeps
// the whole breach uncovered (SPEC-0029 AC4).
func TestMergeFactsPartialCoverageDenies(t *testing.T) {
	h := newHarness(true)
	views := factsSetup(t, h,
		rawFinding("rule-h1", "h1.py", "fn-h1"), rawFinding("rule-h2", "h2.py", "fn-h2"))
	acceptTriage(t, h, "req-triage-a", views[0].Finding.ID)

	facts, err := h.svc.MergeFindingsFacts(context.Background(), "t-1", "repo-1", "actor-1", "mr-1")
	if err != nil {
		t.Fatalf("facts must assemble: %v", err)
	}
	if len(facts.ReliedUponTriageIDs) != 0 {
		t.Fatalf("partial coverage must not exempt: %+v", facts)
	}
}

// A DEFER triage is not an exemption: only ACCEPT/FALSE_POSITIVE covers a
// breach (SPEC-0029 AC4).
func TestMergeFactsDeferDoesNotExempt(t *testing.T) {
	h := newHarness(true)
	views := factsSetup(t, h, rawFinding("rule-high", "high.py", "fn-high"))
	ctx := validContext()
	ctx.RequestID = "req-triage-defer"
	if _, err := h.svc.SetTriage(context.Background(), api.TriageTransition{
		Context: ctx, FindingID: views[0].Finding.ID, State: api.TriageDefer,
		Justification: "later", ExpectedVersion: 0,
	}); err != nil {
		t.Fatalf("SetTriage: %v", err)
	}
	facts, err := h.svc.MergeFindingsFacts(context.Background(), "t-1", "repo-1", "actor-1", "mr-1")
	if err != nil {
		t.Fatalf("facts must assemble: %v", err)
	}
	if len(facts.ReliedUponTriageIDs) != 0 {
		t.Fatalf("a DEFER must not exempt: %+v", facts)
	}
}

// PRE_EXISTING findings are excluded: a HIGH defect already at the base does
// not raise the gate's highest severity or counts (SPEC-0028 attribution).
func TestMergeFactsPreExistingExcluded(t *testing.T) {
	h := newHarness(true)
	ctx := context.Background()
	h.svc.SetMergeBaseResolver(&fakeResolver{base: "rev-base", found: true})
	if _, err := h.svc.IngestScanResults(ctx, chunkAt("rev-base", "req-b", 0,
		rawFinding("rule-old", "old.py", "fn-old"))); err != nil {
		t.Fatal(err)
	}
	low := rawFinding("rule-low", "low.py", "fn-low")
	low.Severity = api.SeverityLow
	if _, err := h.svc.IngestScanResults(ctx, chunkAt("rev-head", "req-h", time.Hour,
		rawFinding("rule-old", "old.py", "fn-old"), low)); err != nil {
		t.Fatal(err)
	}
	announceMR(h, "rev-head")

	facts, err := h.svc.MergeFindingsFacts(ctx, "t-1", "repo-1", "actor-1", "mr-1")
	if err != nil {
		t.Fatalf("facts must assemble: %v", err)
	}
	if facts.HighestAttributedSeverity != "LOW" || facts.High != 0 || facts.Low != 1 {
		t.Fatalf("PRE_EXISTING must not count: %+v", facts)
	}
}

// Every way the facts cannot assemble is the same coarse error — missing,
// stale, cross-scoped, and malformed are indistinguishable, and the merge
// gate fails closed on all of them (SPEC-0029 AC9).
func TestMergeFactsFailClosed(t *testing.T) {
	ctx := context.Background()

	t.Run("unknown merge request", func(t *testing.T) {
		h := newHarness(true)
		if _, err := h.svc.MergeFindingsFacts(ctx, "t-1", "repo-1", "actor-1", "mr-nope"); err == nil {
			t.Fatal("an unknown MR must not assemble")
		}
	})
	t.Run("wrong repository", func(t *testing.T) {
		h := newHarness(true)
		factsSetup(t, h)
		if _, err := h.svc.MergeFindingsFacts(ctx, "t-1", "repo-2", "actor-1", "mr-1"); err == nil {
			t.Fatal("a cross-repository request must not assemble")
		}
	})
	t.Run("empty arguments", func(t *testing.T) {
		h := newHarness(true)
		factsSetup(t, h)
		if _, err := h.svc.MergeFindingsFacts(ctx, "", "repo-1", "actor-1", "mr-1"); err == nil {
			t.Fatal("an empty tenant must not assemble")
		}
	})
	t.Run("unavailable comparison", func(t *testing.T) {
		h := newHarness(true)
		h.svc.SetMergeBaseResolver(&fakeResolver{found: false})
		if _, err := h.svc.IngestScanResults(ctx, chunkAt("rev-head", "req-h", 0,
			rawFinding("rule-new", "new.py", "fn-new"))); err != nil {
			t.Fatal(err)
		}
		announceMR(h, "rev-head")
		if _, err := h.svc.MergeFindingsFacts(ctx, "t-1", "repo-1", "actor-1", "mr-1"); err == nil {
			t.Fatal("an UNAVAILABLE comparison must not assemble")
		}
	})
	t.Run("stale record", func(t *testing.T) {
		h := newHarness(true)
		factsSetup(t, h, rawFinding("rule-high", "high.py", "fn-high"))
		// The head moves; no scan of the new head exists: a gate fact accepts
		// no stale fallback.
		announceMR(h, "rev-head2")
		if _, err := h.svc.MergeFindingsFacts(ctx, "t-1", "repo-1", "actor-1", "mr-1"); err == nil {
			t.Fatal("a stale comparison must not assemble")
		}
	})
}
