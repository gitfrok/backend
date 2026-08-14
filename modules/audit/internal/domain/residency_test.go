// The residency section's pure-computation invariants (T-0033, SPEC-0040):
// classification of the four witnessed residency facts, the declaration-in-
// force derivation (AC6), and the AC5 rule that silence renders as a gap,
// never as compliance.
package domain

import (
	"testing"
	"time"

	"github.com/gitfrok/backend/modules/audit/api"
)

// residencyRecord is one witnessed residency fact as the Residency context's
// witness adapter writes it onto the tenant's chain.
func residencyRecord(seq int64, action api.Action, resource string, outcome api.Outcome, detail map[string]string) api.Record {
	return api.Record{
		Seq:        seq,
		TenantID:   "tenant-a",
		Action:     action,
		ActorID:    "control-plane",
		Resource:   resource,
		Outcome:    outcome,
		Detail:     detail,
		OccurredAt: evidenceNow.Add(time.Duration(seq) * time.Hour),
		PrevHash:   "prev-hash",
		Hash:       "hash",
	}
}

// TestClassifyResidencyFacts is AC4's classification half: each of the four
// witnessed actions classifies into the residency section with its fact kind
// and BOTH placements, and a refused or contradicting placement is cited with
// allowed=false — the outcome the chain witnessed.
func TestClassifyResidencyFacts(t *testing.T) {
	pinned := map[string]string{
		"pinned_cloud": "gke", "pinned_region": "europe-west1",
		"observed_cloud": "aws", "observed_region": "us-east1",
	}
	cases := []struct {
		action api.Action
		kind   api.ResidencyFactKind
		denied bool
	}{{
		actionResidencyDeclarationSet, api.ResidencyFactPinning, false,
	}, {
		actionResidencyPlacementObserved, api.ResidencyFactPlacement, false,
	}, {
		actionResidencyPlacementRefused, api.ResidencyFactPlacementRefused, true,
	}, {
		actionResidencyPlacementContradicted, api.ResidencyFactPlacementContradiction, true,
	}}
	for _, tc := range cases {
		outcome := api.OutcomeAllowed
		if tc.denied {
			outcome = api.OutcomeDenied
		}
		sr, section, ok := Classify(residencyRecord(1, tc.action, "data_plane/plane-1", outcome, pinned))
		if !ok || section != api.SectionResidency || sr.Residency == nil {
			t.Fatalf("%s: must classify into the residency section, got ok=%v section=%v", tc.action, ok, section)
		}
		if sr.Residency.FactKind != tc.kind {
			t.Fatalf("%s: fact kind = %v, want %v", tc.action, sr.Residency.FactKind, tc.kind)
		}
		if sr.Allowed != !tc.denied {
			t.Fatalf("%s: allowed = %v, want %v — the section cites the witnessed outcome", tc.action, sr.Allowed, !tc.denied)
		}
		if tc.kind != api.ResidencyFactPinning {
			if sr.Residency.DataPlaneID != "plane-1" {
				t.Fatalf("%s: data plane ID = %q, want plane-1", tc.action, sr.Residency.DataPlaneID)
			}
			if sr.Residency.ObservedCloud != "aws" || sr.Residency.ObservedRegion != "us-east1" {
				t.Fatalf("%s: observed placement missing: %+v", tc.action, sr.Residency)
			}
		}
		if sr.Residency.PinnedCloud != "gke" || sr.Residency.PinnedRegion != "europe-west1" {
			t.Fatalf("%s: pinned placement missing: %+v", tc.action, sr.Residency)
		}
	}
}

// sectionFact is one classified residency record for the silence-gap tests.
func sectionFact(seq int64, kind api.ResidencyFactKind, planeID string, at time.Time) api.SectionRecord {
	return api.SectionRecord{
		ChainSeq:   seq,
		OccurredAt: at,
		Residency:  &api.ResidencyDetail{FactKind: kind, DataPlaneID: planeID},
	}
}

func pinningAt(at time.Time) api.SectionRecord {
	return api.SectionRecord{
		OccurredAt: at,
		Residency:  &api.ResidencyDetail{FactKind: api.ResidencyFactPinning},
	}
}

// TestLastDeclarationBefore is AC6's read side: the declaration in force at
// an instant is the latest pinning strictly before it — a change never
// rewrites the earlier one.
func TestLastDeclarationBefore(t *testing.T) {
	first := pinningAt(evidenceNow)
	second := pinningAt(evidenceNow.Add(48 * time.Hour))
	decls := []api.SectionRecord{first, second}

	got, ok := LastDeclarationBefore(decls, evidenceNow.Add(24*time.Hour))
	if !ok || got != first {
		t.Fatalf("in force mid-window = %+v,%v; want the first pinning", got, ok)
	}
	got, ok = LastDeclarationBefore(decls, evidenceNow.Add(72*time.Hour))
	if !ok || got != second {
		t.Fatalf("in force after the change = %+v,%v; want the change", got, ok)
	}
	// Strictly before: a pinning AT the instant is not yet in force at it.
	if _, ok := LastDeclarationBefore(decls, evidenceNow); ok {
		t.Fatal("a pinning at the instant asked about is not yet in force at it")
	}
	if _, ok := LastDeclarationBefore(nil, evidenceNow); ok {
		t.Fatal("no declarations means nothing in force")
	}
}

// TestSilenceGapsUndeclaredIsNoGap: placement unconstrained by any pinning
// has no residency obligation — silence is not an evidence gap.
func TestSilenceGapsUndeclaredIsNoGap(t *testing.T) {
	from, to := evidenceNow, evidenceNow.Add(24*time.Hour)
	gaps := SilenceGaps([]api.SectionRecord{sectionFact(1, api.ResidencyFactPlacement, "plane-1", from)}, nil, from, to, time.Hour)
	if len(gaps) != 0 {
		t.Fatalf("an undeclared tenant has no silence gaps, got %+v", gaps)
	}
}

// TestSilenceGapsZeroWindowFailsSafe: a declaration in force with no
// configured reporting bound cannot render any interval as covered — the
// whole obligation window is one PLACEMENT_SILENT gap (fail-safe, AC5).
func TestSilenceGapsZeroWindowFailsSafe(t *testing.T) {
	from, to := evidenceNow, evidenceNow.Add(24*time.Hour)
	decl := pinningAt(from.Add(-time.Hour))
	gaps := SilenceGaps([]api.SectionRecord{sectionFact(1, api.ResidencyFactPlacement, "plane-1", from)}, &decl, from, to, 0)
	if len(gaps) != 1 || gaps[0] != (api.SectionGap{From: from, To: to, Reason: api.GapPlacementSilent}) {
		t.Fatalf("zero reporting bound must gap the whole window, got %+v", gaps)
	}
}

// TestSilenceGapsDeclaredButNeverReported is AC5's offline shape: a pinning
// in force and not one report in the range — the whole obligation window is
// silent, never complete.
func TestSilenceGapsDeclaredButNeverReported(t *testing.T) {
	from, to := evidenceNow, evidenceNow.Add(24*time.Hour)
	decl := pinningAt(from.Add(-time.Hour))
	gaps := SilenceGaps(nil, &decl, from, to, time.Hour)
	if len(gaps) != 1 || gaps[0] != (api.SectionGap{From: from, To: to, Reason: api.GapPlacementSilent}) {
		t.Fatalf("a declared tenant with zero reports must gap the whole window, got %+v", gaps)
	}
}

// TestSilenceGapsCoveredRangeIsComplete: reports inside the bound from the
// window's start until past its end leave no gap — the complete shape.
func TestSilenceGapsCoveredRangeIsComplete(t *testing.T) {
	from, to := evidenceNow, evidenceNow.Add(3*time.Hour)
	decl := pinningAt(from.Add(-time.Hour))
	recs := []api.SectionRecord{
		sectionFact(1, api.ResidencyFactPlacement, "plane-1", from),
		sectionFact(2, api.ResidencyFactPlacement, "plane-1", from.Add(time.Hour)),
		sectionFact(3, api.ResidencyFactPlacement, "plane-1", from.Add(2*time.Hour)),
	}
	gaps := SilenceGaps(recs, &decl, from, to, time.Hour)
	if len(gaps) != 0 {
		t.Fatalf("hourly reports under a one-hour bound cover the range, got %+v", gaps)
	}
}

// TestSilenceGapsOfflineIntervalIsAGap is AC5 itself: a plane that reported,
// then went silent past the bound, then came back — the silent interval is a
// gap with PLACEMENT_SILENT, and the tail past the last report's deadline is
// one too.
func TestSilenceGapsOfflineIntervalIsAGap(t *testing.T) {
	from, to := evidenceNow, evidenceNow.Add(7*time.Hour)
	decl := pinningAt(from.Add(-time.Hour))
	recs := []api.SectionRecord{
		sectionFact(1, api.ResidencyFactPlacement, "plane-1", from),
		// plane-1 silent from from+1h (its deadline) until from+5h.
		sectionFact(2, api.ResidencyFactPlacement, "plane-1", from.Add(5*time.Hour)),
	}
	gaps := SilenceGaps(recs, &decl, from, to, time.Hour)
	want := []api.SectionGap{
		{From: from.Add(time.Hour), To: from.Add(5 * time.Hour), Reason: api.GapPlacementSilent},
		{From: from.Add(6 * time.Hour), To: to, Reason: api.GapPlacementSilent},
	}
	if len(gaps) != len(want) {
		t.Fatalf("gaps = %+v, want %+v", gaps, want)
	}
	for i := range want {
		if gaps[i] != want[i] {
			t.Fatalf("gap[%d] = %+v, want %+v", i, gaps[i], want[i])
		}
	}
}

// TestSilenceGapsWindowOpensAtDeclaration: a pinning taking effect INSIDE the
// range opens the obligation window at its effective time — the instants
// before it had no residency to be silent about (AC1, AC5, AC6 together).
func TestSilenceGapsWindowOpensAtDeclaration(t *testing.T) {
	from, to := evidenceNow, evidenceNow.Add(4*time.Hour)
	decl := pinningAt(from.Add(2 * time.Hour))
	gaps := SilenceGaps(nil, &decl, from, to, time.Hour)
	if len(gaps) != 1 || gaps[0] != (api.SectionGap{From: from.Add(2 * time.Hour), To: to, Reason: api.GapPlacementSilent}) {
		t.Fatalf("the window must open at the declaration's effective time, got %+v", gaps)
	}
}

// TestSilenceGapsPerPlaneAreDeterministic: two planes silent in different
// shapes render plane-ordered gaps — assembly is deterministic across runs.
func TestSilenceGapsPerPlaneAreDeterministic(t *testing.T) {
	from, to := evidenceNow, evidenceNow.Add(2*time.Hour)
	decl := pinningAt(from.Add(-time.Hour))
	recs := []api.SectionRecord{
		sectionFact(1, api.ResidencyFactPlacement, "plane-b", from),
		sectionFact(2, api.ResidencyFactPlacement, "plane-a", from.Add(time.Hour)),
	}
	gaps := SilenceGaps(recs, &decl, from, to, 30*time.Minute)
	// plane-a: silent [from, from+1h], covered to from+1:30, tail gap [from+1:30, to].
	// plane-b: covered to from+30m, tail gap [from+30m, to].
	want := []api.SectionGap{
		{From: from, To: from.Add(time.Hour), Reason: api.GapPlacementSilent},
		{From: from.Add(90 * time.Minute), To: to, Reason: api.GapPlacementSilent},
		{From: from.Add(30 * time.Minute), To: to, Reason: api.GapPlacementSilent},
	}
	if len(gaps) != len(want) {
		t.Fatalf("gaps = %+v, want %+v", gaps, want)
	}
	for i := range want {
		if gaps[i] != want[i] {
			t.Fatalf("gap[%d] = %+v, want %+v", i, gaps[i], want[i])
		}
	}
}
