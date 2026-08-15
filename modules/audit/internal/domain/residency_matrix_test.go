// The contradiction/gap matrix (T-0039, SPEC-0043 AC2 + AC3): the four placement
// scenarios — declared-matches, declared-contradicts, placement-silent-within-window,
// placement-silent-beyond-window — each rendered pinned to ONE vocabulary: the pack
// section's ResidencyFactKind facts and its GAP_REASON_PLACEMENT_SILENT gaps, the same
// vocabulary any health view reads (no parallel error channel, no inferred placement).
package domain

import (
	"testing"
	"time"

	"github.com/gitfrok/backend/modules/audit/api"
)

// matrixNow anchors the matrix's instants; residencyRecord staggers OccurredAt one hour
// per chain position, so seq 0 is the anchor's hour.
var matrixNow = evidenceNow

// matrixDetail carries both placements a residency record names — pinned (the declaration
// in force) and observed (the placement reported or attempted), exactly as the witness
// writes them (SPEC-0040 AC2).
func matrixDetail(pinnedCloud, pinnedRegion, observedCloud, observedRegion string) map[string]string {
	d := map[string]string{
		"pinned_cloud": pinnedCloud, "pinned_region": pinnedRegion,
	}
	if observedCloud != "" {
		d["observed_cloud"] = observedCloud
		d["observed_region"] = observedRegion
	}
	return d
}

// classifyResidency classifies one witnessed record and fails the test unless it lands in
// the residency section with the wanted fact kind — the matrix's rendering assertion.
func classifyResidency(t *testing.T, rec api.Record, wantKind api.ResidencyFactKind) api.SectionRecord {
	t.Helper()
	sr, section, ok := Classify(rec)
	if !ok || section != api.SectionResidency || sr.Residency == nil {
		t.Fatalf("%s must classify into the residency section, got ok=%v section=%v", rec.Action, ok, section)
	}
	if sr.Residency.FactKind != wantKind {
		t.Fatalf("%s renders as %v, want %v", rec.Action, sr.Residency.FactKind, wantKind)
	}
	return sr
}

// TestMatrixDeclaredMatches is scenario 1: the declaration and the witnessed placement
// agree — the section cites a PINNING act and a PLACEMENT observation, no contradiction,
// and a fully-covered range carries no gap (AC2's positive half).
func TestMatrixDeclaredMatches(t *testing.T) {
	pinning := classifyResidency(t, residencyRecord(0, actionResidencyDeclarationSet,
		"tenant/tenant-a", api.OutcomeAllowed,
		matrixDetail("gke", "europe-west1", "", "")), api.ResidencyFactPinning)
	placement := classifyResidency(t, residencyRecord(1, actionResidencyPlacementObserved,
		"data_plane/plane-1", api.OutcomeAllowed,
		matrixDetail("gke", "europe-west1", "gke", "europe-west1")), api.ResidencyFactPlacement)
	if !placement.Allowed {
		t.Fatal("an admitted placement cites allowed=true — the witnessed outcome")
	}

	// The range opens at the report: a fully-covered range carries no gap.
	from, to := matrixNow.Add(time.Hour), matrixNow.Add(2*time.Hour)
	gaps := SilenceGaps([]api.SectionRecord{placement}, &pinning, from, to, 24*time.Hour)
	if len(gaps) != 0 {
		t.Fatalf("a covered range renders no gaps, got %+v", gaps)
	}
}

// TestMatrixDeclaredContradicts is scenario 2: the witnessed placement contradicts the
// declaration — the refusal AND the raised violation state both render as control-plane
// OBSERVATIONS (PLACEMENT_REFUSED, PLACEMENT_CONTRADICTION), cited denied, each naming
// both placements; the PINNING act stays a control-plane act of its own kind (AC2).
func TestMatrixDeclaredContradicts(t *testing.T) {
	pinning := classifyResidency(t, residencyRecord(0, actionResidencyDeclarationSet,
		"tenant/tenant-a", api.OutcomeAllowed,
		matrixDetail("gke", "europe-west1", "", "")), api.ResidencyFactPinning)
	refused := classifyResidency(t, residencyRecord(1, actionResidencyPlacementRefused,
		"data_plane/plane-1", api.OutcomeDenied,
		matrixDetail("gke", "europe-west1", "aws", "us-east1")), api.ResidencyFactPlacementRefused)
	contradiction := classifyResidency(t, residencyRecord(2, actionResidencyPlacementContradicted,
		"data_plane/plane-1", api.OutcomeDenied,
		matrixDetail("gke", "europe-west1", "aws", "us-east1")), api.ResidencyFactPlacementContradiction)

	for _, sr := range []api.SectionRecord{refused, contradiction} {
		if sr.Allowed {
			t.Fatalf("%v must cite the witnessed denial", sr.Residency.FactKind)
		}
		if sr.Residency.PinnedCloud != "gke" || sr.Residency.ObservedCloud != "aws" {
			t.Fatalf("%v names BOTH placements: %+v", sr.Residency.FactKind, sr.Residency)
		}
	}
	// Refusals and contradictions are reports — they bound the silence interval, so a
	// contradicting plane is not additionally rendered silent (no double jeopardy).
	from, to := matrixNow.Add(time.Hour), matrixNow.Add(3*time.Hour)
	gaps := SilenceGaps([]api.SectionRecord{refused, contradiction}, &pinning, from, to, 24*time.Hour)
	if len(gaps) != 0 {
		t.Fatalf("a reporting (contradicted) plane renders no silence gap, got %+v", gaps)
	}
}

// TestMatrixPlacementSilentWithinWindow is scenario 3: a declared plane last reported
// inside the configured window — the range renders COMPLETE: silence within the bound is
// not yet an evidence gap (AC3's negative half; the window is configuration, never a
// compiled-in constant).
func TestMatrixPlacementSilentWithinWindow(t *testing.T) {
	pinning := classifyResidency(t, residencyRecord(0, actionResidencyDeclarationSet,
		"tenant/tenant-a", api.OutcomeAllowed,
		matrixDetail("gke", "europe-west1", "", "")), api.ResidencyFactPinning)
	placement := classifyResidency(t, residencyRecord(1, actionResidencyPlacementObserved,
		"data_plane/plane-1", api.OutcomeAllowed,
		matrixDetail("gke", "europe-west1", "gke", "europe-west1")), api.ResidencyFactPlacement)

	// Last report at matrixNow+1h with a 24h bound: a range opening at the report and
	// ending before the deadline is fully covered.
	from, to := matrixNow.Add(time.Hour), matrixNow.Add(2*time.Hour)
	gaps := SilenceGaps([]api.SectionRecord{placement}, &pinning, from, to, 24*time.Hour)
	if len(gaps) != 0 {
		t.Fatalf("silence inside the reporting window is no gap, got %+v", gaps)
	}
}

// TestMatrixPlacementSilentBeyondWindow is scenario 4: a declared plane whose last
// report's deadline falls inside the range — the silent tail renders as exactly one
// GAP_REASON_PLACEMENT_SILENT gap, never as an inferred placement or as compliance
// (AC3, SPEC-0040 AC5).
func TestMatrixPlacementSilentBeyondWindow(t *testing.T) {
	pinning := classifyResidency(t, residencyRecord(0, actionResidencyDeclarationSet,
		"tenant/tenant-a", api.OutcomeAllowed,
		matrixDetail("gke", "europe-west1", "", "")), api.ResidencyFactPinning)
	placement := classifyResidency(t, residencyRecord(1, actionResidencyPlacementObserved,
		"data_plane/plane-1", api.OutcomeAllowed,
		matrixDetail("gke", "europe-west1", "gke", "europe-west1")), api.ResidencyFactPlacement)

	// Last report at matrixNow+1h with a 30m bound: the deadline (matrixNow+1h30m)
	// falls inside the range, so the tail is one named gap.
	from, to := matrixNow.Add(time.Hour), matrixNow.Add(3*time.Hour)
	gaps := SilenceGaps([]api.SectionRecord{placement}, &pinning, from, to, 30*time.Minute)
	want := []api.SectionGap{{
		From:   placement.OccurredAt.Add(30 * time.Minute),
		To:     to,
		Reason: api.GapPlacementSilent,
	}}
	if len(gaps) != 1 || gaps[0] != want[0] {
		t.Fatalf("silence beyond the window = %+v, want exactly %+v", gaps, want)
	}
}
