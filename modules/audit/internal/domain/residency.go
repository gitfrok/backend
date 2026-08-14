// Residency evidence — the pure computation behind the evidence pack's
// residency section (T-0033, SPEC-0040): classifying the Residency context's
// witnessed facts and computing the AC5 silence gaps from them.
//
// Everything here is a function of classified records and configuration —
// placement facts are what the control plane observed (the CP-owned registry
// feeding the Residency context's witness), never customer claims (SPEC-0040
// AC7): there is no input shape here a customer attestation could enter.
package domain

import (
	"slices"
	"time"

	"github.com/gitfrok/backend/modules/audit/api"
)

// residencyFactKindOf maps the residency action vocabulary to the section's
// fact kinds. The action set is closed; an unknown action is a defect the
// caller prevented by classifying with Classify, and maps to the zero kind.
func residencyFactKindOf(action api.Action) api.ResidencyFactKind {
	switch string(action) {
	case actionResidencyDeclarationSet:
		return api.ResidencyFactPinning
	case actionResidencyPlacementObserved:
		return api.ResidencyFactPlacement
	case actionResidencyPlacementRefused:
		return api.ResidencyFactPlacementRefused
	case actionResidencyPlacementContradicted:
		return api.ResidencyFactPlacementContradiction
	default:
		return ""
	}
}

// LastDeclarationBefore returns the residency section's latest PINNING record
// strictly before at, if any: the declaration in force at that instant.
// declarations must be classified residency records in chain-sequence order
// — the trail query's job. A change is a later PINNING record with its own
// effective time, so "in force" is always the latest pinning before the
// instant asked about (SPEC-0040 AC6).
func LastDeclarationBefore(declarations []api.SectionRecord, at time.Time) (api.SectionRecord, bool) {
	for i := len(declarations) - 1; i >= 0; i-- {
		if declarations[i].Residency != nil &&
			declarations[i].Residency.FactKind == api.ResidencyFactPinning &&
			declarations[i].OccurredAt.Before(at) {
			return declarations[i], true
		}
	}
	return api.SectionRecord{}, false
}

// SilenceGaps computes the residency section's AC5 gaps (SPEC-0040): silence
// renders as a gap, never as compliance — absence of contradiction is not
// evidence of pinning.
//
// records are the section's classified records over the range (any order);
// declarationInForce is the declaration in force at rangeFrom, when one
// existed; maxInterval is the configured maximum placement-reporting interval.
//
// The shapes:
//
//   - No declaration in force at any point of the range (nil): placement was
//     unconstrained, so silence is not an evidence gap — no gaps.
//   - A declaration in force but a non-positive maxInterval: the assembler
//     cannot bound a silent interval honestly, so the whole obligation window
//     is one gap (fail-safe, like every zero-valued bound in this module).
//   - A data plane with no PLACEMENT observation in the range: silent for the
//     whole obligation window — one gap covering it.
//   - A data plane with observations o1..on: a gap [windowStart, o1] when the
//     window opens before the first report; a gap [oi+maxInterval, oi+1] for
//     every interval exceeding maxInterval; a gap [on+maxInterval, rangeTo]
//     when the last report's deadline falls inside the range.
//
// Refusals and contradictions count as reporting — they are control-plane
// observations of the plane — but PLACEMENT records alone bound the silence
// intervals, so a plane that only ever refused still shows admitted-placement
// silence honestly. The obligation window starts at rangeFrom, or at the
// declaration's effective time when the declaration only took effect inside
// the range: earlier instants had no pinning to be silent about.
//
// Gaps are deterministic: ordered by data plane ID, then by From.
func SilenceGaps(records []api.SectionRecord, declarationInForce *api.SectionRecord,
	from, to time.Time, maxInterval time.Duration) []api.SectionGap {
	if declarationInForce == nil {
		return nil
	}
	windowStart := from
	if declarationInForce.OccurredAt.After(from) {
		windowStart = declarationInForce.OccurredAt
	}
	if windowStart.After(to) {
		return nil
	}
	if maxInterval <= 0 {
		// Fail-safe: without a configured reporting bound the assembler
		// cannot say any interval was covered, so the whole window is a gap.
		return []api.SectionGap{{From: windowStart, To: to, Reason: api.GapPlacementSilent}}
	}

	// Per-plane report instants: admitted observations, refusals and
	// contradictions alike are proof the plane reported to the control plane.
	reported := map[string][]time.Time{}
	for _, r := range records {
		if r.Residency == nil || r.Residency.FactKind == api.ResidencyFactPinning || r.Residency.DataPlaneID == "" {
			continue
		}
		reported[r.Residency.DataPlaneID] = append(reported[r.Residency.DataPlaneID], r.OccurredAt)
	}
	if len(reported) == 0 {
		// Declared, and not one plane reported inside the range: the whole
		// obligation window is silent.
		return []api.SectionGap{{From: windowStart, To: to, Reason: api.GapPlacementSilent}}
	}

	planes := make([]string, 0, len(reported))
	for id := range reported {
		planes = append(planes, id)
	}
	slices.Sort(planes)

	var gaps []api.SectionGap
	for _, id := range planes {
		times := reported[id]
		slices.SortFunc(times, func(a, b time.Time) int {
			if a.Before(b) {
				return -1
			}
			if a.After(b) {
				return 1
			}
			return 0
		})
		if windowStart.Before(times[0]) {
			gaps = append(gaps, api.SectionGap{From: windowStart, To: times[0], Reason: api.GapPlacementSilent})
		}
		for i := 1; i < len(times); i++ {
			if times[i].Sub(times[i-1]) > maxInterval {
				gaps = append(gaps, api.SectionGap{
					From: times[i-1].Add(maxInterval), To: times[i], Reason: api.GapPlacementSilent,
				})
			}
		}
		// A report due exactly at the range's end is covered to the end: a
		// tail gap opens only when the deadline falls inside the range.
		if deadline := times[len(times)-1].Add(maxInterval); deadline.Before(to) {
			gaps = append(gaps, api.SectionGap{From: deadline, To: to, Reason: api.GapPlacementSilent})
		}
	}
	return gaps
}
