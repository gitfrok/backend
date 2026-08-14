package domain

import (
	"testing"
	"time"

	"github.com/gitfrok/backend/modules/metering/api"
)

var t0 = time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)

func sample(msgID, plane string, win api.Interval, counters, gauges map[string]float64) Sample {
	return Sample{MessageID: msgID, DataPlaneID: plane, Window: win, ReceivedAt: win.End, Counters: counters, Gauges: gauges}
}

func win(offsetMin, lengthMin int) api.Interval {
	return api.Interval{Start: t0.Add(time.Duration(offsetMin) * time.Minute), End: t0.Add(time.Duration(offsetMin+lengthMin) * time.Minute)}
}

// Counter derivation is the delta between consecutive cumulative totals: the
// interval's usage is how far the counter moved (ADR-0061 §1).
func TestDeriveCounterDelta(t *testing.T) {
	samples := []Sample{
		sample("m1", "dp-1", win(0, 5), map[string]float64{MetricCIMinutes: 10}, nil),
		sample("m2", "dp-1", win(5, 5), map[string]float64{MetricCIMinutes: 42}, nil),
	}
	value, window, ok := DeriveValue(api.DimensionCIMinutes, samples)
	if !ok || value != 32 {
		t.Fatalf("derive ci_minutes = %v, %v; want 32, ok", value, ok)
	}
	// The boundary is the RECORDED one: first sample's start to last end.
	if !window.Start.Equal(t0) || !window.End.Equal(t0.Add(10*time.Minute)) {
		t.Fatalf("window = %v; want the recorded [t0, t0+10m)", window)
	}
}

// A counter reset moves the baseline without producing negative or invented
// usage.
func TestDeriveCounterReset(t *testing.T) {
	samples := []Sample{
		sample("m1", "dp-1", win(0, 5), map[string]float64{MetricEgressBytes: 100}, nil),
		sample("m2", "dp-1", win(5, 5), map[string]float64{MetricEgressBytes: 10}, nil),
		sample("m3", "dp-1", win(10, 5), map[string]float64{MetricEgressBytes: 30}, nil),
	}
	value, _, ok := DeriveValue(api.DimensionEgress, samples)
	if !ok || value != 20 {
		t.Fatalf("derive egress = %v, %v; want 20, ok (reset adds nothing)", value, ok)
	}
}

// Gauges: repository count takes the latest report, CI concurrency the peak.
func TestDeriveGauges(t *testing.T) {
	samples := []Sample{
		sample("m1", "dp-1", win(0, 5), nil, map[string]float64{MetricRepositories: 7, MetricCIConcurrency: 3}),
		sample("m2", "dp-1", win(5, 5), nil, map[string]float64{MetricRepositories: 9, MetricCIConcurrency: 6}),
		sample("m3", "dp-1", win(10, 5), nil, map[string]float64{MetricRepositories: 8, MetricCIConcurrency: 4}),
	}
	repos, _, ok := DeriveValue(api.DimensionRepositoryCount, samples)
	if !ok || repos != 8 {
		t.Fatalf("repository_count = %v, %v; want 8 (latest), ok", repos, ok)
	}
	peak, _, ok := DeriveValue(api.DimensionCIConcurrency, samples)
	if !ok || peak != 6 {
		t.Fatalf("ci_concurrency = %v, %v; want 6 (peak), ok", peak, ok)
	}
}

// Absence of samples is absence of a value, never a zero (SPEC-0041 AC3):
// the derivation says "no data" and the caller renders a gap.
func TestDeriveNoSamplesIsNotZero(t *testing.T) {
	if _, _, ok := DeriveValue(api.DimensionCIMinutes, nil); ok {
		t.Fatal("derivation with no samples must report no value, not zero")
	}
	// A dimension that carries no metric at all (a gauge sample for a
	// counter dimension) is likewise no-data.
	samples := []Sample{sample("m1", "dp-1", win(0, 5), nil, map[string]float64{MetricRepositories: 1})}
	if _, _, ok := DeriveValue(api.DimensionCIMinutes, samples); ok {
		t.Fatal("a dimension no sample carries must report no value")
	}
}

// A deferred dimension has no derivation by construction (SPEC-0041 AC2).
func TestDeferredDimensionsAreNotDerivable(t *testing.T) {
	for _, d := range []api.Dimension{api.DimensionSeats, api.DimensionRepositoryStorage, api.DimensionIndexSize} {
		if api.Phase3Coverage[d] != api.CoverageDeferred {
			t.Fatalf("%v must be deferred in Phase 3", d)
		}
		if _, _, ok := MetricFor(d); ok {
			t.Fatalf("%v is deferred: it must have no metric to derive from", d)
		}
	}
}

// Gap rendering (SPEC-0041 AC3): a plane silent past GapAfter yields a gap
// starting at its last RECORDED window end. A plane that just reported has
// none.
func TestGapForSilentDataPlane(t *testing.T) {
	samples := []Sample{sample("m1", "dp-1", win(0, 5), map[string]float64{MetricCIMinutes: 5}, nil)}
	now := t0.Add(5 * time.Minute)

	if _, gap := GapFor(samples, "dp-1", now, time.Minute); gap {
		t.Fatal("a plane that just reported has no gap")
	}

	silentAt := t0.Add(35 * time.Minute)
	g, gap := GapFor(samples, "dp-1", silentAt, 10*time.Minute)
	if !gap {
		t.Fatal("a plane silent past GapAfter must render a gap")
	}
	if !g.Start.Equal(t0.Add(5*time.Minute)) || !g.End.Equal(silentAt) {
		t.Fatalf("gap = %v; want [last recorded end, now)", g)
	}
}

// Restart semantics (SPEC-0041 non-functional): derivation is a pure
// function of the recorded samples, so re-deriving from the same records —
// including replays of samples already recorded — neither double-counts nor
// loses an interval. The store's message-ID dedup is what keeps the record
// set itself free of duplicates; this test pins the derivation half.
func TestRestartRederivationIsStable(t *testing.T) {
	samples := []Sample{
		sample("m1", "dp-1", win(0, 5), map[string]float64{MetricCIMinutes: 10}, nil),
		sample("m2", "dp-1", win(5, 5), map[string]float64{MetricCIMinutes: 42}, nil),
	}
	before, w1, _ := DeriveValue(api.DimensionCIMinutes, samples)

	// "Restart": derive again from the same records, in a shuffled order,
	// with a replayed duplicate appended (what an at-least-once redelivery
	// after restart would hand the store before dedup).
	replayed := []Sample{samples[1], samples[0], samples[1]}
	after, w2, _ := DeriveValue(api.DimensionCIMinutes, replayed)

	if before != after {
		t.Fatalf("re-derivation changed the counter: %v -> %v (double-count or lost interval)", before, after)
	}
	if w1 != w2 {
		t.Fatalf("re-derivation moved the recorded boundary: %v -> %v", w1, w2)
	}
}

// Trend comparison reads only the samples strictly before the current
// window; an unknown past is reported as such, never invented.
func TestPreviousValue(t *testing.T) {
	samples := []Sample{
		sample("m1", "dp-1", win(0, 5), map[string]float64{MetricCIMinutes: 10}, nil),
		sample("m2", "dp-1", win(5, 5), map[string]float64{MetricCIMinutes: 40}, nil),
	}
	current := api.Interval{Start: t0.Add(5 * time.Minute), End: t0.Add(10 * time.Minute)}
	prev, ok := PreviousValue(api.DimensionCIMinutes, samples, current)
	if !ok {
		t.Fatal("the earlier interval has data; PreviousValue must find it")
	}
	if prev != 0 {
		// A single earlier cumulative sample establishes a baseline; its
		// delta is zero. The point under test is that the comparison exists
		// and is recorded-window bounded.
		t.Fatalf("previous = %v; want the earlier interval's derivation", prev)
	}
	if _, ok := PreviousValue(api.DimensionCIMinutes, samples[1:], current); ok {
		t.Fatal("no earlier data: PreviousValue must say so, not invent a value")
	}
}
