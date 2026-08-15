// Package domain is the Metering context's inner layer: the pure derivation
// of authoritative counters from received telemetry (ADR-0061 §1). It imports
// no infrastructure (invariant 16) and holds no transport or store concerns:
// a ledger is a function of the samples the channel delivered, which is what
// makes a control-plane restart a re-derivation rather than a risk of
// double-counting (SPEC-0041 non-functional).
package domain

import (
	"slices"
	"time"

	"github.com/gitfrok/backend/modules/metering/api"
)

// Metric names the telemetry metric each metered dimension derives from.
// The vocabulary is the contract between the data plane's TelemetrySample
// gauges/counters and the control plane's derivation; a dimension with no
// metric is not derivable and is deferred instead (ADR-0061 §1).
const (
	MetricCIMinutes     = "ci_job_minutes_total" // cumulative counter
	MetricEgressBytes   = "egress_bytes_total"   // cumulative counter
	MetricScanBytes     = "scan_bytes_total"     // cumulative counter
	MetricRepositories  = "repositories_active"  // gauge, latest wins
	MetricCIConcurrency = "ci_runners_active"    // gauge, peak wins
)

// MetricKind is how a metric's samples combine into one interval value.
type MetricKind int

const (
	// KindCounterDelta sums the deltas between consecutive cumulative totals:
	// the interval's usage is how far the counter moved, not the total.
	KindCounterDelta MetricKind = iota
	// KindGaugeLatest takes the last reported gauge in the window.
	KindGaugeLatest
	// KindGaugePeak takes the maximum reported gauge in the window.
	KindGaugePeak
)

// MetricFor names the metric and combination a dimension derives from. The
// second result is false for every dimension Phase 3 defers: a deferred
// dimension has no derivation by construction (SPEC-0041 AC2).
func MetricFor(d api.Dimension) (metric string, kind MetricKind, ok bool) {
	switch d {
	case api.DimensionCIMinutes:
		return MetricCIMinutes, KindCounterDelta, true
	case api.DimensionEgress:
		return MetricEgressBytes, KindCounterDelta, true
	case api.DimensionScanVolume:
		return MetricScanBytes, KindCounterDelta, true
	case api.DimensionRepositoryCount:
		return MetricRepositories, KindGaugeLatest, true
	case api.DimensionCIConcurrency:
		return MetricCIConcurrency, KindGaugePeak, true
	default:
		return "", 0, false
	}
}

// Sample is one received TelemetrySample as the store records it: identity,
// the RECORDED window boundaries the data plane declared, and the values.
type Sample struct {
	MessageID   string
	DataPlaneID string
	Window      api.Interval
	ReceivedAt  time.Time
	Gauges      map[string]float64
	Counters    map[string]float64
}

// UsageReport is one received UsageSample as the store records it: the data
// plane's own totals, kept for the divergence comparison and nothing else
// (ADR-0061 §2).
type UsageReport struct {
	MessageID   string
	DataPlaneID string
	Window      api.Interval
	ReceivedAt  time.Time
	Reported    map[api.Dimension]float64
}

// sortSamples orders samples by their RECORDED window end, then receive
// time: derivation follows the order the telemetry declares, not arrival
// jitter.
func sortSamples(in []Sample) []Sample {
	out := slices.Clone(in)
	slices.SortFunc(out, func(a, b Sample) int {
		if !a.Window.End.Equal(b.Window.End) {
			return a.Window.End.Compare(b.Window.End)
		}
		return a.ReceivedAt.Compare(b.ReceivedAt)
	})
	return out
}

// DeriveValue computes one dimension's authoritative value from the samples a
// tenant's data planes delivered. The returned interval is the one the
// derivation actually used — the first contributing sample's window start to
// the last's window end — so the boundary is recorded, never inferred
// (SPEC-0041 non-functional). ok is false when no sample carries the
// metric: absence of samples is absence of a value, never a zero (AC3).
func DeriveValue(d api.Dimension, samples []Sample) (value float64, window api.Interval, ok bool) {
	metric, kind, derivable := MetricFor(d)
	if !derivable {
		return 0, api.Interval{}, false
	}
	ordered := sortSamples(samples)

	var contributing []Sample
	for _, s := range ordered {
		if kind == KindCounterDelta {
			if _, has := s.Counters[metric]; has {
				contributing = append(contributing, s)
			}
		} else {
			if _, has := s.Gauges[metric]; has {
				contributing = append(contributing, s)
			}
		}
	}
	if len(contributing) == 0 {
		return 0, api.Interval{}, false
	}

	window = api.Interval{Start: contributing[0].Window.Start, End: contributing[len(contributing)-1].Window.End}
	// A tenant aggregate is a sum of PER-PLANE derivations (SPEC-0045 AC4):
	// interleaving two planes' cumulative totals into one delta chain makes
	// the second plane's baseline read as a counter reset of the first, and
	// silently halves the aggregate. Deriving each plane on its own and
	// summing keeps every plane's telemetry authoritative for itself while
	// the envelope sees the tenant's whole.
	var planes []string
	seen := map[string]bool{}
	for _, s := range contributing {
		if !seen[s.DataPlaneID] {
			seen[s.DataPlaneID] = true
			planes = append(planes, s.DataPlaneID)
		}
	}
	for _, plane := range planes {
		value += derivePlane(kind, metric, contributing, plane)
	}
	return value, window, true
}

// derivePlane derives one dimension over one data plane's contributing
// samples: the combination rules of MetricKind applied to a single counter
// stream, so a reset on one plane never reads as a movement on another.
func derivePlane(kind MetricKind, metric string, contributing []Sample, dataPlaneID string) float64 {
	switch kind {
	case KindCounterDelta:
		// The interval's usage is how far the cumulative counter moved. A
		// total that moves BACKWARDS is a reset on the data plane: the new
		// baseline is accepted and contributes nothing, never a negative
		// usage and never an inferred catch-up.
		var value, prev float64
		first := true
		for _, s := range contributing {
			if s.DataPlaneID != dataPlaneID {
				continue
			}
			total := s.Counters[metric]
			if first {
				prev, first = total, false
				continue
			}
			if total > prev {
				value += total - prev
			}
			prev = total
		}
		return value
	case KindGaugeLatest:
		var value float64
		for _, s := range contributing {
			if s.DataPlaneID == dataPlaneID {
				value = s.Gauges[metric] // ordered: the last one wins
			}
		}
		return value
	case KindGaugePeak:
		var value float64
		for _, s := range contributing {
			if s.DataPlaneID == dataPlaneID {
				if g := s.Gauges[metric]; g > value {
					value = g
				}
			}
		}
		return value
	}
	return 0
}

// PreviousValue derives the same dimension over the samples strictly BEFORE
// the current window's start — the comparison a trend cites (SPEC-0041 AC4).
// ok is false when the earlier interval has no data: an unknown past yields
// a flat trend, never an invented one.
func PreviousValue(d api.Dimension, samples []Sample, current api.Interval) (value float64, ok bool) {
	var earlier []Sample
	for _, s := range samples {
		if !s.Window.End.After(current.Start) {
			earlier = append(earlier, s)
		}
	}
	v, _, derived := DeriveValue(d, earlier)
	return v, derived
}

// LastWindowEnd is the newest RECORDED window end across a data plane's
// samples. ok is false for a plane that never delivered telemetry.
func LastWindowEnd(samples []Sample, dataPlaneID string) (time.Time, bool) {
	var end time.Time
	var seen bool
	for _, s := range samples {
		if s.DataPlaneID != dataPlaneID {
			continue
		}
		if !seen || s.Window.End.After(end) {
			end, seen = s.Window.End, true
		}
	}
	return end, seen
}

// GapFor renders the gap a silent data plane produces (SPEC-0041 AC3): when
// now is more than gapAfter past the plane's last RECORDED window end, the
// interval from that recorded boundary to now is a gap. The gap's start is
// the recorded boundary — absence of events is never rendered as absence of
// usage, and never as zero (the SPEC-0031 AC10 rule precedent).
func GapFor(samples []Sample, dataPlaneID string, now time.Time, gapAfter time.Duration) (api.Interval, bool) {
	end, seen := LastWindowEnd(samples, dataPlaneID)
	if !seen {
		return api.Interval{}, false
	}
	if now.Sub(end) < gapAfter {
		return api.Interval{}, false
	}
	return api.Interval{Start: end, End: now}, true
}
