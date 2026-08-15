// SPEC-0045 AC4 against the metering authority (T-0041): a multi-plane tenant
// is metered per plane with envelopes computed on the tenant's AGGREGATE — no
// plane can under-report itself into a smaller envelope, and a silent plane's
// gap renders as a gap, not as zero. ADR-0061's authority rules are unchanged:
// the control plane counts from telemetry RECEIVED; the plane's own report is
// operational input only.
package app_test

import (
	"context"
	"testing"
	"time"

	"github.com/gitfrok/backend/modules/metering/api"
)

// TestAC4_EnvelopeComputedOnTenantAggregate proves the envelope sees the
// tenant's whole: two planes of one tenant each move their CI-minutes counter
// in the SAME window, and the derived value is the SUM of both movements —
// even when the planes' samples arrive interleaved. (An interleaved delta
// chain would read the second plane's baseline as a reset of the first and
// silently halve the aggregate — the exact under-report AC4 forbids, only
// caused by the derivation instead of the plane.)
func TestAC4_EnvelopeComputedOnTenantAggregate(t *testing.T) {
	f := newFixture(t, ciThresholds())
	w := window(f.now.Add(-time.Hour), f.now)

	// Interleaved arrival: baseline of plane-1, baseline of plane-2, then
	// both finals. The aggregate must still be 45 + 45.
	ingest(t, f.svc, "acme", "plane-1", sampleWithCounter("s1", "plane-1", w, 0))
	ingest(t, f.svc, "acme", "plane-2", sampleWithCounter("s2", "plane-2", w, 0))
	ingest(t, f.svc, "acme", "plane-1", sampleWithCounter("s3", "plane-1", w, 45))
	ingest(t, f.svc, "acme", "plane-2", sampleWithCounter("s4", "plane-2", w, 45))

	view, err := f.svc.UsageView(context.Background(), "acme")
	if err != nil {
		t.Fatalf("UsageView: %v", err)
	}
	var ci api.DimensionView
	for _, row := range view.Dimensions {
		if row.Dimension == api.DimensionCIMinutes {
			ci = row
		}
	}
	if ci.Value != 90 {
		t.Fatalf("aggregate CI minutes = %v, want 90 (45 per plane, summed)", ci.Value)
	}
	// 90 crosses the notification threshold (80) but not the envelope (100):
	// the decision is made on the AGGREGATE, not on either plane's 45 alone.
	if ci.State != api.StateNear {
		t.Fatalf("envelope state on aggregate 90 = %v, want NEAR", ci.State)
	}
}

// TestAC4_PlaneCannotUnderReportIntoSmallerEnvelope proves the escape route
// closed: a plane's self-reported total below the control plane's aggregate
// never shrinks the envelope value. The counter stays the aggregate, the
// breach stands, and the low self-report surfaces as a divergence health
// finding carrying both numbers (ADR-0061 §2).
func TestAC4_PlaneCannotUnderReportIntoSmallerEnvelope(t *testing.T) {
	f := newFixture(t, ciThresholds())
	ctx := context.Background()
	w := window(f.now.Add(-time.Hour), f.now)

	// Control plane sees 60 + 60 = 120 CI minutes — past the envelope (100).
	ingest(t, f.svc, "acme", "plane-1", sampleWithCounter("s1", "plane-1", w, 0))
	ingest(t, f.svc, "acme", "plane-1", sampleWithCounter("s2", "plane-1", w, 60))
	ingest(t, f.svc, "acme", "plane-2", sampleWithCounter("s3", "plane-2", w, 0))
	ingest(t, f.svc, "acme", "plane-2", sampleWithCounter("s4", "plane-2", w, 60))

	// plane-2 claims 10: far below its own derived 60, and an attempt to
	// read the tenant small. The control plane ignores it for the counter.
	if err := f.svc.IngestUsage(ctx, "acme", "plane-2", api.Usage{MessageID: "u1", Window: w, CIMinutes: 10}); err != nil {
		t.Fatalf("IngestUsage: %v", err)
	}

	view, err := f.svc.UsageView(ctx, "acme")
	if err != nil {
		t.Fatalf("UsageView: %v", err)
	}
	var ci api.DimensionView
	for _, row := range view.Dimensions {
		if row.Dimension == api.DimensionCIMinutes {
			ci = row
		}
	}
	if ci.Value != 120 {
		t.Fatalf("aggregate after under-report = %v, want 120 — the self-report must not shrink the counter", ci.Value)
	}
	if ci.State != api.StateExceeded {
		t.Fatalf("envelope state = %v, want EXCEEDED on the unchanged aggregate", ci.State)
	}
	if len(view.Divergences) == 0 {
		t.Fatal("the under-report must surface as a divergence health finding, got none")
	}
	d := view.Divergences[0]
	if d.DataPlaneID != "plane-2" || d.ReportedValue != 10 || d.ControlPlaneValue != 60 {
		t.Fatalf("divergence = %+v, want plane-2 reported 10 vs control-plane 60", d)
	}
}

// TestAC4_SilentPlaneGapRendersAsGapNotZero proves the gap rendering: one
// plane keeps reporting while the other goes silent past GapAfter — the view
// carries the live plane's aggregate AND a visible gap interval for the
// silent plane. The dimension never collapses to zero and never reads as
// fully covered (SPEC-0041 AC3 extended to the multi-plane shape).
func TestAC4_SilentPlaneGapRendersAsGapNotZero(t *testing.T) {
	f := newFixture(t, ciThresholds())
	ctx := context.Background()
	w := window(f.now.Add(-time.Hour), f.now)

	// Both planes report the same window, then plane-2 goes silent.
	ingest(t, f.svc, "acme", "plane-1", sampleWithCounter("s1", "plane-1", w, 0))
	ingest(t, f.svc, "acme", "plane-1", sampleWithCounter("s2", "plane-1", w, 20))
	ingest(t, f.svc, "acme", "plane-2", sampleWithCounter("s3", "plane-2", w, 0))
	ingest(t, f.svc, "acme", "plane-2", sampleWithCounter("s4", "plane-2", w, 20))

	// Time moves past GapAfter (15m): plane-1 reports a NEW window, plane-2
	// stays silent.
	f.now = f.now.Add(30 * time.Minute)
	w2 := window(f.now.Add(-time.Hour), f.now)
	ingest(t, f.svc, "acme", "plane-1", sampleWithCounter("s5", "plane-1", w2, 20))
	ingest(t, f.svc, "acme", "plane-1", sampleWithCounter("s6", "plane-1", w2, 50))

	view, err := f.svc.UsageView(ctx, "acme")
	if err != nil {
		t.Fatalf("UsageView: %v", err)
	}
	var ci api.DimensionView
	for _, row := range view.Dimensions {
		if row.Dimension == api.DimensionCIMinutes {
			ci = row
		}
	}
	if !ci.TelemetryGap {
		t.Fatal("the silent plane must render a telemetry gap on the dimension")
	}
	if len(ci.Gaps) == 0 {
		t.Fatal("the silent plane's gap interval must be listed, got none")
	}
	// The gap starts at the silent plane's last RECORDED window end.
	if !ci.Gaps[0].Start.Equal(w.End) {
		t.Fatalf("gap start = %v, want the silent plane's recorded window end %v", ci.Gaps[0].Start, w.End)
	}
	// And the aggregate carries the live plane's full stream (20 + 30) plus
	// the silent plane's last recorded movement (20) — never zero.
	if ci.Value != 70 {
		t.Fatalf("aggregate while one plane is silent = %v, want 70 — a gap, not a zero", ci.Value)
	}
}
