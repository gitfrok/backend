// App-layer tests for the metering authority (T-0034, SPEC-0041, ADR-0061).
// Each test names the acceptance criterion it proves.
package app_test

import (
	"context"
	"testing"
	"time"

	"github.com/gitfrok/backend/modules/metering/api"
	"github.com/gitfrok/backend/modules/metering/internal/adapters/memory"
	"github.com/gitfrok/backend/modules/metering/internal/app"
	"github.com/gitfrok/backend/modules/metering/internal/domain"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
	platformaudit "github.com/gitfrok/backend/platform/audit"
	"github.com/gitfrok/backend/platform/bus"
)

type fixture struct {
	svc      *app.Service
	events   *bus.InProcess
	notifier *fakeNotifier
	pdp      *fakePDP
	now      time.Time
	audit    []bus.Event
}

type fakeNotifier struct {
	notices []api.Notice
}

func (f *fakeNotifier) Notify(_ context.Context, n api.Notice) error {
	f.notices = append(f.notices, n)
	return nil
}

// fakePDP allows every decision unless denyAll is set: the tests that do not
// test authorization must not depend on it.
type fakePDP struct {
	denyAll bool
	last    policyapi.Request
}

func (p *fakePDP) Decide(_ context.Context, req policyapi.Request) (policyapi.Decision, error) {
	p.last = req
	return policyapi.Decision{Allowed: !p.denyAll}, nil
}

func newFixture(t *testing.T, thresholds map[api.Dimension]api.Threshold) *fixture {
	t.Helper()
	f := &fixture{
		events:   bus.NewInProcess(),
		notifier: &fakeNotifier{},
		pdp:      &fakePDP{},
		now:      time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC),
	}
	f.events.Subscribe(platformaudit.EventAudit, func(_ context.Context, e bus.Event) error {
		f.audit = append(f.audit, e)
		return nil
	})
	cfg := api.Config{
		Now:                  func() time.Time { return f.now },
		GapAfter:             15 * time.Minute,
		DivergenceTolerance:  0.05,
		ThrottledConcurrency: 2,
		QueueDepthCap:        50,
		DefaultThresholds:    thresholds,
	}
	f.svc = app.New(memory.New(), f.notifier, f.events, f.pdp, cfg, nil)
	return f
}

func window(start, end time.Time) api.Interval { return api.Interval{Start: start, End: end} }

func ciThresholds() map[api.Dimension]api.Threshold {
	return map[api.Dimension]api.Threshold{
		api.DimensionCIMinutes: {Notify: 80, Envelope: 100},
	}
}

// sampleWithCounter is one TelemetrySample carrying a cumulative CI-minutes
// counter; two of these with different totals yield their delta.
func sampleWithCounter(id, plane string, w api.Interval, total float64) api.Telemetry {
	return api.Telemetry{
		MessageID: id, Window: w,
		Counters: map[string]float64{domain.MetricCIMinutes: total},
	}
}

func ingest(t *testing.T, svc *app.Service, tenant, plane string, tel api.Telemetry) {
	t.Helper()
	if err := svc.IngestTelemetry(context.Background(), tenant, plane, tel); err != nil {
		t.Fatalf("IngestTelemetry: %v", err)
	}
}

// AC1 + ADR-0061 §2: a data plane's self-report NEVER changes the control
// plane's counter. Where the two disagree, the result is a divergence health
// finding carrying BOTH numbers — never an adjustment.
func TestSelfReportIsOperationalInputNeverCounter(t *testing.T) {
	f := newFixture(t, ciThresholds())
	ctx := context.Background()
	w := window(f.now.Add(-time.Hour), f.now)

	// Control plane sees 10 CI minutes (counter moved 0 → 10).
	ingest(t, f.svc, "tenant-a", "plane-1", sampleWithCounter("s1", "plane-1", w, 0))
	ingest(t, f.svc, "tenant-a", "plane-1", sampleWithCounter("s2", "plane-1", w, 10))

	// The data plane claims 50: a disagreement far past tolerance.
	err := f.svc.IngestUsage(ctx, "tenant-a", "plane-1", api.Usage{MessageID: "u1", Window: w, CIMinutes: 50})
	if err != nil {
		t.Fatalf("IngestUsage: %v", err)
	}

	view, err := f.svc.UsageView(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("UsageView: %v", err)
	}
	var ci api.DimensionView
	for _, row := range view.Dimensions {
		if row.Dimension == api.DimensionCIMinutes {
			ci = row
		}
	}
	// The counter is still 10: the billing number is what the control plane
	// RECEIVED, not what the plane reported (ADR-0061 §2).
	if ci.Value != 10 {
		t.Fatalf("counter adjusted by self-report: got %v, want 10", ci.Value)
	}
	if len(view.Divergences) != 1 {
		t.Fatalf("divergences: got %d, want 1", len(view.Divergences))
	}
	d := view.Divergences[0]
	if d.ControlPlaneValue != 10 || d.ReportedValue != 50 {
		t.Fatalf("divergence must carry BOTH numbers: got cp=%v reported=%v", d.ControlPlaneValue, d.ReportedValue)
	}
	// And the disagreement was audited.
	if len(f.audit) != 1 {
		t.Fatalf("audit events: got %d, want 1", len(f.audit))
	}
	if got := f.audit[0].(platformaudit.MeteringDivergence).Action(); got != platformaudit.ActionMeteringDivergence {
		t.Fatalf("audit action: got %q", got)
	}
}

// AC1, agreeing case: a self-report within tolerance records no divergence
// and still never touches the counter.
func TestAgreeingSelfReportRecordsNothing(t *testing.T) {
	f := newFixture(t, ciThresholds())
	ctx := context.Background()
	w := window(f.now.Add(-time.Hour), f.now)
	ingest(t, f.svc, "tenant-a", "plane-1", sampleWithCounter("s1", "plane-1", w, 0))
	ingest(t, f.svc, "tenant-a", "plane-1", sampleWithCounter("s2", "plane-1", w, 10))

	if err := f.svc.IngestUsage(ctx, "tenant-a", "plane-1", api.Usage{MessageID: "u1", Window: w, CIMinutes: 10}); err != nil {
		t.Fatalf("IngestUsage: %v", err)
	}
	view, err := f.svc.UsageView(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("UsageView: %v", err)
	}
	if len(view.Divergences) != 0 {
		t.Fatalf("divergences: got %d, want 0", len(view.Divergences))
	}
}

// AC2: the view lists every PRD §6 dimension; deferred ones render as
// "not metered" with a reason — never as zero usage, never as within-envelope.
func TestDeferredDimensionsRenderAsGapInCoverage(t *testing.T) {
	f := newFixture(t, ciThresholds())
	view, err := f.svc.UsageView(context.Background(), "tenant-a")
	if err != nil {
		t.Fatalf("UsageView: %v", err)
	}
	if len(view.Dimensions) != len(api.PRDDimensions) {
		t.Fatalf("rows: got %d, want %d (one per PRD dimension)", len(view.Dimensions), len(api.PRDDimensions))
	}
	byDim := map[api.Dimension]api.DimensionView{}
	for _, row := range view.Dimensions {
		byDim[row.Dimension] = row
	}
	for _, dim := range []api.Dimension{api.DimensionSeats, api.DimensionRepositoryStorage, api.DimensionIndexSize} {
		row := byDim[dim]
		if row.Coverage != api.CoverageDeferred {
			t.Fatalf("%s: coverage got %v, want deferred", dim, row.Coverage)
		}
		if row.DeferredReason == "" {
			t.Fatalf("%s: deferred row must carry its reason", dim)
		}
		if row.State == api.StateWithin {
			t.Fatalf("%s: deferred row must never render within-envelope", dim)
		}
	}
}

// AC3: missing telemetry is a VISIBLE GAP, never zero. A tenant whose planes
// never delivered telemetry gets gap rows — not zero usage.
func TestMissingTelemetryIsVisibleGapNeverZero(t *testing.T) {
	f := newFixture(t, ciThresholds())
	view, err := f.svc.UsageView(context.Background(), "tenant-a")
	if err != nil {
		t.Fatalf("UsageView: %v", err)
	}
	for _, row := range view.Dimensions {
		if row.Coverage != api.CoverageMetered {
			continue
		}
		if !row.TelemetryGap {
			t.Fatalf("%s: unmeasured interval must render as a gap", row.Dimension)
		}
		if row.State == api.StateWithin || row.State == api.StateNear || row.State == api.StateExceeded {
			t.Fatalf("%s: a gap must not carry an envelope state, got %v", row.Dimension, row.State)
		}
	}
}

// AC3, silent plane: when a data plane stops reporting past GapAfter, the
// interval after its last RECORDED window end renders as a named gap.
func TestSilentDataPlaneRendersNamedGap(t *testing.T) {
	f := newFixture(t, ciThresholds())
	ctx := context.Background()
	end := f.now.Add(-time.Hour)
	w := window(end.Add(-time.Hour), end)
	ingest(t, f.svc, "tenant-a", "plane-1", sampleWithCounter("s1", "plane-1", w, 0))
	ingest(t, f.svc, "tenant-a", "plane-1", sampleWithCounter("s2", "plane-1", w, 10))

	// The plane goes silent: now moves well past GapAfter.
	f.now = end.Add(time.Hour)
	view, err := f.svc.UsageView(ctx, "tenant-a")
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
		t.Fatal("silent interval must render as a gap")
	}
	if len(ci.Gaps) != 1 {
		t.Fatalf("gaps: got %d, want 1", len(ci.Gaps))
	}
	// The gap starts at the last RECORDED boundary — never at an inferred one.
	if !ci.Gaps[0].Start.Equal(end) {
		t.Fatalf("gap start: got %v, want recorded boundary %v", ci.Gaps[0].Start, end)
	}
}

// AC4: a notification fires on the way to the envelope (NEAR) BEFORE breach,
// names the dimension and its trend, is edge-triggered per crossing, and
// fires again on breach (EXCEEDED).
func TestThresholdNoticeBeforeBreachAndOnBreach(t *testing.T) {
	f := newFixture(t, ciThresholds())
	ctx := context.Background()
	w := window(f.now.Add(-time.Hour), f.now)

	// Value 85: past Notify (80), under Envelope (100) → one NEAR notice.
	ingest(t, f.svc, "tenant-a", "plane-1", sampleWithCounter("s1", "plane-1", w, 0))
	ingest(t, f.svc, "tenant-a", "plane-1", sampleWithCounter("s2", "plane-1", w, 85))
	if _, err := f.svc.Evaluate(ctx, "tenant-a"); err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(f.notifier.notices) != 1 {
		t.Fatalf("notices after NEAR: got %d, want 1", len(f.notifier.notices))
	}
	if got := f.notifier.notices[0].State; got != api.StateNear {
		t.Fatalf("notice state: got %v, want NEAR", got)
	}

	// Re-evaluating the same crossing fires nothing new (edge-triggered).
	if _, err := f.svc.Evaluate(ctx, "tenant-a"); err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(f.notifier.notices) != 1 {
		t.Fatalf("notices after re-evaluation: got %d, want 1 (edge-triggered)", len(f.notifier.notices))
	}

	// Value 105: breach → one more notice, this time EXCEEDED.
	ingest(t, f.svc, "tenant-a", "plane-1", sampleWithCounter("s3", "plane-1", w, 105))
	if _, err := f.svc.Evaluate(ctx, "tenant-a"); err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(f.notifier.notices) != 2 {
		t.Fatalf("notices after breach: got %d, want 2", len(f.notifier.notices))
	}
	if got := f.notifier.notices[1].State; got != api.StateExceeded {
		t.Fatalf("breach notice state: got %v, want EXCEEDED", got)
	}
	if f.notifier.notices[1].Dimension != api.DimensionCIMinutes {
		t.Fatalf("notice must name its dimension, got %v", f.notifier.notices[1].Dimension)
	}
	// The crossing was audited with the counter it cited.
	var notices int
	for _, e := range f.audit {
		if n, ok := e.(platformaudit.MeteringThresholdNotice); ok {
			notices++
			if n.Value != 85 && n.Value != 105 {
				t.Fatalf("notice audit must cite the counter, got %v", n.Value)
			}
		}
	}
	if notices != 2 {
		t.Fatalf("audited notices: got %d, want 2", notices)
	}
}

// SPEC-0046 AC2: the NEAR row names its dimension, its state and its trend
// with the SAME derivation the AC4 notice cites — and while the state is
// NEAR (before breach) the desired state throttles nothing.
func TestUsageViewNamesNearStateAndTrendBeforeBreach(t *testing.T) {
	f := newFixture(t, ciThresholds())
	ctx := context.Background()
	w := window(f.now.Add(-time.Hour), f.now)

	// Value 85: past Notify (80), under Envelope (100) → NEAR, no throttle.
	ingest(t, f.svc, "tenant-a", "plane-1", sampleWithCounter("s1", "plane-1", w, 0))
	ingest(t, f.svc, "tenant-a", "plane-1", sampleWithCounter("s2", "plane-1", w, 85))

	view, err := f.svc.UsageView(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("UsageView: %v", err)
	}
	var ci api.DimensionView
	for _, row := range view.Dimensions {
		if row.Dimension == api.DimensionCIMinutes {
			ci = row
		}
	}
	if ci.State != api.StateNear {
		t.Fatalf("state: got %v, want NEAR", ci.State)
	}
	// One interval has no past: the trend is flat — honest, never estimated.
	if ci.Trend != api.TrendFlat {
		t.Fatalf("trend: got %v, want flat (an unknown past is never estimated)", ci.Trend)
	}
	if len(view.Notices) != 1 || view.Notices[0].State != api.StateNear {
		t.Fatalf("notices: got %d, want the one NEAR notice", len(view.Notices))
	}
	// The view and the notification read from one ledger: same derivation.
	if view.Notices[0].Trend != ci.Trend {
		t.Fatalf("view trend %v must equal the notice trend %v (one derivation)", ci.Trend, view.Notices[0].Trend)
	}
	// NEAR warns; it does not enforce: the desired state throttles nothing.
	desired, ok, err := f.svc.LatestDesiredState(ctx, "tenant-a")
	if err != nil || !ok {
		t.Fatalf("LatestDesiredState: ok=%v err=%v", ok, err)
	}
	if desired.MaxCIConcurrency != 0 || desired.QueueDepthCap != 0 {
		t.Fatalf("NEAR must not throttle: got max=%d cap=%d", desired.MaxCIConcurrency, desired.QueueDepthCap)
	}
}

// SPEC-0046 AC3: the throttle observation shows the METERED desired state and
// the APPLIED ack as separate halves — absent until an evaluation, the applied
// half absent until an ack, and a failed ack cited, never smoothed away.
func TestThrottleObservationEndToEnd(t *testing.T) {
	f := newFixture(t, ciThresholds())
	ctx := context.Background()
	w := window(f.now.Add(-time.Hour), f.now)
	ci := func(view api.View) api.DimensionView {
		t.Helper()
		for _, row := range view.Dimensions {
			if row.Dimension == api.DimensionCIMinutes {
				return row
			}
		}
		t.Fatal("usage view must carry a CI-minutes row")
		return api.DimensionView{}
	}

	// No evaluation yet: absence renders as absence, never as zero state.
	view, err := f.svc.UsageView(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("UsageView: %v", err)
	}
	if view.Throttle.Present {
		t.Fatal("a tenant with no evaluation must carry no throttle observation")
	}

	// Breach (105 ≥ 100): the evaluation meters a throttle (AC5 values).
	ingest(t, f.svc, "tenant-a", "plane-1", sampleWithCounter("s1", "plane-1", w, 0))
	ingest(t, f.svc, "tenant-a", "plane-1", sampleWithCounter("s2", "plane-1", w, 105))
	view, err = f.svc.UsageView(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("UsageView: %v", err)
	}
	if ci(view).State != api.StateExceeded {
		t.Fatalf("state: got %v, want EXCEEDED", ci(view).State)
	}
	th := view.Throttle
	if !th.Present {
		t.Fatal("an evaluated tenant must carry the throttle observation")
	}
	if th.DesiredMaxCIConcurrency != 2 || th.DesiredQueueDepthCap != 50 {
		t.Fatalf("metered desired state: got max=%d cap=%d, want 2/50", th.DesiredMaxCIConcurrency, th.DesiredQueueDepthCap)
	}
	if th.HasAppliedAck {
		t.Fatal("the applied half must stay absent until an ack is recorded")
	}

	// The data plane acks the generation as applied: both halves now cite
	// their own numbers.
	if err := f.svc.AckDesiredState(ctx, "tenant-a", th.DesiredGeneration, true, ""); err != nil {
		t.Fatalf("AckDesiredState: %v", err)
	}
	view, err = f.svc.UsageView(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("UsageView: %v", err)
	}
	th = view.Throttle
	if !th.HasAppliedAck || !th.Applied || th.AppliedGeneration != th.DesiredGeneration {
		t.Fatalf("applied ack: has=%v applied=%v gen=%d, want ack of generation %d", th.HasAppliedAck, th.Applied, th.AppliedGeneration, th.DesiredGeneration)
	}
	if !th.AckedAt.Equal(f.now) {
		t.Fatalf("acked_at: got %v, want %v", th.AckedAt, f.now)
	}

	// A failed ack is shown with its coarse error prose — never smoothed
	// into "applied".
	if err := f.svc.AckDesiredState(ctx, "tenant-a", th.DesiredGeneration, false, "scaler unavailable"); err != nil {
		t.Fatalf("AckDesiredState: %v", err)
	}
	view, err = f.svc.UsageView(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("UsageView: %v", err)
	}
	th = view.Throttle
	if th.Applied || th.AppliedError != "scaler unavailable" {
		t.Fatalf("failed ack must be cited: applied=%v err=%q", th.Applied, th.AppliedError)
	}
}

// AC5 + AC7 + AC8: a breached CI dimension throttles CI concurrency with a
// queue cap — and the enforcement vocabulary structurally cannot block git
// or make a repository read-only.
func TestBreachThrottlesCIAndNeverGit(t *testing.T) {
	f := newFixture(t, ciThresholds())
	ctx := context.Background()
	w := window(f.now.Add(-time.Hour), f.now)
	ingest(t, f.svc, "tenant-a", "plane-1", sampleWithCounter("s1", "plane-1", w, 0))
	ingest(t, f.svc, "tenant-a", "plane-1", sampleWithCounter("s2", "plane-1", w, 105))

	out, err := f.svc.Evaluate(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if out.MaxCIConcurrency != 2 {
		t.Fatalf("throttled concurrency: got %d, want 2", out.MaxCIConcurrency)
	}
	if out.QueueDepthCap != 50 {
		t.Fatalf("queue depth cap: got %d, want 50", out.QueueDepthCap)
	}
	// The AC7/AC8 promise is encoded in the action vocabulary itself: every
	// dimension's enforcement is one of three shapes, and none of them
	// touches git availability or read-only state.
	for _, dim := range api.PRDDimensions {
		switch api.ThrottleFor(dim) {
		case api.ThrottleNone, api.ThrottleReduceCIConcurrency, api.ThrottleWarnAndReport:
			// the entire vocabulary: no git-blocking, no read-only action exists
		default:
			t.Fatalf("unexpected throttle action for %s", dim)
		}
	}
}

// AC5, within-envelope case: no breach means no throttle in the desired state.
func TestWithinEnvelopeProducesNoThrottle(t *testing.T) {
	f := newFixture(t, ciThresholds())
	ctx := context.Background()
	w := window(f.now.Add(-time.Hour), f.now)
	ingest(t, f.svc, "tenant-a", "plane-1", sampleWithCounter("s1", "plane-1", w, 0))
	ingest(t, f.svc, "tenant-a", "plane-1", sampleWithCounter("s2", "plane-1", w, 10))

	out, err := f.svc.Evaluate(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if out.MaxCIConcurrency != 0 || out.QueueDepthCap != 0 {
		t.Fatalf("no breach must produce no throttle, got concurrency=%d cap=%d", out.MaxCIConcurrency, out.QueueDepthCap)
	}
}

// AC9: the desired state carries a monotonic generation the data plane acks.
func TestDesiredStateGenerationIsMonotonic(t *testing.T) {
	f := newFixture(t, ciThresholds())
	ctx := context.Background()
	first, err := f.svc.Evaluate(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	second, err := f.svc.Evaluate(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if first.Generation != 1 || second.Generation != 2 {
		t.Fatalf("generations: got %d then %d, want 1 then 2", first.Generation, second.Generation)
	}
}

// AC10: the customer's usage view and every envelope decision read the SAME
// counters — one ledger, one number.
func TestViewAndDecisionsShareOneLedger(t *testing.T) {
	f := newFixture(t, ciThresholds())
	ctx := context.Background()
	w := window(f.now.Add(-time.Hour), f.now)
	ingest(t, f.svc, "tenant-a", "plane-1", sampleWithCounter("s1", "plane-1", w, 0))
	ingest(t, f.svc, "tenant-a", "plane-1", sampleWithCounter("s2", "plane-1", w, 42))

	out, err := f.svc.Evaluate(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	view, err := f.svc.UsageView(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("UsageView: %v", err)
	}
	var decisionValue, viewValue float64
	for _, d := range out.Decisions {
		if d.Dimension == api.DimensionCIMinutes {
			decisionValue = d.Value
		}
	}
	for _, row := range view.Dimensions {
		if row.Dimension == api.DimensionCIMinutes {
			viewValue = row.Value
		}
	}
	if decisionValue != 42 || viewValue != decisionValue {
		t.Fatalf("view and decisions must cite one ledger: decision=%v view=%v want 42", decisionValue, viewValue)
	}
}

// Invariant 1 + SPEC-0001: tenant isolation is structural — one tenant's
// samples never appear in another tenant's view.
func TestTenantIsolation(t *testing.T) {
	f := newFixture(t, ciThresholds())
	ctx := context.Background()
	w := window(f.now.Add(-time.Hour), f.now)
	ingest(t, f.svc, "tenant-a", "plane-1", sampleWithCounter("s1", "plane-1", w, 0))
	ingest(t, f.svc, "tenant-a", "plane-1", sampleWithCounter("s2", "plane-1", w, 42))

	viewB, err := f.svc.UsageView(ctx, "tenant-b")
	if err != nil {
		t.Fatalf("UsageView tenant-b: %v", err)
	}
	for _, row := range viewB.Dimensions {
		if row.Coverage == api.CoverageMetered && !row.TelemetryGap {
			t.Fatalf("tenant-b sees tenant-a's telemetry on %s", row.Dimension)
		}
	}
	viewA, err := f.svc.UsageView(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("UsageView tenant-a: %v", err)
	}
	for _, row := range viewA.Dimensions {
		if row.Dimension == api.DimensionCIMinutes && row.Value != 42 {
			t.Fatalf("tenant-a ci value: got %v, want 42", row.Value)
		}
	}
}

// Non-functional: ingest is idempotent per message ID, so an at-least-once
// redelivery (the restart shape) neither double-counts nor errors.
func TestReplayedSampleDoesNotDoubleCount(t *testing.T) {
	f := newFixture(t, ciThresholds())
	ctx := context.Background()
	w := window(f.now.Add(-time.Hour), f.now)
	ingest(t, f.svc, "tenant-a", "plane-1", sampleWithCounter("s1", "plane-1", w, 0))
	ingest(t, f.svc, "tenant-a", "plane-1", sampleWithCounter("s2", "plane-1", w, 42))
	// Replay both: counters must not move.
	ingest(t, f.svc, "tenant-a", "plane-1", sampleWithCounter("s1", "plane-1", w, 0))
	ingest(t, f.svc, "tenant-a", "plane-1", sampleWithCounter("s2", "plane-1", w, 42))

	view, err := f.svc.UsageView(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("UsageView: %v", err)
	}
	for _, row := range view.Dimensions {
		if row.Dimension == api.DimensionCIMinutes && row.Value != 42 {
			t.Fatalf("replay changed the counter: got %v, want 42", row.Value)
		}
	}
}

// SPEC-0001 coarse refusals: malformed ingest is refused with the module's
// coarse error; an empty tenant is refused on every surface.
func TestMalformedIngestRefused(t *testing.T) {
	f := newFixture(t, ciThresholds())
	ctx := context.Background()
	w := window(f.now.Add(-time.Hour), f.now)
	good := sampleWithCounter("s1", "plane-1", w, 0)

	if err := f.svc.IngestTelemetry(ctx, "", "plane-1", good); err != api.ErrMalformed {
		t.Fatalf("empty tenant: got %v, want ErrMalformed", err)
	}
	if err := f.svc.IngestTelemetry(ctx, "tenant-a", "", good); err != api.ErrMalformed {
		t.Fatalf("empty plane: got %v, want ErrMalformed", err)
	}
	if err := f.svc.IngestTelemetry(ctx, "tenant-a", "plane-1", api.Telemetry{Window: w}); err != api.ErrMalformed {
		t.Fatalf("empty message id: got %v, want ErrMalformed", err)
	}
	if err := f.svc.IngestTelemetry(ctx, "tenant-a", "plane-1", api.Telemetry{MessageID: "s1", Window: window(f.now, f.now)}); err != api.ErrMalformed {
		t.Fatalf("degenerate window: got %v, want ErrMalformed", err)
	}
	if _, err := f.svc.UsageView(ctx, ""); err != api.ErrMalformed {
		t.Fatalf("empty-tenant view: got %v, want ErrMalformed", err)
	}
}

// AC9: the newest evaluation is available on the delivery seam the agent
// channel polls, and the data plane's acknowledgement is recorded.
func TestEnvelopeDeliveryAndAck(t *testing.T) {
	f := newFixture(t, ciThresholds())
	ctx := context.Background()

	if _, ok, err := f.svc.LatestDesiredState(ctx, "tenant-a"); err != nil || ok {
		t.Fatalf("no evaluation yet: ok=%v err=%v, want ok=false", ok, err)
	}

	w := window(f.now.Add(-time.Hour), f.now)
	ingest(t, f.svc, "tenant-a", "plane-1", sampleWithCounter("s1", "plane-1", w, 0))
	ingest(t, f.svc, "tenant-a", "plane-1", sampleWithCounter("s2", "plane-1", w, 105))

	// Ingestion itself evaluated: the breach is already on the delivery seam
	// without anyone polling Evaluate directly.
	out, ok, err := f.svc.LatestDesiredState(ctx, "tenant-a")
	if err != nil || !ok {
		t.Fatalf("LatestDesiredState: ok=%v err=%v, want a delivered state", ok, err)
	}
	if out.MaxCIConcurrency == 0 {
		t.Fatal("breached CI dimension must carry the throttle on the wire")
	}
	if err := f.svc.AckDesiredState(ctx, "tenant-a", out.Generation, true, ""); err != nil {
		t.Fatalf("AckDesiredState: %v", err)
	}
	acks, err := f.svc.Acks(ctx, "tenant-a")
	if err != nil || len(acks) != 1 || !acks[0].Applied || acks[0].Generation != out.Generation {
		t.Fatalf("acks: got %+v err=%v, want one applied ack of generation %d", acks, err, out.Generation)
	}
}

// Per-tenant thresholds override the configured defaults (SPEC-0041
// non-functional: thresholds are stored configuration, never compiled in).
func TestTenantThresholdOverrides(t *testing.T) {
	f := newFixture(t, ciThresholds())
	ctx := context.Background()
	if err := f.svc.SetTenantThresholds(ctx, "tenant-a", map[api.Dimension]api.Threshold{
		api.DimensionCIMinutes: {Notify: 5, Envelope: 10},
	}); err != nil {
		t.Fatalf("SetTenantThresholds: %v", err)
	}
	w := window(f.now.Add(-time.Hour), f.now)
	ingest(t, f.svc, "tenant-a", "plane-1", sampleWithCounter("s1", "plane-1", w, 0))
	ingest(t, f.svc, "tenant-a", "plane-1", sampleWithCounter("s2", "plane-1", w, 12))

	out, err := f.svc.Evaluate(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	for _, d := range out.Decisions {
		if d.Dimension == api.DimensionCIMinutes && d.State != api.StateExceeded {
			t.Fatalf("override not applied: value 12 against envelope 10 must be EXCEEDED, got %v", d.State)
		}
	}
}

// SPEC-0001 + authz: ReadUsageView asks the PDP for usage.view.read before
// touching the ledger; a denial, a malformed context, and an empty tenant
// are all the same coarse ErrDenied.
func TestReadUsageViewAuthorizedAndCoarse(t *testing.T) {
	f := newFixture(t, ciThresholds())
	ctx := context.Background()
	w := window(f.now.Add(-time.Hour), f.now)
	ingest(t, f.svc, "tenant-a", "plane-1", sampleWithCounter("s1", "plane-1", w, 0))
	ingest(t, f.svc, "tenant-a", "plane-1", sampleWithCounter("s2", "plane-1", w, 42))

	// Authorized read: the same counters, decided through the PDP.
	view, err := f.svc.ReadUsageView(ctx, api.ViewContext{
		TenantID: "tenant-a", ActorID: "actor-1", ActorRoles: []string{"owner"}, RequestID: "req-1",
	})
	if err != nil {
		t.Fatalf("ReadUsageView: %v", err)
	}
	if f.pdp.last.Action != api.ActionUsageViewRead || f.pdp.last.TenantID != "tenant-a" {
		t.Fatalf("PDP must decide %s on the tenant, got %+v", api.ActionUsageViewRead, f.pdp.last)
	}
	var found bool
	for _, row := range view.Dimensions {
		if row.Dimension == api.DimensionCIMinutes && row.Value == 42 {
			found = true
		}
	}
	if !found {
		t.Fatal("authorized read must return the ledger's counters")
	}

	// Denied: the same coarse error as a malformed context (SPEC-0001).
	f.pdp.denyAll = true
	if _, err := f.svc.ReadUsageView(ctx, api.ViewContext{
		TenantID: "tenant-a", ActorID: "actor-1", ActorRoles: []string{"reader"}, RequestID: "req-2",
	}); err != api.ErrDenied {
		t.Fatalf("denied read: got %v, want ErrDenied", err)
	}
	f.pdp.denyAll = false
	if _, err := f.svc.ReadUsageView(ctx, api.ViewContext{
		TenantID: "", ActorID: "actor-1", RequestID: "req-3",
	}); err != api.ErrDenied {
		t.Fatalf("malformed context: got %v, want ErrDenied", err)
	}
}
