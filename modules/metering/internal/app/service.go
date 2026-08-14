// Package app is the Metering context's application layer: ingestion of the
// telemetry the agent channel delivers, envelope evaluation with
// throttle-and-notify enforcement, and the usage view (T-0034, SPEC-0041).
// It composes the domain with ports — store, notifier, bus — and never
// touches infrastructure itself (invariant 16).
package app

import (
	"context"
	"maps"
	"math"
	"slices"
	"sync"
	"time"

	"github.com/gitfrok/backend/modules/metering/api"
	"github.com/gitfrok/backend/modules/metering/internal/domain"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
	platformaudit "github.com/gitfrok/backend/platform/audit"
	"github.com/gitfrok/backend/platform/bus"
)

// Store is the persistence port. Every record it holds carries the RECORDED
// interval boundaries the samples declared; nothing here infers a boundary
// from wall-clock at read time (SPEC-0041 non-functional).
type Store interface {
	// AddSample records one received TelemetrySample. It returns added=false
	// for a MessageID already recorded: ingest is idempotent, which is what
	// keeps a restart from double-counting.
	AddSample(ctx context.Context, tenantID string, s domain.Sample) (added bool, err error)
	Samples(ctx context.Context, tenantID string) ([]domain.Sample, error)
	// AddUsageReport records one received UsageSample (operational input,
	// never a counter input). Idempotent per MessageID.
	AddUsageReport(ctx context.Context, tenantID string, u domain.UsageReport) (added bool, err error)
	UsageReports(ctx context.Context, tenantID string) ([]domain.UsageReport, error)
	RecordDivergence(ctx context.Context, tenantID string, d api.Divergence) error
	Divergences(ctx context.Context, tenantID string) ([]api.Divergence, error)
	RecordNotice(ctx context.Context, tenantID string, n api.Notice) error
	Notices(ctx context.Context, tenantID string) ([]api.Notice, error)
	// NoticeState is the edge-trigger bookkeeping: the last state a notice
	// fired for, per dimension, so a threshold crossing notifies once per
	// crossing, not once per evaluation.
	NoticeState(ctx context.Context, tenantID string, d api.Dimension) (api.State, bool, error)
	SetNoticeState(ctx context.Context, tenantID string, d api.Dimension, s api.State) error
	// Tenant thresholds override the configured defaults; they are stored,
	// never compiled in (SPEC-0041 non-functional).
	TenantThresholds(ctx context.Context, tenantID string) (map[api.Dimension]api.Threshold, bool, error)
	SetTenantThresholds(ctx context.Context, tenantID string, m map[api.Dimension]api.Threshold) error
	// NextGeneration hands out the monotonic desired-state generation (AC9).
	NextGeneration(ctx context.Context, tenantID string) (int64, error)
}

// Service is the composed application service: both halves of the surface —
// the agent channel's Sink and the usage door's Reader — because they share
// one ledger (SPEC-0041 AC10).
type Service struct {
	cfg      api.Config
	store    Store
	notifier api.Notifier
	events   bus.Bus
	pdp      policyapi.DecisionPoint
	logf     func(format string, args ...any)

	mu      sync.Mutex
	desired map[string]api.EnvelopeDesiredState // newest evaluation per tenant (AC9)
	acks    map[string][]api.Ack                // data-plane acknowledgements (AC9)
}

var _ api.Sink = (*Service)(nil)
var _ api.Reader = (*Service)(nil)
var _ api.EnvelopeDelivery = (*Service)(nil)

// New wires the service. A nil store, notifier, bus or PDP is refused: a metering
// surface that cannot record, notify, authorize, or audit is not a metering surface.
func New(store Store, notifier api.Notifier, events bus.Bus, pdp policyapi.DecisionPoint, cfg api.Config, logf func(format string, args ...any)) *Service {
	if store == nil || notifier == nil || events == nil || pdp == nil {
		panic("metering: store, notifier, bus and policy decision point are all required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.GapAfter <= 0 {
		cfg.GapAfter = 15 * time.Minute
	}
	if cfg.DivergenceTolerance <= 0 {
		cfg.DivergenceTolerance = 0.05
	}
	if cfg.DefaultThresholds == nil {
		cfg.DefaultThresholds = map[api.Dimension]api.Threshold{}
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Service{
		cfg: cfg, store: store, notifier: notifier, events: events, pdp: pdp, logf: logf,
		desired: map[string]api.EnvelopeDesiredState{},
		acks:    map[string][]api.Ack{},
	}
}

// --- Ingestion (the Sink half) --------------------------------------------------------

// IngestTelemetry records one TelemetrySample received over the agent
// channel. This is the ONLY path that moves a counter (ADR-0061 §1): the
// sample is recorded under its own message ID, and counters are later
// derived from the record set — idempotent across restarts.
func (s *Service) IngestTelemetry(ctx context.Context, tenantID, dataPlaneID string, t api.Telemetry) error {
	if tenantID == "" || dataPlaneID == "" || t.MessageID == "" {
		return api.ErrMalformed
	}
	if !t.Window.End.After(t.Window.Start) {
		return api.ErrMalformed
	}
	_, err := s.store.AddSample(ctx, tenantID, domain.Sample{
		MessageID:   t.MessageID,
		DataPlaneID: dataPlaneID,
		Window:      t.Window,
		ReceivedAt:  s.cfg.Now(),
		Gauges:      maps.Clone(t.Gauges),
		Counters:    maps.Clone(t.Counters),
	})
	if err != nil {
		return err
	}
	return s.evaluateQuietly(ctx, tenantID)
}

// IngestUsage records one UsageSample — the data plane's OWN totals. It
// NEVER changes a counter (ADR-0061 §2): the only thing it can add to the
// ledger is a divergence health finding (SPEC-0041 AC1).
func (s *Service) IngestUsage(ctx context.Context, tenantID, dataPlaneID string, u api.Usage) error {
	if tenantID == "" || dataPlaneID == "" || u.MessageID == "" {
		return api.ErrMalformed
	}
	if !u.Window.End.After(u.Window.Start) {
		return api.ErrMalformed
	}
	reported := map[api.Dimension]float64{}
	if u.CIMinutes > 0 {
		reported[api.DimensionCIMinutes] = u.CIMinutes
	}
	if u.EgressBytes > 0 {
		reported[api.DimensionEgress] = u.EgressBytes
	}
	if u.ScanBytes > 0 {
		reported[api.DimensionScanVolume] = u.ScanBytes
	}
	if u.CIConcurrencyPeak > 0 {
		reported[api.DimensionCIConcurrency] = u.CIConcurrencyPeak
	}
	if u.RepositoryCount > 0 {
		reported[api.DimensionRepositoryCount] = float64(u.RepositoryCount)
	}
	added, err := s.store.AddUsageReport(ctx, tenantID, domain.UsageReport{
		MessageID:   u.MessageID,
		DataPlaneID: dataPlaneID,
		Window:      u.Window,
		ReceivedAt:  s.cfg.Now(),
		Reported:    reported,
	})
	if err != nil || !added {
		return err
	}
	return s.detectDivergence(ctx, tenantID, dataPlaneID, u.Window, reported)
}

// detectDivergence compares the plane's self-reported totals with the
// control plane's derived counters over the same window. A disagreement past
// tolerance is recorded and audited as a health finding carrying BOTH
// numbers — never an adjustment to the counter (SPEC-0041 AC1, ADR-0061 §2).
func (s *Service) detectDivergence(ctx context.Context, tenantID, dataPlaneID string, window api.Interval, reported map[api.Dimension]float64) error {
	samples, err := s.store.Samples(ctx, tenantID)
	if err != nil {
		return err
	}
	var planeSamples []domain.Sample
	for _, s := range samples {
		if s.DataPlaneID == dataPlaneID && !s.Window.End.After(window.End) && !s.Window.Start.Before(window.Start) {
			planeSamples = append(planeSamples, s)
		}
	}
	for dim, want := range reported {
		got, _, ok := domain.DeriveValue(dim, planeSamples)
		if !ok {
			// The control plane has no derivation for the window: that is a
			// coverage fact, not a divergence.
			continue
		}
		if relDiff(got, want) <= s.cfg.DivergenceTolerance {
			continue
		}
		div := api.Divergence{
			TenantID: tenantID, DataPlaneID: dataPlaneID, Dimension: dim,
			ControlPlaneValue: got, ReportedValue: want,
			Window: window, DetectedAt: s.cfg.Now(),
		}
		if err := s.store.RecordDivergence(ctx, tenantID, div); err != nil {
			return err
		}
		if err := s.events.Publish(ctx, platformaudit.MeteringDivergence{
			TenantID: tenantID, DataPlaneID: dataPlaneID, Dimension: dim.String(),
			ControlPlaneValue: got, ReportedValue: want,
			WindowStart: window.Start, WindowEnd: window.End, OccurredAt: s.cfg.Now(),
		}); err != nil {
			return err
		}
	}
	return nil
}

func relDiff(a, b float64) float64 {
	denom := math.Max(math.Abs(a), math.Abs(b))
	if denom == 0 {
		return 0
	}
	return math.Abs(a-b) / denom
}

// --- Evaluation (envelopes, notices, desired state) -----------------------------------

// thresholds resolves the tenant's envelope configuration: stored per-tenant
// overrides over the configured defaults (SPEC-0041 non-functional).
func (s *Service) thresholds(ctx context.Context, tenantID string) (map[api.Dimension]api.Threshold, error) {
	if override, ok, err := s.store.TenantThresholds(ctx, tenantID); err != nil {
		return nil, err
	} else if ok {
		return override, nil
	}
	return s.cfg.DefaultThresholds, nil
}

// Evaluate computes every metered dimension's envelope condition from the
// ledger, fires the AC4 notifications on threshold crossings, and returns
// the decisions with the desired state the data plane applies (AC9). The
// decisions cite the counter and the interval they were made from (G6), and
// they are the same numbers UsageView reads (AC10).
func (s *Service) Evaluate(ctx context.Context, tenantID string) (api.EnvelopeDesiredState, error) {
	if tenantID == "" {
		return api.EnvelopeDesiredState{}, api.ErrMalformed
	}
	samples, err := s.store.Samples(ctx, tenantID)
	if err != nil {
		return api.EnvelopeDesiredState{}, err
	}
	limits, err := s.thresholds(ctx, tenantID)
	if err != nil {
		return api.EnvelopeDesiredState{}, err
	}

	out := api.EnvelopeDesiredState{}
	ciBreached := false
	for _, dim := range api.PRDDimensions {
		if api.Phase3Coverage[dim] != api.CoverageMetered {
			continue
		}
		limit := limits[dim]
		value, window, ok := domain.DeriveValue(dim, samples)
		if !ok {
			// No telemetry: a gap, not a number, and never a breach. A
			// silent fleet cannot be throttled into an envelope it never
			// reported leaving (AC3).
			continue
		}
		state := stateOf(value, limit)
		out.Decisions = append(out.Decisions, api.Decision{
			Dimension: dim, State: state, Value: value, Window: window, Threshold: limit,
		})
		if state == api.StateExceeded && api.ThrottleFor(dim) == api.ThrottleReduceCIConcurrency {
			ciBreached = true
		}
		if err := s.notifyCrossing(ctx, tenantID, dim, state, value, limit, window, samples); err != nil {
			return api.EnvelopeDesiredState{}, err
		}
	}
	if ciBreached {
		// AC5: the breach reduces concurrency and caps the queue. Jobs
		// already running finish; queued jobs are delayed with the cause
		// visible on the job, and none are dropped. Git is untouched (AC7).
		out.MaxCIConcurrency = s.cfg.ThrottledConcurrency
		out.QueueDepthCap = s.cfg.QueueDepthCap
	}
	gen, err := s.store.NextGeneration(ctx, tenantID)
	if err != nil {
		return api.EnvelopeDesiredState{}, err
	}
	out.Generation = gen
	s.mu.Lock()
	s.desired[tenantID] = out
	s.mu.Unlock()
	return out, nil
}

// evaluateQuietly re-evaluates right after a sample is recorded, so a
// threshold crossing is noticed as soon as the telemetry that crosses it
// lands. The sample is already recorded at this point; an evaluation failure
// is logged, never traded against ingest availability — metering must not
// degrade the channel that carries it (the AC7 discipline applied inward).
func (s *Service) evaluateQuietly(ctx context.Context, tenantID string) error {
	if _, err := s.Evaluate(ctx, tenantID); err != nil {
		s.logf("metering: evaluation after ingest failed for %s: %v", tenantID, err)
	}
	return nil
}

// LatestDesiredState is the AC9 poll: the newest evaluation the agent
// channel's stream delivers to the tenant's data plane. ok is false before
// the first evaluation.
func (s *Service) LatestDesiredState(_ context.Context, tenantID string) (api.EnvelopeDesiredState, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.desired[tenantID]
	return d, ok, nil
}

// AckDesiredState records the data plane's acknowledgement of one desired
// state generation (SPEC-0041 AC9): the applied flag and the coarse error
// prose it reported, nothing more.
func (s *Service) AckDesiredState(_ context.Context, tenantID string, generation int64, applied bool, errMsg string) error {
	if tenantID == "" {
		return api.ErrMalformed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.acks[tenantID] = append(s.acks[tenantID], api.Ack{
		Generation: generation, Applied: applied, Error: errMsg, AckedAt: s.cfg.Now(),
	})
	return nil
}

// Acks returns the tenant's recorded acknowledgements, oldest first.
func (s *Service) Acks(_ context.Context, tenantID string) ([]api.Ack, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.acks[tenantID]), nil
}

// stateOf orders one counter against its tenant-configured thresholds.
func stateOf(value float64, limit api.Threshold) api.State {
	switch {
	case limit.Envelope > 0 && value >= limit.Envelope:
		return api.StateExceeded
	case limit.Notify > 0 && value >= limit.Notify:
		return api.StateNear
	default:
		return api.StateWithin
	}
}

// notifyCrossing fires the AC4 notice on the way to the envelope (NEAR) and
// on breach (EXCEEDED): edge-triggered per crossing, naming the dimension
// and its trend. A return to WITHIN re-arms the notice without firing one.
func (s *Service) notifyCrossing(ctx context.Context, tenantID string, dim api.Dimension, state api.State, value float64, limit api.Threshold, window api.Interval, samples []domain.Sample) error {
	prev, hadPrev, err := s.store.NoticeState(ctx, tenantID, dim)
	if err != nil {
		return err
	}
	if state == api.StateWithin {
		if hadPrev && prev != api.StateWithin {
			return s.store.SetNoticeState(ctx, tenantID, dim, api.StateWithin)
		}
		return nil
	}
	// Fire only on a NEW crossing: reaching NEAR, or escalating NEAR→EXCEEDED.
	if hadPrev && prev >= state {
		return nil
	}
	trend := trendOf(dim, value, window, samples)
	notice := api.Notice{
		TenantID: tenantID, Dimension: dim, State: state,
		Value: value, Threshold: thresholdFor(state, limit),
		Window: window, Trend: trend, OccurredAt: s.cfg.Now(),
	}
	if err := s.store.SetNoticeState(ctx, tenantID, dim, state); err != nil {
		return err
	}
	if err := s.store.RecordNotice(ctx, tenantID, notice); err != nil {
		return err
	}
	if err := s.events.Publish(ctx, platformaudit.MeteringThresholdNotice{
		TenantID: tenantID, Dimension: dim.String(), State: state.String(),
		Value: value, Threshold: notice.Threshold, Trend: trend.String(),
		WindowStart: window.Start, WindowEnd: window.End, OccurredAt: notice.OccurredAt,
	}); err != nil {
		return err
	}
	// The out-of-band half of AC4: the email to the platform engineer. A
	// notifier failure is logged, not fatal: the in-product notice and the
	// audit record already exist, and trading telemetry availability for a
	// delivery receipt would break the very surface this notice serves.
	if err := s.notifier.Notify(ctx, notice); err != nil {
		s.logf("metering: notice delivery failed for %s/%s: %v", tenantID, dim, err)
	}
	return nil
}

// thresholdFor cites the threshold the notice is about: the notification
// value on the way up, the envelope value on breach.
func thresholdFor(state api.State, limit api.Threshold) float64 {
	if state == api.StateExceeded {
		return limit.Envelope
	}
	return limit.Notify
}

// trendOf compares the current interval's value with the one before it. An
// unknown past is flat, never invented (the AC4 trend is cited, not
// estimated — the ADR-0061 §1 discipline applied to prose).
func trendOf(dim api.Dimension, value float64, window api.Interval, samples []domain.Sample) api.Trend {
	prev, ok := domain.PreviousValue(dim, samples, window)
	if !ok {
		return api.TrendFlat
	}
	switch {
	case value > prev:
		return api.TrendRising
	case value < prev:
		return api.TrendFalling
	default:
		return api.TrendFlat
	}
}

// --- The usage view (the Reader half) --------------------------------------------------

// ReadUsageView is the authorized read: the PDP decides usage.view.read for
// the caller BEFORE any ledger is touched, and every refusal — unauthorized,
// malformed, or cross-tenant — is the same coarse ErrDenied (SPEC-0001).
func (s *Service) ReadUsageView(ctx context.Context, vc api.ViewContext) (api.View, error) {
	if vc.TenantID == "" || vc.ActorID == "" || vc.RequestID == "" {
		return api.View{}, api.ErrDenied
	}
	if !s.allowed(ctx, vc) {
		return api.View{}, api.ErrDenied
	}
	return s.UsageView(ctx, vc.TenantID)
}

// allowed asks the PDP. Any error is a refusal: a decision that was not
// reached denies (ADR-0006).
func (s *Service) allowed(ctx context.Context, vc api.ViewContext) bool {
	decision, err := s.pdp.Decide(ctx, policyapi.Request{
		TenantID: vc.TenantID,
		Subject: policyapi.Subject{
			ID: vc.ActorID, TenantID: vc.TenantID,
			Roles: slices.Clone(vc.ActorRoles),
		},
		Action:   api.ActionUsageViewRead,
		Resource: policyapi.Resource{Type: "tenant", ID: vc.TenantID},
	})
	return err == nil && decision.Allowed
}

// UsageView renders the tenant's usage view from the SAME ledger every
// envelope decision was made from (SPEC-0041 AC10): one row per PRD §6
// dimension, deferred rows labelled with their reason (AC2), silent
// intervals rendered as gaps and never as zeros (AC3).
func (s *Service) UsageView(ctx context.Context, tenantID string) (api.View, error) {
	if tenantID == "" {
		return api.View{}, api.ErrMalformed
	}
	now := s.cfg.Now()
	samples, err := s.store.Samples(ctx, tenantID)
	if err != nil {
		return api.View{}, err
	}
	limits, err := s.thresholds(ctx, tenantID)
	if err != nil {
		return api.View{}, err
	}

	view := api.View{GeneratedAt: now}
	for _, dim := range api.PRDDimensions {
		row := api.DimensionView{Dimension: dim, Unit: dim.Unit(), Threshold: limits[dim]}
		if api.Phase3Coverage[dim] != api.CoverageMetered {
			// AC2: deferred renders as "not metered" with its reason —
			// never as zero, never as within-envelope.
			row.Coverage = api.CoverageDeferred
			row.DeferredReason = api.DeferredReasons[dim]
			view.Dimensions = append(view.Dimensions, row)
			continue
		}
		row.Coverage = api.CoverageMetered
		value, window, ok := domain.DeriveValue(dim, samples)
		if ok {
			row.Value = value
			row.Window = window
			row.State = stateOf(value, limits[dim])
		}
		// Gaps: one per silent data plane, each starting at its last
		// RECORDED window end (AC3). When every plane is silent — or none
		// ever reported and a value cannot be derived — the row itself
		// renders as a gap, and its number fields carry no meaning.
		gapNow := false
		for _, plane := range planesOf(samples) {
			if g, isGap := domain.GapFor(samples, plane, now, s.cfg.GapAfter); isGap {
				row.Gaps = append(row.Gaps, g)
				gapNow = true
			}
		}
		if len(samples) == 0 {
			// No telemetry was ever received: the whole dimension is a gap
			// from as far back as the view can say — never a zero.
			gapNow = true
		}
		if gapNow && !ok {
			row.TelemetryGap = true
			row.State = api.StateUnspecified
			row.Value = 0
		} else if gapNow {
			// The current interval carries both a derived number and a
			// visible gap: the customer sees the partial coverage rather
			// than either a false total or a false zero.
			row.TelemetryGap = true
		}
		view.Dimensions = append(view.Dimensions, row)
	}

	if view.Divergences, err = s.store.Divergences(ctx, tenantID); err != nil {
		return api.View{}, err
	}
	if view.Notices, err = s.store.Notices(ctx, tenantID); err != nil {
		return api.View{}, err
	}
	return view, nil
}

// planesOf lists the data planes that appear in the sample set.
func planesOf(samples []domain.Sample) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range samples {
		if !seen[s.DataPlaneID] {
			seen[s.DataPlaneID] = true
			out = append(out, s.DataPlaneID)
		}
	}
	return out
}

// SetTenantThresholds stores one tenant's envelope configuration (SPEC-0041
// non-functional: thresholds are per-tenant configuration, not compiled in).
func (s *Service) SetTenantThresholds(ctx context.Context, tenantID string, m map[api.Dimension]api.Threshold) error {
	if tenantID == "" {
		return api.ErrMalformed
	}
	override := make(map[api.Dimension]api.Threshold, len(m))
	for k, v := range m {
		override[k] = v
	}
	return s.store.SetTenantThresholds(ctx, tenantID, override)
}
