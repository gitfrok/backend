// Package api is the Metering context's in-process surface (T-0034, SPEC-0041,
// ADR-0061): authoritative fair-use counters derived in the control plane from
// telemetry RECEIVED over the agent channel, envelope evaluation, and the
// customer-visible usage view.
//
// The authority rules this surface is built around (ADR-0061):
//
//  1. The control plane counts. A data plane's own report (UsageSample) is
//     operational input; it never changes a counter. Where the two diverge,
//     the divergence is a health finding with both numbers shown, not an
//     adjustment (SPEC-0041 AC1).
//  2. Coverage is explicit. Every PRD §6 dimension is metered or deferred with
//     its reason; a deferred dimension renders as "not metered", never as zero
//     or within-envelope (AC2).
//  3. Missing telemetry is a visible gap, never zero usage (AC3).
//  4. Enforcement is throttle-and-notify. Nothing this surface produces can
//     block git push/fetch/clone/reads (AC7) or make a repository read-only
//     (AC8); read-only stays reserved for the PR-7 durability mode (ADR-0018).
//  5. The customer and the control plane read the same counters: the view and
//     every envelope decision are derived from the one ledger (AC10).
package api

import (
	"context"
	"errors"
	"time"
)

// ErrDenied is the coarse refusal of the usage view: not-found, cross-tenant
// and unauthorized are indistinguishable (SPEC-0001).
var ErrDenied = errors.New("metering: usage view unavailable")

// ErrMalformed refuses an ingest whose shape the contract does not name.
var ErrMalformed = errors.New("metering: malformed sample")

// Dimension is one PRD §6 fair-use dimension.
type Dimension int

const (
	DimensionUnspecified Dimension = iota
	DimensionSeats
	DimensionRepositoryCount
	DimensionRepositoryStorage
	DimensionCIMinutes
	DimensionCIConcurrency
	DimensionScanVolume
	DimensionIndexSize
	DimensionEgress
)

// PRDDimensions is the full PRD §6 list in its stable display order. The
// usage view carries one row per entry — the list itself is the coverage
// statement (SPEC-0041 AC2).
var PRDDimensions = []Dimension{
	DimensionSeats,
	DimensionRepositoryCount,
	DimensionRepositoryStorage,
	DimensionCIMinutes,
	DimensionCIConcurrency,
	DimensionScanVolume,
	DimensionIndexSize,
	DimensionEgress,
}

// String is the coarse dimension name carried in notices and prose.
func (d Dimension) String() string {
	switch d {
	case DimensionSeats:
		return "seats"
	case DimensionRepositoryCount:
		return "repository_count"
	case DimensionRepositoryStorage:
		return "repository_storage"
	case DimensionCIMinutes:
		return "ci_minutes"
	case DimensionCIConcurrency:
		return "ci_concurrency"
	case DimensionScanVolume:
		return "scan_volume"
	case DimensionIndexSize:
		return "index_size"
	case DimensionEgress:
		return "egress"
	default:
		return "unspecified"
	}
}

// Unit is the coarse unit prose a dimension's counters are expressed in.
func (d Dimension) Unit() string {
	switch d {
	case DimensionSeats, DimensionRepositoryCount, DimensionCIConcurrency:
		return "count"
	case DimensionCIMinutes:
		return "minutes"
	case DimensionRepositoryStorage, DimensionScanVolume, DimensionIndexSize, DimensionEgress:
		return "bytes"
	default:
		return ""
	}
}

// Coverage says whether the control plane meters a dimension in this phase
// (SPEC-0041 AC2).
type Coverage int

const (
	CoverageUnspecified Coverage = iota
	CoverageMetered
	CoverageDeferred
)

// Phase-3 coverage decision (T-0034, SPEC-0041 in-scope): what the control
// plane can derive from telemetry it RECEIVES, and what is deferred rather
// than estimated (ADR-0061 §1).
//
// Metered: CI minutes, egress and scan volume stream as cumulative counters;
// repository count and CI concurrency arrive as gauges. Deferred: seats
// (identity events live on the data plane; the control plane holds none),
// repository storage and index size (sizes, not events — the likeliest
// deferrals T-0034 names).
var Phase3Coverage = map[Dimension]Coverage{
	DimensionSeats:             CoverageDeferred,
	DimensionRepositoryCount:   CoverageMetered,
	DimensionRepositoryStorage: CoverageDeferred,
	DimensionCIMinutes:         CoverageMetered,
	DimensionCIConcurrency:     CoverageMetered,
	DimensionScanVolume:        CoverageMetered,
	DimensionIndexSize:         CoverageDeferred,
	DimensionEgress:            CoverageMetered,
}

// DeferredReasons is the honest reason each deferred dimension is not
// metered in Phase 3. A deferred dimension renders this reason — never zero,
// never within-envelope (SPEC-0041 AC2).
var DeferredReasons = map[Dimension]string{
	DimensionSeats:             "identity events live on the data plane; the control plane cannot derive seats from the telemetry it receives",
	DimensionRepositoryStorage: "a size, not an event: storage totals are not streamed as telemetry in Phase 3",
	DimensionIndexSize:         "a size, not an event: index size is not streamed as telemetry in Phase 3",
}

// State is one dimension's envelope condition, computed in the control plane.
type State int

const (
	StateUnspecified State = iota
	StateWithin
	StateNear     // the notification threshold, BEFORE breach (SPEC-0041 AC4)
	StateExceeded // throttle-and-notify; git untouched (AC7)
)

// String is the coarse state name carried in notices and decisions.
func (s State) String() string {
	switch s {
	case StateWithin:
		return "WITHIN"
	case StateNear:
		return "NEAR"
	case StateExceeded:
		return "EXCEEDED"
	default:
		return "UNSPECIFIED"
	}
}

// Trend names the direction a notice cites (SPEC-0041 AC4: name the dimension
// AND its trend).
type Trend int

const (
	TrendFlat Trend = iota
	TrendRising
	TrendFalling
)

// String is the coarse trend name a notice carries.
func (t Trend) String() string {
	switch t {
	case TrendRising:
		return "rising"
	case TrendFalling:
		return "falling"
	default:
		return "flat"
	}
}

// Interval is a recorded window boundary. Boundaries are recorded with the
// samples that declare them, never inferred from wall-clock at read time
// (SPEC-0041 non-functional).
type Interval struct {
	Start time.Time
	End   time.Time
}

// Telemetry is one TelemetrySample received over the agent channel, shaped
// for the app layer. The agent wire adapter maps the contract message onto
// this value; nothing above that adapter sees the proto.
type Telemetry struct {
	MessageID string
	Window    Interval
	Gauges    map[string]float64
	Counters  map[string]float64
}

// Usage is one UsageSample received over the agent channel: the data plane's
// OWN totals. Operational input, never the billing number (ADR-0061 §2).
type Usage struct {
	MessageID         string
	Window            Interval
	CIMinutes         float64
	StorageBytes      float64
	EgressBytes       float64
	SeatCount         int64
	CIConcurrencyPeak float64
	ScanBytes         float64
	RepositoryCount   int64
	IndexBytes        float64
}

// Threshold is one dimension's per-tenant envelope configuration. Thresholds
// and envelope values are per-tenant configuration, never compiled in
// (SPEC-0041 non-functional).
type Threshold struct {
	Envelope float64
	Notify   float64
}

// Notice is the AC4 notification: fired on the way to the envelope (StateNear)
// and again on breach (StateExceeded), naming the dimension and its trend.
type Notice struct {
	TenantID   string
	Dimension  Dimension
	State      State
	Value      float64
	Threshold  float64
	Window     Interval
	Trend      Trend
	OccurredAt time.Time
}

// Notifier delivers one notice out-of-band. The production shape is an email
// to the platform engineer (SPEC-0041 AC4); the composition injects the
// transport, and a dev posture logs it.
type Notifier interface {
	Notify(ctx context.Context, n Notice) error
}

// Divergence is one AC1 health finding: the data plane's self-reported total
// and the control plane's authoritative counter disagree over one interval.
// Both numbers are shown; the counter is never adjusted.
type Divergence struct {
	TenantID          string
	DataPlaneID       string
	Dimension         Dimension
	ControlPlaneValue float64
	ReportedValue     float64
	Window            Interval
	DetectedAt        time.Time
}

// Decision is one dimension's envelope condition with the counter and the
// interval it was made from: the evidence an envelope decision cites (G6),
// and the number the customer reads (AC10).
type Decision struct {
	Dimension Dimension
	State     State
	Value     float64
	Window    Interval
	Threshold Threshold
}

// ThrottleAction is the bounded enforcement vocabulary (SPEC-0041 AC5, AC6).
// It deliberately cannot express blocking a git operation (AC7) or making a
// repository read-only (AC8): the only shapes it has are reducing CI
// concurrency with a queue cap whose delays are visible on the job, and
// warning/reporting on storage-class dimensions.
type ThrottleAction int

const (
	// ThrottleNone enforces nothing: the dimension is within its envelope or
	// not enforceable in this phase.
	ThrottleNone ThrottleAction = iota
	// ThrottleReduceCIConcurrency reduces job concurrency and caps queue depth
	// (AC5): running jobs finish, queued jobs are delayed with the cause
	// visible on the job, and none are dropped.
	ThrottleReduceCIConcurrency
	// ThrottleWarnAndReport warns and reports on a storage or index dimension
	// (AC6); it may throttle new large-object writes. Nothing already stored
	// becomes unreadable.
	ThrottleWarnAndReport
)

// ThrottleFor is the enforcement a breached dimension produces. It is the
// single place the AC7/AC8 promise is encoded: no dimension yields an action
// that touches git availability or repository read-only state.
func ThrottleFor(d Dimension) ThrottleAction {
	switch d {
	case DimensionCIMinutes, DimensionCIConcurrency:
		return ThrottleReduceCIConcurrency
	case DimensionRepositoryStorage, DimensionIndexSize, DimensionScanVolume:
		return ThrottleWarnAndReport
	default:
		return ThrottleNone
	}
}

// EnvelopeDesiredState is the desired state the data plane applies (SPEC-0041
// AC9): the control plane never reaches into the cluster to enforce it.
type EnvelopeDesiredState struct {
	Generation       int64
	Decisions        []Decision
	MaxCIConcurrency int32 // set when a CI dimension is EXCEEDED; 0 = unchanged
	QueueDepthCap    int64 // queued jobs are delayed, never dropped (AC5)
}

// DimensionView is one row of the usage view. Numeric fields are meaningful
// only when Coverage is CoverageMetered and TelemetryGap is false: the shape
// cannot represent "unmeasured" as a number (SPEC-0041 AC2, AC3).
type DimensionView struct {
	Dimension      Dimension
	Coverage       Coverage
	State          State
	TelemetryGap   bool
	Gaps           []Interval
	Value          float64
	Threshold      Threshold
	Unit           string
	Window         Interval
	DeferredReason string
}

// View is the tenant's usage view: the same ledger every envelope decision
// was made from (SPEC-0041 AC10).
type View struct {
	Dimensions  []DimensionView
	Divergences []Divergence
	Notices     []Notice
	GeneratedAt time.Time
}

// Sink is the ingestion seam: the agent context forwards every TelemetrySample
// and UsageSample it RECEIVES on the channel to whatever the composition root
// attaches here. It is a port in the metering context's own terms; the agent
// context cannot tell what counts on the other side (invariant 14).
type Sink interface {
	IngestTelemetry(ctx context.Context, tenantID, dataPlaneID string, t Telemetry) error
	IngestUsage(ctx context.Context, tenantID, dataPlaneID string, u Usage) error
}

// Reader is the usage-view half of the surface the gRPC door serves. The
// read is authorized through the PDP before any ledger is touched; a
// refusal is coarse (SPEC-0001).
type Reader interface {
	ReadUsageView(ctx context.Context, vc ViewContext) (View, error)
}

// ActionUsageViewRead is the policy action the PDP decides on for a usage
// view read; governance/policies grants it to owner and member roles.
const ActionUsageViewRead = "usage.view.read"

// ViewContext is the verified identity context one usage-view read carries.
// The BFF supplies it from the session; nothing on the wire can assert a
// counter, a state, or an authorization result.
type ViewContext struct {
	TenantID   string
	ActorID    string
	ActorRoles []string
	RequestID  string
}

// EnvelopeDelivery is the AC9 seam: the agent channel polls the newest
// desired state for a tenant's stream and reports the data plane's ack back.
// The control plane never reaches into the cluster to enforce anything — it
// states the envelope, the data plane applies it (SPEC-0041 AC9).
type EnvelopeDelivery interface {
	// LatestDesiredState returns the newest evaluated envelope desired state.
	// ok is false when the tenant has no evaluation yet.
	LatestDesiredState(ctx context.Context, tenantID string) (EnvelopeDesiredState, bool, error)
	// AckDesiredState records the data plane's acknowledgement of one
	// generation: applied, or the coarse error prose it reported.
	AckDesiredState(ctx context.Context, tenantID string, generation int64, applied bool, errMsg string) error
}

// Ack is one recorded data-plane acknowledgement of a desired-state
// generation (SPEC-0041 AC9).
type Ack struct {
	Generation int64
	Applied    bool
	Error      string
	AckedAt    time.Time
}

// Config carries the per-environment knobs. None of them is a threshold:
// thresholds are tenant configuration (Thresholds default map plus
// per-tenant overrides), while these are derivation parameters.
type Config struct {
	Now func() time.Time
	// GapAfter bounds how long a data plane may be silent before the interval
	// following its last recorded window renders as a gap (SPEC-0041 AC3).
	GapAfter time.Duration
	// DivergenceTolerance is the relative difference above which a data
	// plane's self-report and the control plane's counter become a health
	// finding (SPEC-0041 AC1).
	DivergenceTolerance float64
	// ThrottledConcurrency and QueueDepthCap are the AC5 enforcement values a
	// breached CI dimension produces.
	ThrottledConcurrency int32
	QueueDepthCap        int64
	// DefaultThresholds apply to every tenant without an override;
	// per-tenant overrides are stored, not compiled (SPEC-0041
	// non-functional).
	DefaultThresholds map[Dimension]Threshold
}
