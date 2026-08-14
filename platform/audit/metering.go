// Fair-use metering audit vocabulary (T-0034, SPEC-0041, ADR-0061).
//
// Metering is G6 and G9: envelope decisions cite the counters and interval
// they were made from (AC10), and the gaps and divergences the metering
// surface observes are visible product state, not silent zeros (AC2, AC3).
// Every notice fired on the way to an envelope, every breach, and every
// divergence between a data plane's self-report and the control plane's
// counters appends an immutable record here. The dotted vocabulary lives in
// the audit contract's comment; adding one is additive by construction.
//
// No record in this file carries a credential or sample payload: dimensions,
// states, values, windows and coarse prose only (ADR-0007: no payloads in
// audit events).
package audit

import "time"

const (
	// ActionMeteringThresholdNotice records one AC4 notification: a
	// dimension crossing its notification threshold on the way to the
	// envelope (NEAR) or crossing the envelope itself (EXCEEDED), with the
	// counter, the threshold and the trend the notice cited.
	ActionMeteringThresholdNotice = "metering.threshold.notice"
	// ActionMeteringDivergence records one AC1 health finding: a data
	// plane's self-reported total and the control plane's authoritative
	// counter disagreeing over one interval. Both numbers are on the
	// record; the counter is never adjusted (ADR-0061 §2).
	ActionMeteringDivergence = "metering.divergence"
)

// MeteringThresholdNotice records one threshold crossing the usage view and
// the platform engineer both see (SPEC-0041 AC4). It cites the counter and
// the interval the decision was made from (G6): the same numbers the
// customer reads (AC10).
type MeteringThresholdNotice struct {
	TenantID    string
	Dimension   string // api.Dimension.String(): coarse vocabulary, never a payload
	State       string // "NEAR" or "EXCEEDED"
	Value       float64
	Threshold   float64
	Trend       string // "rising", "falling" or "flat"
	WindowStart time.Time
	WindowEnd   time.Time
	OccurredAt  time.Time
}

func (MeteringThresholdNotice) EventName() string { return EventAudit }
func (MeteringThresholdNotice) Action() string    { return ActionMeteringThresholdNotice }
func (e MeteringThresholdNotice) Tenant() string  { return e.TenantID }

// MeteringDivergence records one divergence health finding (SPEC-0041 AC1).
// It carries BOTH numbers — the control plane's authoritative counter and
// the data plane's self-reported total — because a divergence is judged by
// reading the two side by side, and the record is the evidence that the
// counter was never adjusted instead (ADR-0061 §2).
type MeteringDivergence struct {
	TenantID          string
	DataPlaneID       string
	Dimension         string
	ControlPlaneValue float64
	ReportedValue     float64
	WindowStart       time.Time
	WindowEnd         time.Time
	OccurredAt        time.Time
}

func (MeteringDivergence) EventName() string { return EventAudit }
func (MeteringDivergence) Action() string    { return ActionMeteringDivergence }
func (e MeteringDivergence) Tenant() string  { return e.TenantID }
