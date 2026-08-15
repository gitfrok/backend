package api

// This file is the T-0044 / SPEC-0046 AC4 cause contract: every read-only
// condition a product surface can show names its CAUSE — the PR-7 durability
// mode (ADR-0018: dual loss, audited override) or an envelope-throttle
// effect — and a bare "read-only" is structurally impossible. The labels are
// contract vocabulary, not UI copy: the API identifies the cause so every
// consumer renders the same distinction.
//
// The durability branch maps from the shard's replica availability
// (ShardStateDegradedReadOnly is the PR-7 mode's product state). The
// commercial branch is the prohibition itself (SPEC-0041 AC8): no envelope
// state and no throttle action may ever produce a read-only condition —
// metering's enforcement vocabulary cannot express one, and nothing on that
// path calls the constructors here.

// ReadOnlyCause is the bounded vocabulary naming WHY a repository is
// read-only (SPEC-0046 AC4).
type ReadOnlyCause string

const (
	// ReadOnlyCauseDurability is the PR-7 durability mode (ADR-0018): a
	// dual-loss fail-safe, reversible only by the audited operator override
	// (ForcePromote). Reads keep working; writes are refused with this cause
	// named.
	ReadOnlyCauseDurability ReadOnlyCause = "durability_mode"
	// ReadOnlyCauseThrottle names an envelope-throttle effect. It exists so
	// the distinction is complete on the wire; SPEC-0041 AC8 forbids any
	// commercial state from ever producing it — the enforcement vocabulary
	// structurally cannot express a read-only repository.
	ReadOnlyCauseThrottle ReadOnlyCause = "envelope_throttle"
)

// ReadOnlyState is one repository's read-only condition with its cause. A
// read-only condition without a cause cannot be constructed: NewReadOnlyState
// refuses an empty cause, and the zero value is the writable condition.
type ReadOnlyState struct {
	ReadOnly bool
	Cause    ReadOnlyCause
}

// NewReadOnlyState constructs a read-only condition naming its cause. An
// empty cause is refused: a bare "read-only" is exactly what SPEC-0046 AC4
// prohibits, so the shape will not represent one.
func NewReadOnlyState(cause ReadOnlyCause) (ReadOnlyState, bool) {
	if cause != ReadOnlyCauseDurability && cause != ReadOnlyCauseThrottle {
		return ReadOnlyState{}, false
	}
	return ReadOnlyState{ReadOnly: true, Cause: cause}, true
}

// Writable is the writable condition: not read-only, no cause to name.
func Writable() ReadOnlyState { return ReadOnlyState{} }

// ReadOnlyFromShard maps the shard's replica availability onto the read-only
// distinction (SPEC-0046 AC4, durability branch): only the degraded-read-only
// shard — the PR-7 durability mode — renders read-only, and it names the
// durability cause. Healthy and recovering shards are writable conditions:
// recovery in progress delays writes, it does not relabel the repository.
func ReadOnlyFromShard(state ShardState) ReadOnlyState {
	if state == ShardStateDegradedReadOnly {
		s, _ := NewReadOnlyState(ReadOnlyCauseDurability)
		return s
	}
	return Writable()
}
