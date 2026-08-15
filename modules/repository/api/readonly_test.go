package api_test

import (
	"testing"

	"github.com/gitfrok/backend/modules/repository/api"
)

// SPEC-0046 AC4 (T-0044): every read-only condition names its cause — the
// PR-7 durability mode or an envelope-throttle effect — and a bare
// "read-only" is structurally impossible.

// The durability branch: only the degraded-read-only shard — the PR-7
// durability mode (ADR-0018) — renders read-only, and it names the
// durability cause. Recovery delays writes; it does not relabel the
// repository.
func TestReadOnlyFromShardNamesTheDurabilityCause(t *testing.T) {
	got := api.ReadOnlyFromShard(api.ShardStateDegradedReadOnly)
	if !got.ReadOnly {
		t.Fatal("a degraded-read-only shard must render read-only")
	}
	if got.Cause != api.ReadOnlyCauseDurability {
		t.Fatalf("cause: got %q, want the durability cause", got.Cause)
	}
	for _, state := range []api.ShardState{api.ShardStateHealthy, api.ShardStateRecovering, api.ShardStateUnspecified} {
		if got := api.ReadOnlyFromShard(state); got.ReadOnly || got.Cause != "" {
			t.Fatalf("shard state %d must stay a writable condition, got %+v", state, got)
		}
	}
}

// A bare read-only is not constructible: an unnamed cause is refused, so no
// consumer can ever render "read-only" without its distinction.
func TestBareReadOnlyIsNotExpressible(t *testing.T) {
	for _, cause := range []api.ReadOnlyCause{"", "unknown", "commercial", "billing"} {
		if _, ok := api.NewReadOnlyState(cause); ok {
			t.Fatalf("cause %q must be refused: a read-only state must name a contract cause", cause)
		}
	}
	for _, cause := range []api.ReadOnlyCause{api.ReadOnlyCauseDurability, api.ReadOnlyCauseThrottle} {
		got, ok := api.NewReadOnlyState(cause)
		if !ok || !got.ReadOnly || got.Cause != cause {
			t.Fatalf("cause %q must construct a read-only state naming itself, got %+v ok=%v", cause, got, ok)
		}
	}
}

// The writable condition names no cause: the zero value is the honest
// default, and Writable() agrees with it.
func TestWritableConditionNamesNoCause(t *testing.T) {
	if w := api.Writable(); w.ReadOnly || w.Cause != "" {
		t.Fatalf("writable condition must carry no read-only and no cause, got %+v", w)
	}
}
