package api_test

import (
	"strings"
	"testing"

	"github.com/gitfrok/backend/modules/metering/api"
)

// SPEC-0046 AC4, commercial branch (T-0044): a commercial envelope state
// never renders a repository read-only (SPEC-0041 AC8's prohibition). The
// enforcement vocabulary is the proof: it has exactly three members —
// nothing, reduce-CI-concurrency, warn-and-report — and none of them can
// express a read-only repository, for ANY PRD §6 dimension.
func TestThrottleVocabularyCannotExpressReadOnly(t *testing.T) {
	for _, dim := range api.PRDDimensions {
		action := api.ThrottleFor(dim)
		if action != api.ThrottleNone && action != api.ThrottleReduceCIConcurrency && action != api.ThrottleWarnAndReport {
			t.Fatalf("dimension %s: the throttle vocabulary gained an unnamed action %d", dim, action)
		}
	}
	// States are the same story: WITHIN / NEAR / EXCEEDED describe the
	// envelope, and none of them names a read-only condition.
	for _, state := range []api.State{api.StateWithin, api.StateNear, api.StateExceeded} {
		if strings.Contains(strings.ToLower(state.String()), "read") {
			t.Fatalf("envelope state %v must never read as read-only", state)
		}
	}
}
