package ids

import (
	"testing"
	"time"
)

// TestTimeOfRoundTrips asserts TimeOf recovers the millisecond a ULID was
// issued at: the report-store retention sweep ages reports by the attempt
// ULID they are keyed under (SPEC-0037 AC9), so the decode must agree with
// the encode exactly.
func TestTimeOfRoundTrips(t *testing.T) {
	before := time.Now().UnixMilli()
	id := NewULID()
	after := time.Now().UnixMilli()

	got, ok := TimeOf(id)
	if !ok {
		t.Fatalf("TimeOf(%q) must succeed", id)
	}
	millis := got.UnixMilli()
	if millis < before || millis > after {
		t.Errorf("TimeOf(%q) = %d, outside [%d, %d]", id, millis, before, after)
	}
}

// TestTimeOfSpecVector decodes the canonical ULID example: the spec's own
// timestamp 1469918176385 renders as the prefix 01ARYZ6S41, so that prefix
// must decode back to the same millisecond.
func TestTimeOfSpecVector(t *testing.T) {
	var zero [entropyBytes]byte
	id := encode(1469918176385, zero)
	got, ok := TimeOf(id)
	if !ok {
		t.Fatalf("TimeOf(%q) must succeed", id)
	}
	if got.UnixMilli() != 1469918176385 {
		t.Errorf("TimeOf(%q) = %d, want 1469918176385", id, got.UnixMilli())
	}

	if _, ok := TimeOf("7ZZZZZZZZZ0000000000000000"); !ok {
		t.Error("the max 48-bit timestamp must decode")
	}
}

// TestTimeOfRefusesNonULIDs: anything that is not a 26-character Crockford
// base32 ULID reports not-ok rather than guessing a time.
func TestTimeOfRefusesNonULIDs(t *testing.T) {
	for _, bad := range []string{
		"",
		"short",
		"01ARYZ6S41",                  // prefix only
		"01ARYZ6S41000000000000000!",  // illegal character
		"01ARYZ6S4100000000000000000", // too long
		"U1ARYZ6S410000000000000000",  // U is not in the alphabet
		"8ZZZZZZZZZ0000000000000000",  // overflows 48 bits
	} {
		if _, ok := TimeOf(bad); ok {
			t.Errorf("TimeOf(%q) must refuse", bad)
		}
	}
}
