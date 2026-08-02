package ids

import "testing"

// Canonical ULID vector: the spec's own example timestamp 1469918176385 renders as the
// 10-character prefix 01ARYZ6S41.
func TestEncodeMatchesTheULIDSpecVector(t *testing.T) {
	var zero [entropyBytes]byte
	got := encode(1469918176385, zero)
	if got[:10] != "01ARYZ6S41" {
		t.Errorf("timestamp prefix = %q, want 01ARYZ6S41 (full: %q)", got[:10], got)
	}
	if got[10:] != "0000000000000000" {
		t.Errorf("zero entropy should render as zeros, got %q", got[10:])
	}
	if all := encode(0, zero); all != "00000000000000000000000000" {
		t.Errorf("zero ULID = %q", all)
	}
	// Max 48-bit timestamp must saturate the first 10 characters, not overflow into entropy.
	if maxTS := encode(1<<48-1, zero); maxTS[:10] != "7ZZZZZZZZZ" {
		t.Errorf("max timestamp = %q, want prefix 7ZZZZZZZZZ", maxTS[:10])
	}
}
