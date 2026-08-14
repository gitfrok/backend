// Package domain is the pure residency computation: what contradicts a declaration, and
// nothing else (T-0033, SPEC-0040). No infrastructure here — the judgement must be
// testable without a database and re-derivable by anyone holding the pack's facts.
package domain

// Contradiction reports whether an observed placement violates a declared residency.
// Declared and observed are different facts (SPEC-0040 "Data owned"); the comparison is
// exact on both halves. An observation that reports no cloud or no region cannot be
// reconciled against any declaration, so it contradicts every one: a placement the
// platform cannot place is outside every pinning, and refusing it is the fail-safe reading
// of AC2.
func Contradiction(declaredCloud, declaredRegion, observedCloud, observedRegion string) bool {
	return observedCloud != declaredCloud || observedRegion != declaredRegion
}
