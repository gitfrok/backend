package domain

import (
	"strings"
	"testing"
	"time"
)

// SPEC-0003 AC2: entries are hash-chained and a verifier detects tampering.
//
// The positive case is the cheap half — a verifier that returns "ok" unconditionally passes it. What
// these tests are really for is the negative half: each way of tampering must be *caught*, and each
// must be reported as the incident it actually is, because a mutated record and a deleted one call
// for different responses.

func at(sec int) time.Time { return time.Unix(int64(1780000000+sec), 0).UTC() }

func fields(seq int64, action string) Fields {
	return Fields{
		Seq:        seq,
		TenantID:   "acme",
		Action:     action,
		ActorID:    "user-1",
		Resource:   "repo/01H",
		Outcome:    "DENIED",
		Detail:     map[string]string{"sqlstate": "42501", "policy": "tenant_isolation"},
		OccurredAt: at(int(seq)),
	}
}

// chain builds n correctly linked records.
func chain(n int) []Link {
	var out []Link
	var prev string
	for i := 1; i <= n; i++ {
		f := fields(int64(i), "tenant.isolation.violation")
		h := Hash(prev, f)
		out = append(out, Link{Fields: f, PrevHash: prev, Hash: h})
		prev = h
	}
	return out
}

func TestIntactChainVerifies(t *testing.T) {
	ok, at, reason := VerifyChain(chain(5))
	if !ok {
		t.Fatalf("intact chain reported broken at %d: %s", at, reason)
	}
}

// The core of AC2: alter a stored record and the chain must not verify.
func TestMutatedRecordIsDetected(t *testing.T) {
	c := chain(5)
	c[2].Fields.Resource = "repo/somebody-elses" // the row an attacker would edit

	ok, brokenAt, reason := VerifyChain(c)
	if ok {
		t.Fatal("a mutated record verified — the chain is not tamper-evident (SPEC-0003 AC2)")
	}
	if brokenAt != 3 {
		t.Errorf("reported broken at %d, want 3 (the mutated record)", brokenAt)
	}
	if !strings.Contains(reason, "content was altered") {
		t.Errorf("reason = %q, want it to name content alteration", reason)
	}
}

// Re-hashing the mutated record locally is the obvious next move for an attacker, and it must fail
// too: the record now disagrees with its successor's prev_hash. This is what distinguishes a chain
// from per-row checksums, so it gets its own test.
func TestMutatedRecordWithRecomputedHashIsStillDetected(t *testing.T) {
	c := chain(5)
	c[2].Fields.Resource = "repo/somebody-elses"
	c[2].Hash = Hash(c[2].PrevHash, c[2].Fields) // attacker fixes up the local hash

	ok, brokenAt, reason := VerifyChain(c)
	if ok {
		t.Fatal("a re-hashed record verified — per-record hashes are not chained (SPEC-0003 AC2)")
	}
	if brokenAt != 4 {
		t.Errorf("reported broken at %d, want 4 — the successor is where the forgery surfaces", brokenAt)
	}
	if !strings.Contains(reason, "broken link") {
		t.Errorf("reason = %q, want it to name a broken link", reason)
	}
}

// Deleting a record is tampering too, and it is invisible to hashes alone: the survivors are all
// individually valid. The sequence check is what catches it.
func TestDeletedRecordIsDetected(t *testing.T) {
	c := chain(5)
	c = append(c[:2], c[3:]...) // remove seq 3

	ok, brokenAt, reason := VerifyChain(c)
	if ok {
		t.Fatal("a deleted record went undetected — append-only is unenforced (SPEC-0003 AC1/AC2)")
	}
	if !strings.Contains(reason, "sequence gap") {
		t.Errorf("reason = %q, want it to name a sequence gap", reason)
	}
	if brokenAt != 4 {
		t.Errorf("reported broken at %d, want 4 (the record that follows the hole)", brokenAt)
	}
}

// Truncating the head is the one attack a self-contained chain cannot detect, and pretending
// otherwise would be worse than admitting it. Recorded as a test so the limit is visible in the
// suite rather than only in prose.
func TestTruncationOfTheHeadIsNotDetectableWithoutAnExternalAnchor(t *testing.T) {
	full := chain(5)
	truncated := full[:3]

	ok, _, _ := VerifyChain(truncated)
	if !ok {
		t.Fatal("a truncated-but-internally-consistent chain failed to verify; " +
			"the test's premise is wrong, not the implementation")
	}
	// Documenting the consequence: detecting this needs the head hash anchored somewhere the
	// database cannot rewrite — an external witness, a periodic notarisation, or WORM storage.
	// ADR-0007 does not decide that, and T-0006 does not add it.
}

// Reordering must not verify: swapping two records keeps every field intact, so only the chain
// links can catch it.
func TestReorderedRecordsAreDetected(t *testing.T) {
	c := chain(5)
	c[1], c[2] = c[2], c[1]

	if ok, _, _ := VerifyChain(c); ok {
		t.Fatal("reordered records verified — the chain does not fix an order (SPEC-0003 AC2)")
	}
}

// The canonical form must be stable across map iteration order, which Go randomises. Without this,
// verification would fail intermittently on records that were never touched — an alarm that cries
// wolf, which is how verifiers get switched off.
func TestCanonicalFormIsStableAcrossMapOrder(t *testing.T) {
	a := fields(1, "x")
	b := fields(1, "x")
	b.Detail = map[string]string{"policy": "tenant_isolation", "sqlstate": "42501"} // inserted in the other order

	for i := 0; i < 50; i++ {
		if Hash("", a) != Hash("", b) {
			t.Fatal("hash depends on map iteration order — verification would fail at random")
		}
	}
}

// Length prefixing: two different records must not share a canonical form. Without prefixes,
// resource="a|b" + actor="" and resource="a" + actor="b" could serialise identically, letting one be
// substituted for the other.
func TestAdjacentFieldsCannotBeConfused(t *testing.T) {
	x := fields(1, "act")
	x.Resource, x.ActorID = "a:b", ""
	y := fields(1, "act")
	y.Resource, y.ActorID = "a", "b"

	if Hash("", x) == Hash("", y) {
		t.Error("two distinct records hash identically — field boundaries are ambiguous")
	}
}

// Timestamps must hash identically regardless of the zone they arrive in, or the same record
// verified on another machine would look tampered with.
func TestTimestampZoneDoesNotAffectTheHash(t *testing.T) {
	utc := fields(1, "act")
	other := fields(1, "act")
	other.OccurredAt = utc.OccurredAt.In(time.FixedZone("elsewhere", 5*3600))

	if Hash("", utc) != Hash("", other) {
		t.Error("hash depends on the timestamp's zone; the same record would fail verification elsewhere")
	}
}
