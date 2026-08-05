// Package domain holds the hash chain — the part of the audit log that makes tampering detectable.
//
// No infrastructure here (invariant 24): the chain is pure computation over record content, which is
// also what lets it be tested without a database and re-verified anywhere, including by an auditor
// who has only an export.
//
// SPEC-0003 AC2, ADR-0007.
package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Fields is the canonical content of one record, in the order it is hashed.
//
// Canonical ordering is the whole game. If two implementations serialise the same record differently
// — map iteration order, timestamp precision, field order — they compute different hashes and the
// chain reports tampering that never happened. That failure mode is worse than no verifier, because
// it trains people to ignore alarms.
type Fields struct {
	Seq        int64
	TenantID   string
	Action     string
	ActorID    string
	Resource   string
	Outcome    string
	Detail     map[string]string
	OccurredAt time.Time
}

// Canonical renders the fields deterministically.
//
// Length-prefixed, not delimiter-joined: with a plain separator, a value containing that separator
// could be split differently by an attacker who controls two adjacent fields — resource="a|b",
// actor="" and resource="a", actor="b" would hash identically, so one could be swapped for the
// other without detection. Prefixing each value with its byte length removes the ambiguity.
func (f Fields) Canonical() string {
	var b strings.Builder
	write := func(name, v string) {
		fmt.Fprintf(&b, "%s:%d:%s\n", name, len(v), v)
	}
	write("seq", fmt.Sprintf("%d", f.Seq))
	write("tenant", f.TenantID)
	write("action", f.Action)
	write("actor", f.ActorID)
	write("resource", f.Resource)
	write("outcome", f.Outcome)
	// UTC and nanoseconds: a record hashed in one zone must verify in another, and truncating to
	// seconds would let two events inside the same second swap places undetected.
	write("occurred_at", f.OccurredAt.UTC().Format(time.RFC3339Nano))

	keys := make([]string, 0, len(f.Detail))
	for k := range f.Detail {
		keys = append(keys, k)
	}
	sort.Strings(keys) // Go map order is randomised; unsorted keys would make the hash unstable
	for _, k := range keys {
		write("detail."+k, f.Detail[k])
	}
	return b.String()
}

// Hash computes this record's hash, binding it to prevHash.
//
// Including the predecessor's hash is what makes the structure a chain rather than a list of
// checksums: altering record N changes its hash, which invalidates N+1's binding, and so on to the
// head. An attacker must therefore rewrite every subsequent record, not just the one they care about.
func Hash(prevHash string, f Fields) string {
	h := sha256.New()
	h.Write([]byte("prev:" + prevHash + "\n"))
	h.Write([]byte(f.Canonical()))
	return hex.EncodeToString(h.Sum(nil))
}

// Link is one step of a chain, as verification sees it.
type Link struct {
	Fields   Fields
	PrevHash string
	Hash     string
}

// VerifyChain walks links in order and returns the sequence number and reason of the first fault.
// ok is true when the chain is intact.
//
// Three distinct faults, reported separately because they are different incidents: a recomputed hash
// mismatch means a record's content was altered; a broken link means a record was replaced or
// re-hashed in isolation; a sequence gap means a record was removed. An investigator should not have
// to infer which happened from a single "invalid" flag.
func VerifyChain(links []Link) (ok bool, brokenAt int64, reason string) {
	var prev string
	var lastSeq int64
	for i, l := range links {
		if i > 0 && l.Fields.Seq != lastSeq+1 {
			return false, l.Fields.Seq, fmt.Sprintf(
				"sequence gap: expected %d, found %d — a record was removed", lastSeq+1, l.Fields.Seq)
		}
		if l.PrevHash != prev {
			return false, l.Fields.Seq, "broken link: stored prev_hash does not match the previous record's hash"
		}
		if want := Hash(prev, l.Fields); want != l.Hash {
			return false, l.Fields.Seq, "hash mismatch: record content was altered after it was written"
		}
		prev = l.Hash
		lastSeq = l.Fields.Seq
	}
	return true, 0, ""
}
