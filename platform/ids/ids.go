// Package ids issues the sortable identifiers contracts/events declares. Pure; no infra, so both
// the domain and app layers may use it (invariant 16).
package ids

import (
	"crypto/rand"
	"encoding/binary"
	"sync"
	"time"
)

// crockford is the ULID alphabet: base32 without I, L, O or U, so a transcribed id cannot be
// confused with a digit.
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// entropyBytes is the ULID random component: 80 bits after the 48-bit timestamp.
const entropyBytes = 10

var state struct {
	sync.Mutex
	lastMillis uint64
	lastRandom [entropyBytes]byte
}

// NewULID returns a ULID: 48 bits of millisecond timestamp followed by 80 bits of entropy,
// rendered as 26 Crockford base32 characters.
//
// Ids drawn in the same millisecond are made monotonic by incrementing the previous entropy rather
// than redrawing it, so lexicographic order is creation order even under load. That is the
// property consumers lean on when using event_id as an idempotency and ordering key, and it has to
// hold after these events move onto Redpanda (ADR-0026), where nothing else preserves
// per-producer order.
func NewULID() string {
	now := uint64(time.Now().UnixMilli())

	state.Lock()
	if now > state.lastMillis {
		state.lastMillis = now
		fillRandom(&state.lastRandom)
	} else {
		// Same millisecond, or a clock that stepped backwards: keep the previous timestamp and
		// step the entropy. Holding lastMillis means a backwards clock cannot produce an id that
		// sorts before one already issued.
		if !increment(&state.lastRandom) {
			// 2^80 ids inside one millisecond is unreachable in practice; if it ever happens,
			// borrowing from the next millisecond is still monotonic.
			state.lastMillis++
			fillRandom(&state.lastRandom)
		}
	}
	millis, entropy := state.lastMillis, state.lastRandom
	state.Unlock()

	return encode(millis, entropy)
}

// fillRandom draws fresh entropy. It panics only if the OS entropy source fails, at which point
// nothing else in the process is trustworthy either.
func fillRandom(b *[entropyBytes]byte) {
	if _, err := rand.Read(b[:]); err != nil {
		panic("ids: crypto/rand unavailable: " + err.Error())
	}
}

// increment adds one to the entropy big-endian, reporting false on overflow.
func increment(b *[entropyBytes]byte) bool {
	for i := len(b) - 1; i >= 0; i-- {
		b[i]++
		if b[i] != 0 {
			return true
		}
	}
	return false
}

// encode renders the 128-bit value as 26 Crockford base32 characters, most significant first.
func encode(millis uint64, entropy [entropyBytes]byte) string {
	// Lay the 128 bits out big-endian: 6 timestamp bytes, then 10 entropy bytes.
	var raw [16]byte
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], millis)
	copy(raw[0:6], ts[2:8])
	copy(raw[6:16], entropy[:])

	// 26 characters × 5 bits = 130 bits, so the first character carries only the top 2 bits of the
	// 128 and can never exceed 7 — which is what keeps a ULID inside its fixed length.
	out := make([]byte, 26)
	for i := range out {
		out[i] = crockford[extract5(raw, i*5-2)] // the first character is left-padded by 2 bits
	}
	return string(out)
}

// extract5 reads the 5 bits starting at bitPos, which is negative for the padded first character
// where the missing high bits read as zero.
func extract5(raw [16]byte, bitPos int) byte {
	var v byte
	for i := 0; i < 5; i++ {
		p := bitPos + i
		if p < 0 {
			v <<= 1
			continue
		}
		v = v<<1 | (raw[p/8]>>(7-uint(p%8)))&1
	}
	return v
}
