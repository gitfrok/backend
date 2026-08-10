package ids_test

import (
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gitfrok/backend/platform/ids"
)

// contracts/events declares event_id as a ULID used by consumers as an idempotency key. These
// tests pin the three properties consumers actually rely on: it is unique, it is canonical, and it
// sorts by creation time — the last one is what lets a consumer detect reordering after this event
// moves onto Redpanda (ADR-0026).

// TestULIDIsCanonical: 26 characters of Crockford base32, no padding, uppercase.
func TestULIDIsCanonical(t *testing.T) {
	const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	id := ids.NewULID()
	if len(id) != 26 {
		t.Errorf("len = %d, want 26: %q", len(id), id)
	}
	for _, r := range id {
		if !strings.ContainsRune(crockford, r) {
			t.Errorf("character %q is not Crockford base32 (I, L, O and U are excluded): %q", r, id)
		}
	}
	// The timestamp occupies 48 bits, so the first character can never exceed 7.
	if id[0] > '7' {
		t.Errorf("first character %q overflows the 48-bit timestamp: %q", id[0], id)
	}
}

// TestULIDsAreUnique guards the idempotency-key role.
func TestULIDsAreUnique(t *testing.T) {
	const n = 10_000
	seen := make(map[string]struct{}, n)
	for range n {
		id := ids.NewULID()
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate ULID after %d draws: %q", len(seen), id)
		}
		seen[id] = struct{}{}
	}
}

// TestULIDsSortByCreationTime: lexicographic order matches time order, including within the same
// millisecond, so a consumer can order events by id alone.
func TestULIDsSortByCreationTime(t *testing.T) {
	const n = 1_000
	got := make([]string, n)
	for i := range got {
		got[i] = ids.NewULID()
	}
	want := append([]string(nil), got...)
	sort.Strings(want)
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("ULIDs are not monotonic at index %d: generated %q, sorted %q", i, got[i], want[i])
		}
	}
}

// TestULIDsAcrossMillisecondsStillSort: the monotonic counter must reset cleanly on a new
// millisecond rather than carrying a stale value forward.
func TestULIDsAcrossMillisecondsStillSort(t *testing.T) {
	first := ids.NewULID()
	time.Sleep(2 * time.Millisecond)
	second := ids.NewULID()
	if !(first < second) {
		t.Errorf("want %q < %q across a millisecond boundary", first, second)
	}
}

// TestConcurrentGenerationIsSafe: every module in the plane binary shares this generator.
func TestConcurrentGenerationIsSafe(t *testing.T) {
	const workers, each = 16, 200
	var wg sync.WaitGroup
	var mu sync.Mutex
	seen := make(map[string]struct{}, workers*each)
	for range workers {
		wg.Go(func() {
			local := make([]string, each)
			for i := range local {
				local[i] = ids.NewULID()
			}
			mu.Lock()
			defer mu.Unlock()
			for _, id := range local {
				if _, dup := seen[id]; dup {
					t.Errorf("duplicate ULID under concurrency: %q", id)
				}
				seen[id] = struct{}{}
			}
		})
	}
	wg.Wait()
}
