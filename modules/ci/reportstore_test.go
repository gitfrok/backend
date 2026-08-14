package ci_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	ci "github.com/gitfrok/backend/modules/ci"
	"github.com/gitfrok/backend/platform/ids"
)

// fixedClock pins the sweep's notion of now so retention decisions are
// deterministic.
func fixedClock() func() time.Time {
	return func() time.Time { return time.Date(2026, 8, 14, 10, 0, 0, 0, time.UTC) }
}

func newStore(t *testing.T, maxBytes int64) *ci.ScanReportStore {
	t.Helper()
	store, err := ci.NewScanReportStore(ci.NewMemoryReportTier(), maxBytes, fixedClock())
	if err != nil {
		t.Fatalf("NewScanReportStore: %v", err)
	}
	return store
}

// TestWriteReadRoundTrip is the storage precedent for SPEC-0037 AC1: one
// durable, tenant-scoped object per (tenant, repository, job, attempt, scanner
// class), addressed content-last so both object tiers can verify it.
func TestWriteReadRoundTrip(t *testing.T) {
	store := newStore(t, 1<<20)
	job, attempt := ids.NewULID(), ids.NewULID()
	report := []byte(`{"findings":[]}`)

	ref, err := store.Write(t.Context(), "tenant-a", "repo-a", job, attempt, "sast", bytes.NewReader(report))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	// The key shape is the contract the ingest subscriber and the retention
	// sweep both parse: fixed root, then the five address segments, then the
	// content digest.
	parts := strings.Split(ref.Key, "/")
	if len(parts) != 7 {
		t.Fatalf("key %q has %d segments, want 7", ref.Key, len(parts))
	}
	if parts[0] != "ci-scan-reports" {
		t.Fatalf("key root = %q, want ci-scan-reports", parts[0])
	}
	for i, want := range []string{"tenant-a", "repo-a", job, attempt, "sast"} {
		if parts[i+1] != want {
			t.Fatalf("key segment %d = %q, want %q", i+1, parts[i+1], want)
		}
	}
	if len(parts[6]) != 64 {
		t.Fatalf("key does not end in a sha256 digest: %q", parts[6])
	}

	got, err := store.Read(t.Context(), "tenant-a", "repo-a", job, attempt, "sast")
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !bytes.Equal(got, report) {
		t.Fatalf("Read = %q, want %q", got, report)
	}
}

// TestWriteRefusesOversizedWithoutTruncating is SPEC-0037 AC7 at write time:
// a report over the limit is refused whole, and nothing truncated is stored.
func TestWriteRefusesOversizedWithoutTruncating(t *testing.T) {
	store := newStore(t, 16)
	job, attempt := ids.NewULID(), ids.NewULID()

	_, err := store.Write(t.Context(), "tenant-a", "repo-a", job, attempt, "sast", bytes.NewReader(make([]byte, 17)))
	if !errors.Is(err, ci.ErrScanReportTooLarge) {
		t.Fatalf("Write = %v, want ErrScanReportTooLarge", err)
	}
	// Nothing was stored, truncated or otherwise.
	refs, err := store.AttemptReports(t.Context(), "tenant-a", "repo-a", job, attempt)
	if err != nil {
		t.Fatalf("AttemptReports: %v", err)
	}
	if len(refs) != 0 {
		t.Fatalf("the refused write left %v behind", refs)
	}
	// Exactly at the limit is admitted.
	if _, err := store.Write(t.Context(), "tenant-a", "repo-a", job, attempt, "sast", bytes.NewReader(make([]byte, 16))); err != nil {
		t.Fatalf("a report at the limit must be accepted: %v", err)
	}
}

// TestOneReportPerScannerClassPerAttempt is AC1's "one object per scanner
// class per attempt": a second write for the same class is refused, and a
// different class is its own object.
func TestOneReportPerScannerClassPerAttempt(t *testing.T) {
	store := newStore(t, 1<<20)
	job, attempt := ids.NewULID(), ids.NewULID()

	if _, err := store.Write(t.Context(), "tenant-a", "repo-a", job, attempt, "sast", strings.NewReader("first")); err != nil {
		t.Fatalf("Write sast: %v", err)
	}
	if _, err := store.Write(t.Context(), "tenant-a", "repo-a", job, attempt, "sast", strings.NewReader("second")); err == nil {
		t.Fatal("a second report for the same scanner class was accepted")
	}
	if _, err := store.Write(t.Context(), "tenant-a", "repo-a", job, attempt, "secrets", strings.NewReader("third")); err != nil {
		t.Fatalf("Write secrets: %v", err)
	}
	// The original report is untouched by the refused write.
	got, err := store.Read(t.Context(), "tenant-a", "repo-a", job, attempt, "sast")
	if err != nil || string(got) != "first" {
		t.Fatalf("Read = %q, %v", got, err)
	}

	refs, err := store.AttemptReports(t.Context(), "tenant-a", "repo-a", job, attempt)
	if err != nil {
		t.Fatalf("AttemptReports: %v", err)
	}
	classes := map[string]bool{}
	for _, ref := range refs {
		classes[ref.ScannerClass] = true
	}
	if len(refs) != 2 || !classes["sast"] || !classes["secrets"] {
		t.Fatalf("AttemptReports = %v, want one ref each for sast and secrets", refs)
	}
}

// TestAbsentAttemptIsNotFound covers AC4's precondition: a job that persisted
// no report leaves the store saying so, coarsely and without error.
func TestAbsentAttemptIsNotFound(t *testing.T) {
	store := newStore(t, 1<<20)
	job, attempt := ids.NewULID(), ids.NewULID()
	if _, err := store.Read(t.Context(), "tenant-a", "repo-a", job, attempt, "sast"); !errors.Is(err, ci.ErrScanReportNotFound) {
		t.Fatalf("Read = %v, want ErrScanReportNotFound", err)
	}
	refs, err := store.AttemptReports(t.Context(), "tenant-a", "repo-a", job, attempt)
	if err != nil || len(refs) != 0 {
		t.Fatalf("AttemptReports = %v, %v, want empty", refs, err)
	}
}

// TestCrossTenantReadsAreCoarseNotFound: one tenant's report is invisible to
// another tenant — as absent, not as someone else's object (SPEC-0001).
func TestCrossTenantReadsAreCoarseNotFound(t *testing.T) {
	store := newStore(t, 1<<20)
	job, attempt := ids.NewULID(), ids.NewULID()
	if _, err := store.Write(t.Context(), "tenant-a", "repo-a", job, attempt, "sast", strings.NewReader("a's report")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := store.Read(t.Context(), "tenant-b", "repo-a", job, attempt, "sast"); !errors.Is(err, ci.ErrScanReportNotFound) {
		t.Fatalf("tenant-b Read = %v, want ErrScanReportNotFound", err)
	}
	refs, err := store.AttemptReports(t.Context(), "tenant-b", "repo-a", job, attempt)
	if err != nil || len(refs) != 0 {
		t.Fatalf("tenant-b AttemptReports = %v, %v, want empty", refs, err)
	}
}

// TestWriteValidatesIdentifiers: every address segment is caller-supplied, so
// a malformed one is refused before it can become a key.
func TestWriteValidatesIdentifiers(t *testing.T) {
	store := newStore(t, 1<<20)
	job, attempt := ids.NewULID(), ids.NewULID()
	cases := []struct{ tenant, repo, job, attempt, class string }{
		{"", "repo-a", job, attempt, "sast"},
		{"tenant-a", "", job, attempt, "sast"},
		{"tenant-a", "repo-a", "", attempt, "sast"},
		{"tenant-a", "repo-a", job, "", "sast"},
		{"tenant-a", "repo-a", job, attempt, ""},
		{"tenant-a", "repo-a", job, attempt, "SAST"},    // classes are lowercase
		{"tenant-a", "repo-a", job, attempt, "sa st"},   // no spaces
		{"tenant-a", "repo-a", job, attempt, "../evil"}, // no escapes
		{"tenant/a", "repo-a", job, attempt, "sast"},    // no separators in ids
		{"tenant..a", "repo-a", job, attempt, "sast"},   // no traversal shapes
		{"tenant-a", "repo-a", "not-a-ulid", attempt, "sast"},
		{"tenant-a", "repo-a", job, "not-a-ulid", "sast"},
	}
	for _, tc := range cases {
		if _, err := store.Write(t.Context(), tc.tenant, tc.repo, tc.job, tc.attempt, tc.class, strings.NewReader("x")); err == nil {
			t.Errorf("Write accepted (%q, %q, %q, %q, %q)", tc.tenant, tc.repo, tc.job, tc.attempt, tc.class)
		}
	}
}

// TestSweepDeletesOnlyExpiredReports is SPEC-0037 AC9: retention deletes
// reports aged out by their attempt ULID and leaves fresh ones alone.
func TestSweepDeletesOnlyExpiredReports(t *testing.T) {
	tier := ci.NewMemoryReportTier()
	store, err := ci.NewScanReportStore(tier, 1<<20, fixedClock())
	if err != nil {
		t.Fatalf("NewScanReportStore: %v", err)
	}
	oldAttempt := "01ARYZ6S410000000000000000" // issued 2016-07-30 — far past any retention
	freshAttempt := ids.NewULID()
	if _, err := store.Write(t.Context(), "tenant-a", "repo-a", ids.NewULID(), oldAttempt, "sast", strings.NewReader("old")); err != nil {
		t.Fatalf("Write old: %v", err)
	}
	if _, err := store.Write(t.Context(), "tenant-a", "repo-a", ids.NewULID(), freshAttempt, "sast", strings.NewReader("new")); err != nil {
		t.Fatalf("Write new: %v", err)
	}

	deleted, err := store.Sweep(t.Context(), 30*24*time.Hour)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("Sweep deleted %d, want 1", deleted)
	}
}

// TestSweepKeepsFreshReportsReadable re-reads the surviving attempt through
// the exact job that wrote it, to prove the sweep kept the fresh report and
// took only the aged one.
func TestSweepKeepsFreshReportsReadable(t *testing.T) {
	tier := ci.NewMemoryReportTier()
	store, err := ci.NewScanReportStore(tier, 1<<20, fixedClock())
	if err != nil {
		t.Fatalf("NewScanReportStore: %v", err)
	}
	oldJob, oldAttempt := ids.NewULID(), "01ARYZ6S410000000000000000"
	newJob, newAttempt := ids.NewULID(), ids.NewULID()
	if _, err := store.Write(t.Context(), "tenant-a", "repo-a", oldJob, oldAttempt, "sast", strings.NewReader("old")); err != nil {
		t.Fatalf("Write old: %v", err)
	}
	if _, err := store.Write(t.Context(), "tenant-a", "repo-a", newJob, newAttempt, "sast", strings.NewReader("new")); err != nil {
		t.Fatalf("Write new: %v", err)
	}
	if _, err := store.Sweep(t.Context(), 30*24*time.Hour); err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if _, err := store.Read(t.Context(), "tenant-a", "repo-a", oldJob, oldAttempt, "sast"); !errors.Is(err, ci.ErrScanReportNotFound) {
		t.Fatalf("the aged-out report still reads: %v", err)
	}
	got, err := store.Read(t.Context(), "tenant-a", "repo-a", newJob, newAttempt, "sast")
	if err != nil || string(got) != "new" {
		t.Fatalf("the fresh report must survive the sweep: %q, %v", got, err)
	}
}

// TestSweepLeavesWhatItCannotAge: an object whose attempt segment is not a
// ULID cannot be aged, and what cannot be aged is not deleted — retention
// guesses nothing.
func TestSweepLeavesWhatItCannotAge(t *testing.T) {
	tier := ci.NewMemoryReportTier()
	store, err := ci.NewScanReportStore(tier, 1<<20, fixedClock())
	if err != nil {
		t.Fatalf("NewScanReportStore: %v", err)
	}
	// A foreign object under the reports root with an unparseable attempt.
	content := []byte("junk")
	sum := sha256.Sum256(content)
	digest := hex.EncodeToString(sum[:])
	foreign := "ci-scan-reports/tenant-a/repo-a/job-x/not-a-ulid/sast/" + digest
	if _, err := tier.Put(t.Context(), foreign, int64(len(content)), digest, bytes.NewReader(content)); err != nil {
		t.Fatalf("seed foreign object: %v", err)
	}

	deleted, err := store.Sweep(t.Context(), 30*24*time.Hour)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if deleted != 0 {
		t.Fatalf("Sweep deleted %d, want 0", deleted)
	}
	if _, _, err := tier.Get(t.Context(), foreign); err != nil {
		t.Fatalf("the unageable object was deleted: %v", err)
	}
}
