// The bounded trail read says when it truncated (H4, SPEC-0031 AC10): a
// query that hits its limit returns the earliest prefix AND truncated=true,
// so the evidence assembler can mark its sections incomplete instead of
// presenting the prefix as the whole range.
package memory

import (
	"testing"
	"time"

	"github.com/gitfrok/backend/modules/audit/api"
	"github.com/gitfrok/backend/platform/tenancy"
)

func seededStore(t *testing.T, n int) *Store {
	t.Helper()
	s := New()
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID("tenant-trunc"))
	for i := range n {
		if _, err := s.Append(ctx, api.Entry{
			TenantID:   "tenant-trunc",
			Action:     api.Action("findings.scan_ingested"),
			ActorID:    "u-ci",
			Resource:   "scan/scan-1",
			Outcome:    api.OutcomeAllowed,
			OccurredAt: time.Date(2026, 8, 1, 0, 0, i, 0, time.UTC),
			Provenance: api.ProvenanceFirstParty,
		}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	return s
}

// A range holding more records than the limit yields exactly the earliest
// limit-many and reports truncation; a range that fits reports none.
func TestQueryReportsTruncation(t *testing.T) {
	s := seededStore(t, 6)
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID("tenant-trunc"))

	records, truncated, err := s.Query(ctx, api.TrailQuery{Limit: 4})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(records) != 4 {
		t.Fatalf("records = %d, want the earliest 4", len(records))
	}
	for i := 1; i < len(records); i++ {
		if records[i].Seq <= records[i-1].Seq {
			t.Fatalf("records out of chain order at index %d", i)
		}
	}
	if !truncated {
		t.Fatal("a range holding 6 records under limit 4 must report truncation")
	}

	records, truncated, err = s.Query(ctx, api.TrailQuery{Limit: 6})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(records) != 6 || truncated {
		t.Fatalf("a fitting range = %d records truncated=%v, want 6 records and no truncation", len(records), truncated)
	}
}

// Truncation is measured on MATCHING records: a limit that fits the matches
// reports none even when the chain holds more non-matching records.
func TestQueryTruncationCountsOnlyMatchingRecords(t *testing.T) {
	s := seededStore(t, 4)
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID("tenant-trunc"))

	records, truncated, err := s.Query(ctx, api.TrailQuery{
		Actions: []api.Action{"some.other.action"},
		Limit:   1,
	})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(records) != 0 || truncated {
		t.Fatalf("no matches = %d records truncated=%v, want none and no truncation", len(records), truncated)
	}
}
