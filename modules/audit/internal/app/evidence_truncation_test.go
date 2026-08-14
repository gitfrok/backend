// The evidence assembler never presents a truncated range as complete (H4,
// SPEC-0031 AC10, SPEC-0032 AC8): when the trail read hits its bounded
// limit, every trail-fed section lands Complete: false with a READ_TRUNCATED
// gap over the unread tail — in the final sections, in the live status, and
// in the streamed chunks.
package app

import (
	"context"
	"testing"
	"time"

	"github.com/gitfrok/backend/modules/audit/api"
)

// truncatingTrail is the fixture trail: appends succeed, and Query answers
// with the configured prefix and truncation flag — the shape a real store
// reports when the range holds more records than the bounded read returned.
type truncatingTrail struct {
	records   []api.Record
	truncated bool
	seq       int64
}

func (t *truncatingTrail) Append(_ context.Context, e api.Entry) (api.Record, error) {
	t.seq++
	return api.Record{Seq: t.seq, TenantID: e.TenantID, Action: e.Action, ActorID: e.ActorID,
		Hash: "hash-trunc", OccurredAt: e.OccurredAt}, nil
}

func (t *truncatingTrail) Verify(context.Context) (api.VerifyResult, error) {
	return api.VerifyResult{OK: true}, nil
}

func (t *truncatingTrail) Query(context.Context, api.TrailQuery) ([]api.Record, bool, error) {
	return t.records, t.truncated, nil
}

func truncationFixture(t *testing.T, trail *truncatingTrail) (*Service, api.Context, api.PackRequest, string) {
	t.Helper()
	pdp := &stubPDP{allow: true}
	svc := New(pdp, stubBus{}, trail, nil, nil, nil)
	svc.now = func() time.Time { return factsNow }

	owner := api.Context{TenantID: "tenant-a", ActorID: "u-owner", ActorRoles: []string{"owner"}, RequestID: "req-trunc"}
	req := api.PackRequest{RangeFrom: factsNow.Add(-time.Hour), RangeTo: factsNow.Add(time.Hour)}
	packID, _, err := svc.RequestPack(context.Background(), owner, req)
	if err != nil {
		t.Fatalf("pack generation: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		st, err := svc.PackStatus(context.Background(), owner, packID)
		if err != nil {
			t.Fatalf("pack status: %v", err)
		}
		if st.State == api.PackReady {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("pack never became READY")
		}
		time.Sleep(time.Millisecond)
	}
	return svc, owner, req, packID
}

// A trail read that hit its limit marks every trail-fed section incomplete
// with the truncation gap — never the earliest prefix rendered as complete.
func TestTruncatedTrailReadMarksSectionsIncomplete(t *testing.T) {
	prefix := []api.Record{{
		Seq: 1, TenantID: "tenant-a", Action: api.Action("codereview.review.approved"),
		ActorID: "u-reviewer", Resource: "merge_request/mr-1", Outcome: api.OutcomeAllowed,
		OccurredAt: factsNow.Add(-30 * time.Minute), Hash: "hash-1",
	}}
	trail := &truncatingTrail{records: prefix, truncated: true}
	svc, owner, req, packID := truncationFixture(t, trail)

	chunks, err := svc.GetPack(context.Background(), owner, packID)
	if err != nil {
		t.Fatalf("get pack: %v", err)
	}
	wantGap := api.SectionGap{From: prefix[0].OccurredAt, To: req.RangeTo, Reason: api.GapReadTruncated}
	// The residency section's declaration-history read truncates too, but on
	// its own terms: the unread tail may hold the pinning in force, so its
	// honest gap covers the whole range (T-0033).
	residencyGap := api.SectionGap{From: req.RangeFrom, To: req.RangeTo, Reason: api.GapReadTruncated}
	checked := 0
	for _, c := range chunks {
		if c.Section == nil || c.Section.Type == api.SectionAccessChanges {
			continue // the access-changes section is fed by its own port, not the trail
		}
		checked++
		if c.Section.Complete {
			t.Errorf("section %s must not render complete over a truncated trail read", c.Section.Type)
		}
		gap := wantGap
		if c.Section.Type == api.SectionResidency {
			gap = residencyGap
		}
		if len(c.Section.Gaps) != 1 || c.Section.Gaps[0] != gap {
			t.Errorf("section %s gaps = %+v, want exactly %+v", c.Section.Type, c.Section.Gaps, gap)
		}
	}
	if checked != 4 {
		t.Fatalf("checked %d trail-fed sections, want 4 (residency reads the trail on its own)", checked)
	}

	// The live status surface carries the same marker.
	st, err := svc.PackStatus(context.Background(), owner, packID)
	if err != nil {
		t.Fatalf("pack status: %v", err)
	}
	for _, ss := range st.SectionCounts {
		if ss.Type == api.SectionAccessChanges {
			continue
		}
		if len(ss.Gaps) != 1 || ss.Gaps[0].Reason != api.GapReadTruncated {
			t.Errorf("status section %s gaps = %+v, want the truncation gap", ss.Type, ss.Gaps)
		}
	}
}

// The same assembly without truncation stays complete and gap-free: the
// marker is a property of the bounded read, not of the sections.
func TestCompleteTrailReadLeavesSectionsComplete(t *testing.T) {
	trail := &truncatingTrail{records: nil, truncated: false}
	svc, owner, _, packID := truncationFixture(t, trail)

	chunks, err := svc.GetPack(context.Background(), owner, packID)
	if err != nil {
		t.Fatalf("get pack: %v", err)
	}
	for _, c := range chunks {
		if c.Section == nil || c.Section.Type == api.SectionAccessChanges {
			continue
		}
		if !c.Section.Complete || len(c.Section.Gaps) != 0 {
			t.Errorf("section %s must stay complete over a full trail read, got %+v", c.Section.Type, c.Section)
		}
	}
}
