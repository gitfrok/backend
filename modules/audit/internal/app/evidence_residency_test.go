// The residency section at the assembly seam (T-0033, SPEC-0040): what the
// evidence pack cites (the declaration in force and observed placements,
// AC4), how a change appears (AC6), how silence renders (AC5 — a gap, never
// compliance), and how customer attestation stays out (AC7 — the appendix is
// the only representable place, and the control shapes cannot carry it).
package app

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gitfrok/backend/modules/audit/api"
	"github.com/gitfrok/backend/modules/audit/internal/adapters/memory"
	"github.com/gitfrok/backend/modules/audit/internal/domain"
	"github.com/gitfrok/backend/platform/tenancy"
)

// residencyFixture builds the assembler on a real in-memory chain with a
// configured reporting window; the tenant's facts are seeded through the
// trail's own append surface, exactly as the Residency context's witness
// adapter writes them.
func residencyFixture(t *testing.T, window time.Duration) (*Service, *memory.Store, api.Context, api.PackRequest) {
	t.Helper()
	trail := memory.New()
	svc := New(&stubPDP{allow: true}, stubBus{}, trail, nil, nil, nil).WithResidencyWindow(window)
	svc.now = func() time.Time { return factsNow }
	owner := api.Context{TenantID: "tenant-a", ActorID: "u-owner", ActorRoles: []string{"owner"}, RequestID: "req-residency"}
	req := api.PackRequest{RangeFrom: factsNow.Add(-time.Hour), RangeTo: factsNow.Add(time.Hour)}
	return svc, trail, owner, req
}

// seedResidency appends one residency fact the way the Residency context's
// witness adapter does: first-party, tenant-scoped, server-timed.
func seedResidency(t *testing.T, trail *memory.Store, action, resource string, outcome api.Outcome, detail map[string]string, at time.Time) api.Record {
	t.Helper()
	rec, err := trail.Append(tenancy.WithTenant(context.Background(), tenancy.ID("tenant-a")), api.Entry{
		TenantID:   "tenant-a",
		Action:     api.Action(action),
		ActorID:    "control-plane",
		Resource:   resource,
		Outcome:    outcome,
		Detail:     detail,
		OccurredAt: at,
		Provenance: api.ProvenanceFirstParty,
	})
	if err != nil {
		t.Fatalf("seed residency record: %v", err)
	}
	return rec
}

// readyResidencySection requests the pack, waits for READY and returns the
// pack's chunks.
func readyPackChunks(t *testing.T, svc *Service, owner api.Context, req api.PackRequest) []api.PackChunk {
	t.Helper()
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
		if st.State == api.PackFailed {
			t.Fatalf("pack failed: %s", st.FailureReason)
		}
		if time.Now().After(deadline) {
			t.Fatal("pack never became READY")
		}
		time.Sleep(time.Millisecond)
	}
	chunks, err := svc.GetPack(context.Background(), owner, packID)
	if err != nil {
		t.Fatalf("get pack: %v", err)
	}
	return chunks
}

func residencyChunkOf(t *testing.T, chunks []api.PackChunk) api.Section {
	t.Helper()
	for _, c := range chunks {
		if c.Section != nil && c.Section.Type == api.SectionResidency {
			return *c.Section
		}
	}
	t.Fatal("the pack carries no residency section")
	return api.Section{}
}

var bothPlacements = map[string]string{
	"pinned_cloud": "gke", "pinned_region": "europe-west1",
	"observed_cloud": "gke", "observed_region": "europe-west1",
}

// TestResidencySectionCitesDeclarationInForceAndPlacements is SPEC-0040 AC4:
// the section cites the declaration in force — even when it took effect
// before the range — and the observed placement of every data plane, each
// record carrying both placements. The facts entered through the trail the
// Residency context witnessed onto: placement facts flow registry → witness
// → chain → section, never through a customer claim.
func TestResidencySectionCitesDeclarationInForceAndPlacements(t *testing.T) {
	svc, trail, owner, req := residencyFixture(t, 24*time.Hour)
	seedResidency(t, trail, "residency.declaration.set", "tenant/tenant-a", api.OutcomeAllowed,
		map[string]string{"pinned_cloud": "gke", "pinned_region": "europe-west1"}, factsNow.Add(-48*time.Hour))
	seedResidency(t, trail, "residency.placement.observed", "data_plane/plane-1", api.OutcomeAllowed,
		bothPlacements, req.RangeFrom)
	seedResidency(t, trail, "residency.placement.observed", "data_plane/plane-2", api.OutcomeAllowed,
		bothPlacements, req.RangeFrom)

	chunks := readyPackChunks(t, svc, owner, req)
	if len(chunks) != 8 { // header + five sections + appendix + closing
		t.Fatalf("chunks = %d, want 8: header, FIVE sections, appendix, closing", len(chunks))
	}
	sec := residencyChunkOf(t, chunks)
	if !sec.Complete || len(sec.Gaps) != 0 {
		t.Fatalf("a covered range must assemble complete: %+v", sec)
	}
	if len(sec.Records) != 3 {
		t.Fatalf("records = %d, want the declaration in force plus two placements", len(sec.Records))
	}
	pin := sec.Records[0]
	if pin.Residency == nil || pin.Residency.FactKind != api.ResidencyFactPinning ||
		pin.Residency.PinnedCloud != "gke" || pin.Residency.PinnedRegion != "europe-west1" {
		t.Fatalf("the declaration in force must be cited first: %+v", pin)
	}
	if !pin.OccurredAt.Equal(factsNow.Add(-48 * time.Hour)) {
		t.Fatalf("the cited declaration keeps its effective time: %v", pin.OccurredAt)
	}
	for _, rec := range sec.Records[1:] {
		if rec.Residency.FactKind != api.ResidencyFactPlacement || !rec.Allowed {
			t.Fatalf("placement record wrong: %+v", rec)
		}
		if rec.Residency.ObservedCloud != "gke" || rec.Residency.PinnedCloud != "gke" {
			t.Fatalf("a placement cites BOTH placements: %+v", rec.Residency)
		}
	}
	// Every data plane that reported appears — AC4's "every data plane".
	planes := map[string]bool{}
	for _, rec := range sec.Records[1:] {
		planes[rec.Residency.DataPlaneID] = true
	}
	if !planes["plane-1"] || !planes["plane-2"] {
		t.Fatalf("the section must cite every reporting data plane: %v", planes)
	}
	if ok, reason := domain.VerifySection(sec); !ok {
		t.Fatalf("the residency section must verify like every other: %s", reason)
	}
}

// TestResidencySectionShowsDeclarationChangeWithEffectiveTime is SPEC-0040
// AC6: a declaration change appears as a second PINNING record with its own
// effective time — the pack shows a change, never just the current value.
func TestResidencySectionShowsDeclarationChangeWithEffectiveTime(t *testing.T) {
	svc, trail, owner, req := residencyFixture(t, 24*time.Hour)
	seedResidency(t, trail, "residency.declaration.set", "tenant/tenant-a", api.OutcomeAllowed,
		map[string]string{"pinned_cloud": "gke", "pinned_region": "europe-west1"}, factsNow.Add(-48*time.Hour))
	seedResidency(t, trail, "residency.declaration.set", "tenant/tenant-a", api.OutcomeAllowed,
		map[string]string{"pinned_cloud": "aws", "pinned_region": "eu-central-1"}, factsNow)
	seedResidency(t, trail, "residency.placement.observed", "data_plane/plane-1", api.OutcomeAllowed,
		map[string]string{"pinned_cloud": "aws", "pinned_region": "eu-central-1", "observed_cloud": "aws", "observed_region": "eu-central-1"}, factsNow)

	sec := residencyChunkOf(t, readyPackChunks(t, svc, owner, req))
	var pinnings []api.SectionRecord
	for _, r := range sec.Records {
		if r.Residency != nil && r.Residency.FactKind == api.ResidencyFactPinning {
			pinnings = append(pinnings, r)
		}
	}
	if len(pinnings) != 2 {
		t.Fatalf("both declarations stay on the record: want 2 pinnings, got %d", len(pinnings))
	}
	if pinnings[0].Residency.PinnedCloud != "gke" || pinnings[1].Residency.PinnedCloud != "aws" {
		t.Fatalf("pinnings must appear in chain order: %+v", pinnings)
	}
	if pinnings[0].OccurredAt.Equal(pinnings[1].OccurredAt) {
		t.Fatal("the change keeps its own effective time — the pack shows a change, not the current value")
	}
}

// TestResidencySectionSilenceIsGapNotCompliance is SPEC-0040 AC5: a declared
// tenant whose plane stops reporting renders PLACEMENT_SILENT gaps with
// Complete=false — silence never passes as compliance. Two shapes: the plane
// that went quiet mid-range, and the tenant whose planes never reported at
// all.
func TestResidencySectionSilenceIsGapNotCompliance(t *testing.T) {
	t.Run("mid-range silence", func(t *testing.T) {
		svc, trail, owner, req := residencyFixture(t, 30*time.Minute)
		seedResidency(t, trail, "residency.declaration.set", "tenant/tenant-a", api.OutcomeAllowed,
			map[string]string{"pinned_cloud": "gke", "pinned_region": "europe-west1"}, factsNow.Add(-48*time.Hour))
		// One report at range start; the deadline passes inside the range.
		seedResidency(t, trail, "residency.placement.observed", "data_plane/plane-1", api.OutcomeAllowed,
			bothPlacements, req.RangeFrom)

		sec := residencyChunkOf(t, readyPackChunks(t, svc, owner, req))
		if sec.Complete {
			t.Fatal("a plane silent past its reporting deadline must not render complete")
		}
		want := api.SectionGap{From: req.RangeFrom.Add(30 * time.Minute), To: req.RangeTo, Reason: api.GapPlacementSilent}
		if len(sec.Gaps) != 1 || sec.Gaps[0] != want {
			t.Fatalf("gaps = %+v, want exactly %+v", sec.Gaps, want)
		}
	})
	t.Run("declared but never reported", func(t *testing.T) {
		svc, trail, owner, req := residencyFixture(t, 24*time.Hour)
		seedResidency(t, trail, "residency.declaration.set", "tenant/tenant-a", api.OutcomeAllowed,
			map[string]string{"pinned_cloud": "gke", "pinned_region": "europe-west1"}, factsNow.Add(-48*time.Hour))

		sec := residencyChunkOf(t, readyPackChunks(t, svc, owner, req))
		want := api.SectionGap{From: req.RangeFrom, To: req.RangeTo, Reason: api.GapPlacementSilent}
		if sec.Complete || len(sec.Gaps) != 1 || sec.Gaps[0] != want {
			t.Fatalf("a declared tenant with zero reports gaps the whole range: %+v", sec)
		}
	})
}

// TestResidencySectionUndeclaredTenantIsComplete: no pinning means placement
// was unconstrained — an empty, complete section with no gaps, even with the
// fail-safe zero window.
func TestResidencySectionUndeclaredTenantIsComplete(t *testing.T) {
	svc, _, owner, req := residencyFixture(t, 0)
	sec := residencyChunkOf(t, readyPackChunks(t, svc, owner, req))
	if !sec.Complete || len(sec.Gaps) != 0 || len(sec.Records) != 0 {
		t.Fatalf("an undeclared tenant's residency section is empty and complete: %+v", sec)
	}
}

// TestResidencyZeroWindowFailsSafe: a declaration in force with no
// configured reporting bound renders the whole obligation window as a gap —
// the zero value never lets silence pass (AC5's fail-safe).
func TestResidencyZeroWindowFailsSafe(t *testing.T) {
	svc, trail, owner, req := residencyFixture(t, 0)
	seedResidency(t, trail, "residency.declaration.set", "tenant/tenant-a", api.OutcomeAllowed,
		map[string]string{"pinned_cloud": "gke", "pinned_region": "europe-west1"}, factsNow.Add(-48*time.Hour))
	seedResidency(t, trail, "residency.placement.observed", "data_plane/plane-1", api.OutcomeAllowed,
		bothPlacements, factsNow)

	sec := residencyChunkOf(t, readyPackChunks(t, svc, owner, req))
	want := api.SectionGap{From: req.RangeFrom, To: req.RangeTo, Reason: api.GapPlacementSilent}
	if sec.Complete || len(sec.Gaps) != 1 || sec.Gaps[0] != want {
		t.Fatalf("zero reporting bound must gap the whole window: %+v", sec)
	}
}

// stubAttested is an attested-history source carrying customer-imported
// history — the AC7 probe: it must land in the appendix and nowhere else.
type stubAttested struct{ groups []api.AttestedGroup }

func (s stubAttested) AttestedHistory(context.Context, string, time.Time, time.Time, string) ([]api.AttestedGroup, error) {
	return s.groups, nil
}

// TestAttestedHistoryNeverEntersTheResidencySection is SPEC-0040 AC7: a
// customer attestation is admitted only into the labelled appendix; the
// residency section — a control section — is untouched by it, and the Go
// shapes make the exclusion structural, not a filter.
func TestAttestedHistoryNeverEntersTheResidencySection(t *testing.T) {
	svc, trail, owner, req := residencyFixture(t, 24*time.Hour)
	svc.attested = stubAttested{groups: []api.AttestedGroup{{
		Import: api.HistoryImportedRef{
			EventID: "evt-1", ActorID: "u-owner", ImportID: "imp-1",
			SourceSystem: "customer-jira", RecordCounts: map[string]int64{"approval": 3},
			OccurredAt: factsNow,
		},
		Records: []api.AttestedRecord{{
			RecordKind: "approval", Payload: []byte("customer claims residency compliance"),
			Provenance: api.AttestedProvenance{
				ImportID: "imp-1", SourceSystem: "customer-jira", ForeignHandle: "customer-admin",
				DeclaredAt: factsNow,
			},
		}},
	}}}
	seedResidency(t, trail, "residency.declaration.set", "tenant/tenant-a", api.OutcomeAllowed,
		map[string]string{"pinned_cloud": "gke", "pinned_region": "europe-west1"}, factsNow.Add(-48*time.Hour))
	seedResidency(t, trail, "residency.placement.observed", "data_plane/plane-1", api.OutcomeAllowed,
		bothPlacements, req.RangeFrom)

	chunks := readyPackChunks(t, svc, owner, req)
	sec := residencyChunkOf(t, chunks)
	if len(sec.Records) != 2 {
		t.Fatalf("the residency section holds only the witnessed facts, got %d records", len(sec.Records))
	}
	for _, r := range sec.Records {
		if r.ActorID != "control-plane" {
			t.Fatalf("every residency record is control-plane witnessed: %+v", r)
		}
	}
	var appendix *api.Appendix
	for _, c := range chunks {
		if c.Appendix != nil {
			appendix = c.Appendix
		}
	}
	if appendix == nil || len(appendix.Groups) != 1 || appendix.Label != api.AppendixLabel {
		t.Fatalf("the attestation lands ONLY in the labelled appendix: %+v", appendix)
	}
}

// TestResidencyShapesAdmitNoAttestation is AC7's structural half, as a Go
// type property mirroring SPEC-0032 AC2: no field of the control shapes can
// carry an attested claim — no provenance, no foreign handle, no payload, no
// declared time. A customer attestation has no field to live in.
func TestResidencyShapesAdmitNoAttestation(t *testing.T) {
	banned := []string{"attest", "provenance", "import", "payload", "foreign", "sourcesystem", "sourceref", "sourceinstance", "declaredat"}
	for _, ty := range []reflect.Type{reflect.TypeOf(api.ResidencyDetail{}), reflect.TypeOf(api.SectionRecord{})} {
		for i := 0; i < ty.NumField(); i++ {
			name := strings.ToLower(ty.Field(i).Name)
			for _, b := range banned {
				if strings.Contains(name, b) {
					t.Fatalf("%s.%s: a control-section shape cannot carry an attestation-capable field (%q)",
						ty.Name(), ty.Field(i).Name, b)
				}
			}
		}
	}
}
