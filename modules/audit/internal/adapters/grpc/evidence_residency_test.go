// Wire parity for the residency section (T-0033): the additive governance
// contract values (SECTION_TYPE_RESIDENCY, GAP_REASON_PLACEMENT_SILENT, the
// ResidencyFactKind enum, ResidencyRecord) are exactly what the adapter
// renders — checked against the numeric contract values, so a wire drift
// fails here, not in a consumer.
package grpc

import (
	"testing"
	"time"

	auditv1 "github.com/gitfrok/backend/gen/proto/audit/v1"
	"github.com/gitfrok/backend/modules/audit/api"
)

func TestResidencyWireParity(t *testing.T) {
	at := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	sec := api.Section{
		Type:     api.SectionResidency,
		Complete: false,
		Gaps:     []api.SectionGap{{From: at, To: at.Add(time.Hour), Reason: api.GapPlacementSilent}},
		Records: []api.SectionRecord{{
			ChainSeq: 7, RecordHash: "hash-7", ActorID: "control-plane",
			Resource: "data_plane/plane-1", Action: "residency.placement.observed",
			Allowed: true, OccurredAt: at,
			Residency: &api.ResidencyDetail{
				FactKind: api.ResidencyFactPlacement, DataPlaneID: "plane-1",
				PinnedCloud: "gke", PinnedRegion: "europe-west1",
				ObservedCloud: "gke", ObservedRegion: "europe-west1",
			},
		}},
	}
	pb := sectionOf(sec)

	if pb.Type != auditv1.SectionType_SECTION_TYPE_RESIDENCY || int32(pb.Type) != 5 {
		t.Fatalf("section type = %v (%d), want SECTION_TYPE_RESIDENCY (5)", pb.Type, int32(pb.Type))
	}
	if len(pb.Gaps) != 1 || pb.Gaps[0].Reason != auditv1.GapReason_GAP_REASON_PLACEMENT_SILENT || int32(pb.Gaps[0].Reason) != 4 {
		t.Fatalf("gap reason = %v, want GAP_REASON_PLACEMENT_SILENT (4)", pb.Gaps[0].Reason)
	}
	rec := pb.Records[0]
	res := rec.GetResidency()
	if res == nil {
		t.Fatal("the record must render its residency detail")
	}
	if res.FactKind != auditv1.ResidencyFactKind_RESIDENCY_FACT_KIND_PLACEMENT || int32(res.FactKind) != 2 {
		t.Fatalf("fact kind = %v (%d), want PLACEMENT (2)", res.FactKind, int32(res.FactKind))
	}
	if res.DataPlaneId != "plane-1" || res.PinnedCloud != "gke" || res.PinnedRegion != "europe-west1" ||
		res.ObservedCloud != "gke" || res.ObservedRegion != "europe-west1" {
		t.Fatalf("residency record fields wrong: %+v", res)
	}

	// The remaining fact kinds map onto their dedicated enum values, pairwise
	// distinguishable on the wire.
	kinds := map[api.ResidencyFactKind]auditv1.ResidencyFactKind{
		api.ResidencyFactPinning:                auditv1.ResidencyFactKind_RESIDENCY_FACT_KIND_PINNING,
		api.ResidencyFactPlacement:              auditv1.ResidencyFactKind_RESIDENCY_FACT_KIND_PLACEMENT,
		api.ResidencyFactPlacementRefused:       auditv1.ResidencyFactKind_RESIDENCY_FACT_KIND_PLACEMENT_REFUSED,
		api.ResidencyFactPlacementContradiction: auditv1.ResidencyFactKind_RESIDENCY_FACT_KIND_PLACEMENT_CONTRADICTION,
	}
	for in, want := range kinds {
		if got := residencyFactKindOf(in); got != want {
			t.Fatalf("fact kind %s renders %v, want %v", in, got, want)
		}
	}
	if residencyFactKindOf("BOGUS") != auditv1.ResidencyFactKind_RESIDENCY_FACT_KIND_UNSPECIFIED {
		t.Fatal("an unknown fact kind renders UNSPECIFIED, never an invented value")
	}
}
