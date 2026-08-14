// The assembly invariants the Phase-2 review wave pinned (H4, M7, M8):
// a truncated trail read never renders complete sections, the header chunk
// carries identity only, and a policy decision without its input digest
// cannot enter a control section.
package domain

import (
	"testing"
	"time"

	"github.com/gitfrok/backend/modules/audit/api"
)

var evidenceNow = time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)

// trailRecord is one witnessed record the classifier can admit.
func trailRecord(seq int64, action api.Action, detail map[string]string) api.Record {
	return api.Record{
		Seq:        seq,
		TenantID:   "tenant-a",
		Action:     action,
		ActorID:    "actor-1",
		Resource:   "merge_request/mr-1",
		Outcome:    api.OutcomeAllowed,
		Detail:     detail,
		OccurredAt: evidenceNow.Add(time.Duration(seq) * time.Minute),
		PrevHash:   "prev-hash",
		Hash:       "hash",
	}
}

// SPEC-0031 AC3: every policy decision a control section cites carries its
// deciding policy version AND input digest. A decision with no input digest
// is excluded at classification — where the type still allows it — rather
// than rendered and filtered later.
func TestClassifyExcludesPolicyDecisionWithoutInputDigest(t *testing.T) {
	provenance := func(inputDigest string) map[string]string {
		return map[string]string{
			"policy_mode":     "ENFORCED",
			"decision_id":     "decision-1",
			"policy_revision": "bundle-rev-1",
			"input_digest":    inputDigest,
		}
	}

	// With the digest: admitted to the policy-decisions section.
	sr, section, ok := Classify(trailRecord(1, api.Action("security.finding.read.denied"), provenance("sha256:input")))
	if !ok || section != api.SectionPolicyDecisions || sr.PolicyDecision == nil ||
		sr.PolicyDecision.InputDigest != "sha256:input" {
		t.Fatalf("an enforced decision with its input digest must be admitted, got ok=%v section=%v detail=%+v",
			ok, section, sr.PolicyDecision)
	}

	// Without it: excluded, whatever the action string.
	if _, _, ok := Classify(trailRecord(2, api.Action("security.finding.read.denied"), provenance(""))); ok {
		t.Fatal("a decision without its input digest must not enter a control section (SPEC-0031 AC3)")
	}
	// And absence of either other provenance field still excludes.
	if _, _, ok := Classify(trailRecord(3, api.Action("x.denied"), map[string]string{
		"policy_mode":  "ENFORCED",
		"input_digest": "sha256:input",
	})); ok {
		t.Fatal("a decision without its policy revision must not enter a control section")
	}
}

// SPEC-0031 AC10, SPEC-0032 AC8: when the trail read hit its bounded limit,
// every trail-fed section renders Complete: false with the truncation gap —
// never the earliest prefix presented as the whole range.
func TestAssembleSectionsMarksTruncatedSectionsIncomplete(t *testing.T) {
	records := []api.Record{
		trailRecord(1, api.Action("codereview.review.approved"), map[string]string{"protection_rule_id": "rule-1"}),
		trailRecord(2, api.Action("security.scan.denied"), map[string]string{
			"policy_mode": "ENFORCED", "decision_id": "d-1",
			"policy_revision": "rev-1", "input_digest": "sha256:in",
		}),
	}
	gap := api.SectionGap{
		From: records[1].OccurredAt, To: evidenceNow.Add(24 * time.Hour), Reason: api.GapReadTruncated,
	}

	sections := AssembleSections(records, "", &gap, nil)
	if len(sections) != 3 {
		t.Fatalf("trail-fed sections = %d, want 3 (access-changes and residency assemble separately)", len(sections))
	}
	for _, sec := range sections {
		if sec.Complete {
			t.Errorf("section %s: a truncated trail read must not render Complete", sec.Type)
		}
		if len(sec.Gaps) != 1 || sec.Gaps[0] != gap {
			t.Errorf("section %s: gaps = %+v, want exactly the truncation gap %+v", sec.Type, sec.Gaps, gap)
		}
	}
	// The cited prefix still assembles: records, anchors and digests intact.
	if len(sections[0].Records) != 1 || sections[0].RecordsDigest != RecordsDigest(sections[0].Records) {
		t.Errorf("a truncated section still carries its cited prefix verifiable: %+v", sections[0])
	}

	// Without truncation the same records assemble complete and gap-free.
	for _, sec := range AssembleSections(records, "", nil, nil) {
		if !sec.Complete || len(sec.Gaps) != 0 {
			t.Errorf("section %s: a full read must render complete without gaps, got %+v", sec.Type, sec)
		}
	}
}

// Wave-2 N4 pin: a section type whose records live ONLY in the unread tail
// still appears in a truncated pack — as an empty section marked incomplete
// with the truncation gap, never absent. Absence would let a truncated read
// hide that the range even witnessed that control.
func TestTruncatedReadEmitsTailOnlySectionTypesIncomplete(t *testing.T) {
	// The prefix holds one approval only; scan gates and policy decisions
	// exist solely in the unread tail.
	records := []api.Record{
		trailRecord(1, api.Action("codereview.review.approved"), map[string]string{"protection_rule_id": "rule-1"}),
	}
	gap := api.SectionGap{
		From: records[0].OccurredAt, To: evidenceNow.Add(24 * time.Hour), Reason: api.GapReadTruncated,
	}

	sections := AssembleSections(records, "", &gap, nil)
	if len(sections) != 3 {
		t.Fatalf("trail-fed sections = %d, want 3", len(sections))
	}
	for _, sec := range sections {
		if sec.Complete {
			t.Errorf("section %s: a truncated read must not render Complete", sec.Type)
		}
		if len(sec.Gaps) != 1 || sec.Gaps[0] != gap {
			t.Errorf("section %s: gaps = %+v, want exactly the truncation gap %+v", sec.Type, sec.Gaps, gap)
		}
	}
	// The tail-only types are present with zero records — present AND
	// incomplete is the honest shape.
	for _, want := range []api.SectionType{api.SectionPolicyDecisions, api.SectionScanGates} {
		found := false
		for _, sec := range sections {
			if sec.Type == want {
				found = true
				if len(sec.Records) != 0 || sec.Anchor != (api.ChainAnchor{}) {
					t.Errorf("section %s: a tail-only type must carry no records and no anchors, got %+v", want, sec)
				}
			}
		}
		if !found {
			t.Errorf("section %s: a truncated read must still emit the type, not drop it", want)
		}
	}
}

// Wave-2 N6 — an enforced policy decision lacking its input digest is
// excluded from the section's records (SPEC-0031 AC3), but never dropped
// silently: the policy-decisions section renders Complete: false with one
// visible exclusion gap per excluded record (SPEC-0031 AC10).
func TestExcludedPolicyDecisionsMarkTheSectionIncomplete(t *testing.T) {
	admitted := trailRecord(1, api.Action("security.scan.denied"), map[string]string{
		"policy_mode": "ENFORCED", "decision_id": "d-1",
		"policy_revision": "rev-1", "input_digest": "sha256:in",
	})
	excluded := trailRecord(2, api.Action("security.finding.read.denied"), map[string]string{
		"policy_mode": "ENFORCED", "decision_id": "d-2",
		"policy_revision": "rev-1", // the input digest is missing
	})
	wantGap := api.SectionGap{From: excluded.OccurredAt, To: excluded.OccurredAt, Reason: api.GapRecordsExcluded}

	policy := func(sections []api.Section) api.Section {
		t.Helper()
		for _, sec := range sections {
			if sec.Type == api.SectionPolicyDecisions {
				return sec
			}
		}
		t.Fatal("the policy-decisions section must be present")
		return api.Section{}
	}

	// Without truncation: the exclusion alone marks the section.
	sec := policy(AssembleSections([]api.Record{admitted, excluded}, "", nil, nil))
	if sec.Complete {
		t.Error("a section with an excluded decision must not render Complete")
	}
	if len(sec.Records) != 1 || sec.Records[0].PolicyDecision == nil ||
		sec.Records[0].PolicyDecision.DecisionID != "d-1" {
		t.Fatalf("only the fully-provenanced decision may be cited, got %+v", sec.Records)
	}
	if len(sec.Gaps) != 1 || sec.Gaps[0] != wantGap {
		t.Fatalf("gaps = %+v, want exactly the exclusion marker %+v", sec.Gaps, wantGap)
	}
	// The cited record stays verifiable: digest over the records as delivered.
	if sec.RecordsDigest != RecordsDigest(sec.Records) {
		t.Error("the cited slice must stay digest-verifiable")
	}

	// Other sections are untouched by the exclusion.
	for _, s := range AssembleSections([]api.Record{admitted, excluded}, "", nil, nil) {
		if s.Type != api.SectionPolicyDecisions && (!s.Complete || len(s.Gaps) != 0) {
			t.Errorf("section %s: the exclusion belongs to policy decisions only, got %+v", s.Type, s)
		}
	}

	// With truncation too: the exclusion gap renders first, then the
	// truncation gap — chain order.
	trunc := api.SectionGap{From: excluded.OccurredAt, To: evidenceNow.Add(24 * time.Hour), Reason: api.GapReadTruncated}
	sec = policy(AssembleSections([]api.Record{admitted, excluded}, "", &trunc, nil))
	if len(sec.Gaps) != 2 || sec.Gaps[0] != wantGap || sec.Gaps[1] != trunc || sec.Complete {
		t.Fatalf("truncated section gaps = %+v, want [%+v, %+v] and Complete=false", sec.Gaps, wantGap, trunc)
	}
}

// The bounded-chunk streaming shape: the header chunk carries the pack's
// identity ONLY — sections and appendix travel in their own chunks. A header
// embedding the whole pack would make chunk 0 unbounded and defeat the shape
// GetEvidencePack streams.
func TestChunksHeaderCarriesIdentityOnly(t *testing.T) {
	pack := api.Pack{
		PackID: "pack-1", TenantID: "tenant-a",
		RangeFrom: evidenceNow.Add(-time.Hour), RangeTo: evidenceNow.Add(time.Hour),
		RequestedBy: "u-owner", DecisionID: "decision-gen", GeneratedAt: evidenceNow,
		Sections: []api.Section{{Type: api.SectionApprovals, Complete: true}},
		Appendix: api.Appendix{Label: api.AppendixLabel, Groups: []api.AttestedGroup{{
			Import: api.HistoryImportedRef{ImportID: "import-1"},
		}}},
	}

	chunks := Chunks(pack)
	if len(chunks) != 4 {
		t.Fatalf("chunks = %d, want 4 (header + 1 section + appendix + final)", len(chunks))
	}
	header := chunks[0].Header
	if header == nil {
		t.Fatal("chunk 0 must carry the header")
	}
	if header.PackID != "pack-1" || header.TenantID != "tenant-a" || header.RequestedBy != "u-owner" ||
		header.DecisionID != "decision-gen" || header.RangeFrom != pack.RangeFrom || header.RangeTo != pack.RangeTo {
		t.Fatalf("header chunk must carry the pack's identity, got %+v", header)
	}
	if len(header.Sections) != 0 || header.Appendix.Label != "" || len(header.Appendix.Groups) != 0 {
		t.Fatalf("header chunk must carry no sections or appendix, got sections=%d appendix=%+v",
			len(header.Sections), header.Appendix)
	}
	// The original pack is untouched: chunking is a rendering, not a mutation.
	if len(pack.Sections) != 1 || pack.Appendix.Label != api.AppendixLabel || len(pack.Appendix.Groups) != 1 {
		t.Fatalf("chunking mutated the source pack: %+v", pack)
	}
	if chunks[1].Section == nil || chunks[1].Section.Type != api.SectionApprovals {
		t.Fatalf("chunk 1 must carry the section, got %+v", chunks[1])
	}
	if chunks[2].Appendix == nil || chunks[2].Appendix.Label != api.AppendixLabel || len(chunks[2].Appendix.Groups) != 1 {
		t.Fatalf("chunk 2 must carry the appendix with its label, got %+v", chunks[2])
	}
	if !chunks[3].Final || chunks[3].Header != nil || chunks[3].Section != nil || chunks[3].Appendix != nil {
		t.Fatalf("the closing chunk must carry no content: %+v", chunks[3])
	}
}

// Wave-2 residual A — the exclusion marker keyed only on the ENFORCED mode,
// so a decision record that lost its mode in transit fell through Classify
// and left the pack with no trace. Three shapes are pinned here: the
// mode-less decision record IS an exclusion (it carries the revision and
// digest auditsink writes for decisions only); an unrecognized mode is one
// too; and the decision_id-only shape every audited action carries — an
// auditor-grant issuance, for instance — is NOT, because gapping on a
// correlation key would mark healthy packs incomplete.
func TestExclusionMarkerCoversModelessAndUnknownModes(t *testing.T) {
	policy := func(sections []api.Section) api.Section {
		t.Helper()
		for _, sec := range sections {
			if sec.Type == api.SectionPolicyDecisions {
				return sec
			}
		}
		t.Fatal("the policy-decisions section must be present")
		return api.Section{}
	}

	for _, tc := range []struct {
		name    string
		detail  map[string]string
		wantGap bool
	}{
		{
			name: "a decision record with no mode is an exclusion",
			detail: map[string]string{
				"decision_id": "d-1", "policy_revision": "rev-1", "input_digest": "sha256:in",
			},
			wantGap: true,
		},
		{
			name:    "a mode the vocabulary does not define is an exclusion",
			detail:  map[string]string{"policy_mode": "SHADOW", "decision_id": "d-1"},
			wantGap: true,
		},
		{
			name: "a DRY_RUN decision is absent, not missing",
			detail: map[string]string{
				"policy_mode": "DRY_RUN", "decision_id": "d-1",
				"policy_revision": "rev-1", "input_digest": "sha256:in",
			},
			wantGap: false,
		},
		{
			name:    "an audited action carrying only decision_id is not a decision record",
			detail:  map[string]string{"decision_id": "d-1", "grant_id": "g-1"},
			wantGap: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := trailRecord(1, api.Action("auditor.grant.issued"), tc.detail)
			sec := policy(AssembleSections([]api.Record{rec}, "", nil, nil))
			gapped := len(sec.Gaps) > 0
			if gapped != tc.wantGap {
				t.Fatalf("gaps = %+v, want a gap: %v", sec.Gaps, tc.wantGap)
			}
			if sec.Complete == tc.wantGap {
				t.Errorf("Complete = %v with gaps %+v", sec.Complete, sec.Gaps)
			}
			if tc.wantGap {
				want := api.SectionGap{From: rec.OccurredAt, To: rec.OccurredAt, Reason: api.GapRecordsExcluded}
				if sec.Gaps[0] != want {
					t.Errorf("gap = %+v, want %+v", sec.Gaps[0], want)
				}
			}
			if len(sec.Records) != 0 {
				t.Errorf("no record here is citable, got %+v", sec.Records)
			}
		})
	}
}
