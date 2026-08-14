// Evidence assembly — the pure computation that turns a tenant's witnessed
// chain into evidence pack sections (SPEC-0031, SPEC-0032).
//
// No infrastructure here, for the same reason the hash chain lives in this
// package: assembly must be testable without a database and re-derivable by
// anyone holding a pack, which is what "internally verifiable" means
// (SPEC-0032 AC7).
package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/gitfrok/backend/modules/audit/api"
)

// The audited actions the sections classify. The vocabulary is the one
// platform/audit emits onto the trail; naming it here — not importing it —
// keeps the classifier a pure function of strings, and a new action the
// classifier has not heard of is simply unclassified, never an error.
const (
	actionReviewApproved = "codereview.review.approved"
	actionScanIngested   = "findings.scan_ingested"
)

// policyModeEnforced is the only decision mode the policy-decisions section
// admits. The string rendering of policy EvaluationMode the trail carries.
const policyModeEnforced = "ENFORCED"

// Detail keys the classifier reads from trail records. These are the keys
// auditsink writes; they are server-produced facts, never caller claims.
const (
	detailPolicyMode       = "policy_mode"
	detailDecisionID       = "decision_id"
	detailPolicyRevision   = "policy_revision"
	detailInputDigest      = "input_digest"
	detailScanID           = "scan_id"
	detailProtectionRuleID = "protection_rule_id"
	detailReliedUponTriage = "relied_upon_triage_ids"
	detailRepositoryID     = "repository_id"
)

// Classify maps one witnessed trail record to the control-section record it is
// evidence for, or reports that it is none. ok is false for records no section
// cites — the trail carries more than the four control sections, and a record
// that belongs to none is simply not evidence, never forced into one.
//
// The classification is the server-determined half of assembly (SPEC-0032):
// no caller names the records a section contains.
func Classify(r api.Record) (api.SectionRecord, api.SectionType, bool) {
	base := api.SectionRecord{
		ChainSeq:   r.Seq,
		RecordHash: r.Hash,
		ActorID:    r.ActorID,
		Resource:   r.Resource,
		Action:     r.Action,
		Allowed:    r.Outcome == api.OutcomeAllowed,
		OccurredAt: r.OccurredAt,
	}
	switch string(r.Action) {
	case actionReviewApproved:
		base.Approval = &api.ApprovalDetail{
			MergeRequestID:   resourceID(r.Resource),
			ProtectionRuleID: r.Detail[detailProtectionRuleID],
		}
		return base, api.SectionApprovals, true

	case actionScanIngested:
		base.ScanGate = &api.ScanGateDetail{
			ScanID:              r.Detail[detailScanID],
			ReliedUponTriageIDs: splitCSV(r.Detail[detailReliedUponTriage]),
		}
		return base, api.SectionScanGates, true
	}

	// Policy decisions are classified by their provenance, not by the action
	// string: a denial record carries the REFUSED action as its action (that
	// is what the investigation reads), and what makes it a control decision
	// is the decision provenance the trail writes onto it — the mode, the
	// decision ID and the deciding policy revision (SPEC-0029 AC8, SPEC-0030).
	// A control-section policy decision carries its deciding policy version
	// and input digest (SPEC-0031 AC3). A record without that provenance
	// cannot satisfy the section, and a DRY_RUN decision is not representable
	// in a control section at all (SPEC-0032 AC3) — both are excluded here,
	// where the type still allows it, rather than rendered and filtered later.
	mode := r.Detail[detailPolicyMode]
	if mode != policyModeEnforced {
		return api.SectionRecord{}, 0, false
	}
	if r.Detail[detailDecisionID] == "" || r.Detail[detailPolicyRevision] == "" ||
		r.Detail[detailInputDigest] == "" {
		return api.SectionRecord{}, 0, false
	}
	base.PolicyDecision = &api.PolicyDecisionDetail{
		DecisionID:     r.Detail[detailDecisionID],
		BundleRevision: r.Detail[detailPolicyRevision],
		InputDigest:    r.Detail[detailInputDigest],
	}
	return base, api.SectionPolicyDecisions, true
}

// excludedPolicyDecision reports whether a witnessed record is an enforced
// policy decision the control section cannot admit: it carries the ENFORCED
// mode but lacks part of its SPEC-0030 provenance (decision ID, policy
// revision, or input digest). Classify refuses it — the section may cite
// only fully-provenanced decisions (SPEC-0031 AC3) — and assembly marks the
// exclusion with a gap instead of dropping it silently (wave-2 N6). The two
// actions classified by their action string are never policy decisions, and
// a DRY_RUN (or un-moded) record is not an exclusion: it is simply not
// control evidence at all (SPEC-0032 AC3).
func excludedPolicyDecision(r api.Record) bool {
	switch string(r.Action) {
	case actionReviewApproved, actionScanIngested:
		return false
	}
	if r.Detail[detailPolicyMode] != policyModeEnforced {
		return false
	}
	return r.Detail[detailDecisionID] == "" || r.Detail[detailPolicyRevision] == "" ||
		r.Detail[detailInputDigest] == ""
}

// resourceID extracts the identifier after the kind prefix of a trail
// resource ("merge_request/mr-1" -> "mr-1"). A resource without a prefix is
// returned whole.
func resourceID(resource string) string {
	if _, after, ok := strings.Cut(resource, "/"); ok {
		return after
	}
	return resource
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// AnchorWithPrev bounds a section's cited slice of the chain. records must
// be in chain-sequence order; prevHash is the hash of the chain record
// immediately before the slice — the continuity anchor, which is exactly the
// first cited record's own prev-hash link (ADR-0007). An empty slice yields a
// zero anchor: an empty section is a legitimate answer and says so via its
// anchors and counts.
func AnchorWithPrev(records []api.SectionRecord, prevHash string) api.ChainAnchor {
	if len(records) == 0 {
		return api.ChainAnchor{}
	}
	first, last := records[0], records[len(records)-1]
	return api.ChainAnchor{
		FirstSeq:        first.ChainSeq,
		LastSeq:         last.ChainSeq,
		FirstRecordHash: first.RecordHash,
		LastRecordHash:  last.RecordHash,
		PrevRecordHash:  prevHash,
	}
}

// AssembleSections classifies witnessed records into the four control
// sections, in SectionType order, computing anchors and digests. records must
// be tenant-scoped, range-filtered and in chain-sequence order — the trail
// query's job. repositoryID, when non-empty, restricts membership to records
// attributed to that repository or carrying no repository attribution.
//
// truncation, when non-nil, says the trail read hit its bounded limit: the
// records are the earliest prefix of the range and the tail is missing. Every
// trail-fed section then renders Complete: false with that gap — a truncated
// section says so, rather than presenting the prefix as the whole range
// (SPEC-0031 AC10, SPEC-0032 AC8). The access-changes section is unaffected:
// it assembles separately from the AccessChangesSource port; see Service for
// its degraded shape when no such surface is wired.
//
// Exclusions are marked, never silent: an enforced policy decision lacking
// its SPEC-0030 provenance cannot enter the policy-decisions section
// (SPEC-0031 AC3), but its presence in the range is witnessed — the section
// renders Complete: false with one point gap (From = To = the record's
// witnessed time) per excluded record, ordered before any truncation gap
// (wave-2 N6, SPEC-0031 AC10).
func AssembleSections(records []api.Record, repositoryID string, truncation *api.SectionGap) []api.Section {
	grouped := map[api.SectionType][]api.SectionRecord{}
	firstPrev := map[api.SectionType]string{}
	var excludedGaps []api.SectionGap
	for _, r := range records {
		if repositoryID != "" {
			if repo, ok := r.Detail[detailRepositoryID]; ok && repo != repositoryID {
				continue
			}
		}
		if excludedPolicyDecision(r) {
			excludedGaps = append(excludedGaps, api.SectionGap{
				From: r.OccurredAt, To: r.OccurredAt, Reason: api.GapRecordsExcluded,
			})
			continue
		}
		sr, section, ok := Classify(r)
		if !ok {
			continue
		}
		// The continuity anchor of a section is the first cited record's own
		// prev-hash link; keep the one belonging to the slice's head.
		if _, seen := grouped[section]; !seen {
			firstPrev[section] = r.PrevHash
		}
		grouped[section] = append(grouped[section], sr)
	}

	sections := make([]api.Section, 0, len(api.AllSectionTypes))
	for _, st := range api.AllSectionTypes {
		if st == api.SectionAccessChanges {
			continue // assembled from the identity surface port, not the trail
		}
		recs := grouped[st]
		sec := api.Section{
			Type:          st,
			Anchor:        AnchorWithPrev(recs, firstPrev[st]),
			Records:       recs,
			Complete:      true,
			RecordsDigest: RecordsDigest(recs),
		}
		// Gaps render in chain order: the policy section's witnessed
		// exclusions first, then the unread-tail truncation when the read
		// was bounded. Any gap makes the section incomplete.
		if st == api.SectionPolicyDecisions {
			sec.Gaps = append(sec.Gaps, excludedGaps...)
		}
		if truncation != nil {
			// The unread tail may hold records of ANY section: the honest
			// shape marks every trail-fed section incomplete, whether or not
			// it cited records from the prefix it did read.
			sec.Gaps = append(sec.Gaps, *truncation)
		}
		if len(sec.Gaps) > 0 {
			sec.Complete = false
		}
		sections = append(sections, sec)
	}
	return sections
}

// RecordsDigest is the digest over a section's embedded records as canonically
// serialized. A consumer recomputes it over the records as delivered and
// detects any mutation of membership, order or content (SPEC-0032 AC7).
func RecordsDigest(records []api.SectionRecord) string {
	h := sha256.New()
	for _, r := range records {
		writeCanonicalRecord(h, r)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// writeCanonical renders one record deterministically: length-prefixed fields
// in a fixed order, for the same reason the chain hash is length-prefixed —
// a delimiter join is ambiguous when a value contains the delimiter.
func writeCanonicalRecord(h interface{ Write([]byte) (int, error) }, r api.SectionRecord) {
	write := func(name, v string) {
		fmt.Fprintf(h, "%s:%d:%s\n", name, len(v), v)
	}
	write("seq", fmt.Sprintf("%d", r.ChainSeq))
	write("hash", r.RecordHash)
	write("actor", r.ActorID)
	write("resource", r.Resource)
	write("action", string(r.Action))
	if r.Allowed {
		write("outcome", "ALLOWED")
	} else {
		write("outcome", "DENIED")
	}
	write("occurred_at", r.OccurredAt.UTC().Format(time.RFC3339Nano))
	switch {
	case r.Approval != nil:
		write("detail", "approval")
		write("approval.merge_request_id", r.Approval.MergeRequestID)
		write("approval.protection_rule_id", r.Approval.ProtectionRuleID)
	case r.PolicyDecision != nil:
		write("detail", "policy_decision")
		write("policy.decision_id", r.PolicyDecision.DecisionID)
		write("policy.bundle_revision", r.PolicyDecision.BundleRevision)
		write("policy.input_digest", r.PolicyDecision.InputDigest)
	case r.ScanGate != nil:
		write("detail", "scan_gate")
		write("scan.merge_request_id", r.ScanGate.MergeRequestID)
		write("scan.scan_id", r.ScanGate.ScanID)
		triage := append([]string(nil), r.ScanGate.ReliedUponTriageIDs...)
		slices.Sort(triage)
		write("scan.relied_upon_triage_ids", strings.Join(triage, ","))
	case r.AccessChange != nil:
		write("detail", "access_change")
		write("access.kind", r.AccessChange.AccessKind)
		write("access.target_principal_id", r.AccessChange.TargetPrincipalID)
		write("access.grant_id", r.AccessChange.GrantID)
	default:
		write("detail", "unspecified")
	}
}

// AppendixDigest digests the appendix's embedded content the same way, so a
// consumer can verify the labelled half of the pack too — the label says the
// records carry no control claim, and the digest says they are the records
// the platform embedded.
func AppendixDigest(groups []api.AttestedGroup) string {
	h := sha256.New()
	for _, g := range groups {
		fmt.Fprintf(h, "import:%d:%s\n", len(g.Import.ImportID), g.Import.ImportID)
		fmt.Fprintf(h, "manifest_digest:%d:%s\n", len(g.Import.ManifestDigest), g.Import.ManifestDigest)
		for _, r := range g.Records {
			fmt.Fprintf(h, "record_kind:%d:%s\n", len(r.RecordKind), r.RecordKind)
			fmt.Fprintf(h, "payload:%d:%s\n", len(r.Payload), r.Payload)
			fmt.Fprintf(h, "provenance.import_id:%d:%s\n", len(r.Provenance.ImportID), r.Provenance.ImportID)
			fmt.Fprintf(h, "provenance.declared_actor:%d:%s\n", len(r.Provenance.ForeignHandle), r.Provenance.ForeignHandle)
			fmt.Fprintf(h, "provenance.declared_at:%d:%s\n",
				len(r.Provenance.DeclaredAt.UTC().Format(time.RFC3339Nano)),
				r.Provenance.DeclaredAt.UTC().Format(time.RFC3339Nano))
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Chunks renders a READY pack as its bounded chunk sequence, exactly in the
// order GetEvidencePack streams them (contracts/proto/audit/v1): the header
// first, then control sections in SectionType order, then the appendix, then
// the closing chunk. Nothing of the pack is authoritative until the final
// chunk.
//
// The header chunk carries the pack's identity ONLY — sections and appendix
// cleared. They arrive in their own chunks; embedding the whole pack in
// chunk 0 would defeat the bounded-chunk streaming shape entirely.
func Chunks(p api.Pack) []api.PackChunk {
	chunks := make([]api.PackChunk, 0, len(p.Sections)+3)
	idx := int64(0)
	push := func(c api.PackChunk) {
		c.Index = idx
		idx++
		chunks = append(chunks, c)
	}
	header := p
	header.Sections = nil
	header.Appendix = api.Appendix{}
	push(api.PackChunk{Header: &header})
	for i := range p.Sections {
		s := p.Sections[i]
		push(api.PackChunk{Section: &s})
	}
	app := p.Appendix
	push(api.PackChunk{Appendix: &app})
	push(api.PackChunk{Final: true})
	return chunks
}

// VerifySection re-derives a section's internal consistency the way a pack
// consumer does (SPEC-0032 AC7): the records digest matches the embedded
// records, the anchors bound exactly the cited slice, and every record's hash
// is the one its chain position claims. It returns the first fault found.
//
// The chain-side check — that record_hash is really the chain's hash at
// chain_seq — requires the chain itself and is the caller's; this verifies
// everything a pack can prove about itself.
func VerifySection(s api.Section) (ok bool, reason string) {
	if want := RecordsDigest(s.Records); want != s.RecordsDigest {
		return false, fmt.Sprintf("section %s: records digest mismatch — a record was mutated", s.Type)
	}
	if len(s.Records) == 0 {
		if s.Anchor != (api.ChainAnchor{}) {
			return false, fmt.Sprintf("section %s: empty section carries anchors", s.Type)
		}
		return true, ""
	}
	anchor := AnchorWithPrev(s.Records, s.Anchor.PrevRecordHash)
	if anchor != s.Anchor {
		return false, fmt.Sprintf("section %s: anchors do not bound the cited records", s.Type)
	}
	for i := 1; i < len(s.Records); i++ {
		if s.Records[i].ChainSeq <= s.Records[i-1].ChainSeq {
			return false, fmt.Sprintf("section %s: records out of chain order at seq %d", s.Type, s.Records[i].ChainSeq)
		}
	}
	return true, ""
}
