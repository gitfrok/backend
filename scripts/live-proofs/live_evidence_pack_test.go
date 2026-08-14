// Package liveproofs holds the platform's live proofs: end-to-end proofs that
// run against the REAL dependencies — never fixture replays — and skip only
// when a dependency is genuinely absent. They live here, outside the modules,
// because they compose more than one context and the governance bundle, which
// no module is entitled to know about (ADR-0025: only cmd/ composes).
package liveproofs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gitfrok/backend/modules/audit"
	auditapi "github.com/gitfrok/backend/modules/audit/api"
	"github.com/gitfrok/backend/modules/policy"
	platformaudit "github.com/gitfrok/backend/platform/audit"
	"github.com/gitfrok/backend/platform/auditsink"
	"github.com/gitfrok/backend/platform/bus"
)

// TestLiveEvidencePackProof is SPEC-0031/SPEC-0032 against the real policy:
// load the actual governance bundle into the real OPA decision point, feed the
// tenant's chain with the same audit events a plane emits — through the same
// sink a plane composes — then generate, observe and retrieve a pack, and
// assert the pack's shape, its section contents, its degraded access-changes
// section, its idempotent replay, and that the real policy refuses everyone
// but the tenant owner.
//
// It is a live proof, not a fixture replay: the authorization vocabulary it
// exercises (evidence.pack.generate, evidence.pack.read) is decided by
// governance/policies as checked out beside backend/, and it skips only when
// that checkout is absent.
func TestLiveEvidencePackProof(t *testing.T) {
	bundle := filepath.Join("..", "..", "..", "governance", "policies")
	if _, err := os.Stat(filepath.Join(bundle, ".manifest")); err != nil {
		t.Skipf("governance/policies not checked out beside backend/ (%v); "+
			"the live evidence proof needs the real bundle", err)
	}

	b := bus.NewInProcess()
	pdp, err := policy.NewOPADecisionPoint(bundle, b)
	if err != nil {
		t.Fatalf("the real governance bundle does not load: %v", err)
	}

	// The dev-plane composition: an in-memory trail fed by the same audit
	// sink, and the evidence service composed on the real PDP. The appendix
	// and access-changes sources stay nil — a plane with no import surface
	// answers with an empty appendix, and a missing auditor-grant surface
	// degrades the access-changes section per contract (SPEC-0031 AC10).
	trail := audit.NewMemoryTrail()
	auditsink.NewLogSink(trail).Subscribe(b)
	svc := audit.NewEvidenceService(pdp, b, trail, nil, nil, nil)

	const tenant = "t-live-evidence"
	now := time.Now().UTC()
	from, to := now.Add(-time.Hour), now.Add(time.Hour)
	ctx := context.Background()

	// Seed the chain with the events a plane actually emits, published onto
	// the bus so they traverse the sink exactly as in a running plane. A
	// merge first — classified by no section — so every section's first
	// cited record carries a non-empty prev-hash continuity anchor.
	publish := func(e bus.Event) {
		if err := b.Publish(ctx, e); err != nil {
			t.Fatalf("publish %T: %v", e, err)
		}
	}
	publish(platformaudit.MergeRequestMerged{
		TenantID: tenant, ActorID: "u-dev", RepositoryID: "repo-live",
		MergeRequestID: "mr-0", TargetRef: "refs/heads/main", HeadRevision: "rev-0",
		RequestID: "req-seed-0", PolicyDecisionID: "dec-seed-0", OccurredAt: now.Add(-50 * time.Minute),
	})
	publish(platformaudit.MergeRequestApproved{
		TenantID: tenant, ActorID: "u-reviewer", RepositoryID: "repo-live",
		MergeRequestID: "mr-1", HeadRevision: "rev-1",
		RequestID: "req-seed-1", PolicyDecisionID: "dec-seed-1", OccurredAt: now.Add(-40 * time.Minute),
	})
	// An approval in ANOTHER repository: the repo-scoped pack must not cite it.
	publish(platformaudit.MergeRequestApproved{
		TenantID: tenant, ActorID: "u-reviewer", RepositoryID: "repo-other",
		MergeRequestID: "mr-other", HeadRevision: "rev-x",
		RequestID: "req-seed-2", PolicyDecisionID: "dec-seed-2", OccurredAt: now.Add(-35 * time.Minute),
	})
	publish(platformaudit.PolicyDecisionDenied{
		TenantID: tenant, ActorID: "u-intruder", DeniedAction: "repo.delete",
		Resource: "repository/repo-live", DecisionID: "dec-seed-denied",
		PolicyRevision: "rev-live-bundle", InputDigest: "sha256:seed-input",
		PolicyMode: "ENFORCED", OccurredAt: now.Add(-30 * time.Minute),
	})
	publish(platformaudit.FindingsScanIngested{
		TenantID: tenant, ActorID: "u-ci", RepositoryID: "repo-live",
		ScanID: "scan-1", RequestID: "req-seed-3", PolicyDecisionID: "dec-seed-3",
		FindingsRecorded: 3, OccurredAt: now.Add(-20 * time.Minute),
	})

	req := auditapi.PackRequest{RangeFrom: from, RangeTo: to, RepositoryID: "repo-live"}

	// The real policy refuses a non-owner, and the refusal is the same coarse
	// shape as every other failed pack operation (SPEC-0032 AC5).
	memberCtx := auditapi.Context{TenantID: tenant, ActorID: "u-member", ActorRoles: []string{"member"}, RequestID: "req-live-member"}
	if _, _, err := svc.RequestPack(ctx, memberCtx, req); !errors.Is(err, auditapi.ErrPackUnavailable) {
		t.Fatalf("the real bundle must refuse a non-owner's pack generation, got %v", err)
	}

	// The owner generates. Generation is a PDP decision, itself audited.
	ownerCtx := auditapi.Context{TenantID: tenant, ActorID: "u-owner", ActorRoles: []string{"owner"}, RequestID: "req-live-1"}
	packID, state, err := svc.RequestPack(ctx, ownerCtx, req)
	if err != nil {
		t.Fatalf("owner pack generation refused by the real bundle: %v", err)
	}
	if packID == "" || state != auditapi.PackPending {
		t.Fatalf("generation returned %q in state %s; want a pack ID in PACK_STATE_PENDING", packID, state)
	}

	// Idempotent replay: same context, range and request ID return the same
	// pack — no second pack, no second audit record (SPEC-0032 AC1).
	replayID, _, err := svc.RequestPack(ctx, ownerCtx, req)
	if err != nil || replayID != packID {
		t.Fatalf("idempotent replay returned %q (%v); want the original pack %q", replayID, err, packID)
	}

	// Observe assembly until READY.
	deadline := time.Now().Add(10 * time.Second)
	var st auditapi.PackStatus
	for {
		st, err = svc.PackStatus(ctx, ownerCtx, packID)
		if err != nil {
			t.Fatalf("pack status: %v", err)
		}
		if st.State != auditapi.PackPending && st.State != auditapi.PackAssembling {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("pack never became READY (last state %s: %s)", st.State, st.FailureReason)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if st.State != auditapi.PackReady {
		t.Fatalf("pack ended in %s: %s", st.State, st.FailureReason)
	}

	// The access-changes section degraded per contract: no auditor-grant
	// surface is wired yet, so an explicit SOURCE_UNAVAILABLE gap over the
	// range — never an empty section presented as complete.
	var accessStatus *auditapi.SectionStatus
	for i := range st.SectionCounts {
		if st.SectionCounts[i].Type == auditapi.SectionAccessChanges {
			accessStatus = &st.SectionCounts[i]
		}
	}
	if accessStatus == nil || len(accessStatus.Gaps) != 1 || accessStatus.Gaps[0].Reason != auditapi.GapSourceUnavailable {
		t.Fatalf("access-changes status must carry exactly one SOURCE_UNAVAILABLE gap, got %+v", accessStatus)
	}

	// Retrieve the pack as its chunk sequence.
	chunks, err := svc.GetPack(ctx, ownerCtx, packID)
	if err != nil {
		t.Fatalf("get pack: %v", err)
	}
	// Shape: header, four control sections in order, appendix, closing chunk.
	if len(chunks) != 7 {
		t.Fatalf("pack streamed %d chunks; want 7 (header + 4 sections + appendix + final)", len(chunks))
	}
	header := chunks[0].Header
	if header == nil || header.PackID != packID || header.RequestedBy != "u-owner" || header.DecisionID == "" {
		t.Fatalf("header chunk malformed: %+v", chunks[0])
	}
	// The header chunk carries identity only: sections and appendix arrive in
	// their own bounded chunks, never embedded in chunk 0.
	if len(header.Sections) != 0 || header.Appendix.Label != "" || len(header.Appendix.Groups) != 0 {
		t.Fatalf("header chunk must carry no sections or appendix, got %+v", header)
	}
	if chunks[5].Appendix == nil || chunks[5].Appendix.Label != auditapi.AppendixLabel || len(chunks[5].Appendix.Groups) != 0 {
		t.Fatalf("appendix chunk must be empty and carry the server-set label, got %+v", chunks[5])
	}
	if !chunks[6].Final || chunks[6].Header != nil || chunks[6].Section != nil || chunks[6].Appendix != nil {
		t.Fatalf("closing chunk must carry no content: %+v", chunks[6])
	}

	sections := map[auditapi.SectionType]auditapi.Section{}
	for i, want := range []auditapi.SectionType{
		auditapi.SectionApprovals, auditapi.SectionPolicyDecisions,
		auditapi.SectionScanGates, auditapi.SectionAccessChanges,
	} {
		c := chunks[1+i]
		if c.Section == nil || c.Section.Type != want {
			t.Fatalf("chunk %d must carry section %s, got %+v", 1+i, want, c)
		}
		sections[want] = *c.Section
	}

	// Approvals: exactly the seeded repo-live approval — the repo-other one is
	// excluded by the repository scope, and nothing else is admitted.
	approvals := sections[auditapi.SectionApprovals]
	if len(approvals.Records) != 1 || approvals.Records[0].Approval == nil ||
		approvals.Records[0].Approval.MergeRequestID != "mr-1" || !approvals.Complete {
		t.Fatalf("approvals section must cite exactly mr-1, got %+v", approvals)
	}
	if approvals.Anchor.FirstRecordHash == "" || approvals.Anchor.PrevRecordHash == "" {
		t.Fatalf("approvals anchors must carry record and continuity hashes, got %+v", approvals.Anchor)
	}
	if approvals.RecordsDigest == "" {
		t.Fatal("approvals section must carry its records digest")
	}

	// Policy decisions: the seeded enforced denial is cited with its
	// provenance. The real PDP's own refusal of the member above may also be
	// cited — the assertion is containment, never an exact count.
	decisions := sections[auditapi.SectionPolicyDecisions]
	var found *auditapi.PolicyDecisionDetail
	for _, r := range decisions.Records {
		if r.PolicyDecision != nil && r.PolicyDecision.DecisionID == "dec-seed-denied" {
			found = r.PolicyDecision
		}
	}
	if found == nil || found.BundleRevision != "rev-live-bundle" || found.InputDigest != "sha256:seed-input" {
		t.Fatalf("policy-decisions section must cite dec-seed-denied with its provenance, got %+v", decisions)
	}

	// Scan gates: the seeded ingest.
	gates := sections[auditapi.SectionScanGates]
	if len(gates.Records) != 1 || gates.Records[0].ScanGate == nil || gates.Records[0].ScanGate.ScanID != "scan-1" {
		t.Fatalf("scan-gates section must cite exactly scan-1, got %+v", gates)
	}

	// Access changes: the degraded section itself — complete=false, one
	// SOURCE_UNAVAILABLE gap over the whole range, no records.
	access := sections[auditapi.SectionAccessChanges]
	if access.Complete || len(access.Records) != 0 || len(access.Gaps) != 1 ||
		access.Gaps[0].Reason != auditapi.GapSourceUnavailable ||
		!access.Gaps[0].From.Equal(from) || !access.Gaps[0].To.Equal(to) {
		t.Fatalf("access-changes section must degrade per contract, got %+v", access)
	}

	// Retrieval is a PDP decision too: another tenant's owner sees the same
	// coarse denial as a nonexistent pack (SPEC-0001, SPEC-0032 AC5).
	otherCtx := auditapi.Context{TenantID: "t-other", ActorID: "u-owner", ActorRoles: []string{"owner"}, RequestID: "req-live-x"}
	if _, err := svc.GetPack(ctx, otherCtx, packID); !errors.Is(err, auditapi.ErrPackUnavailable) {
		t.Fatalf("cross-tenant read must be the coarse denial, got %v", err)
	}

	t.Logf("live proof: pack %s assembled under the real governance bundle — "+
		"approvals=%d policy_decisions=%d scan_gates=%d, access-changes degraded SOURCE_UNAVAILABLE, "+
		"non-owner generation and cross-tenant reads refused",
		packID, len(approvals.Records), len(decisions.Records), len(gates.Records))
}
