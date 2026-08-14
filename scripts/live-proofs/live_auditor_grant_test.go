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
	"github.com/gitfrok/backend/modules/identity"
	identityapi "github.com/gitfrok/backend/modules/identity/api"
	"github.com/gitfrok/backend/modules/policy"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
	"github.com/gitfrok/backend/platform/auditsink"
	"github.com/gitfrok/backend/platform/bus"
	"github.com/gitfrok/backend/platform/tenancy"
)

// TestLiveAuditorGrantProof is SPEC-0033 against the real policy: load the
// actual governance bundle into the real OPA decision point, run the grant
// lifecycle against it (issuing is owner-only per the merged Rego), prove the
// evidence pack's access-changes section is LIVE — citing the witnessed
// issuance rather than degrading SOURCE_UNAVAILABLE — and prove the pack
// read decision behaves exactly as the Rego's decision-time conjuncts say,
// END-TO-END through the evidence service's decide() path: allowed under a
// valid grant's fresh facts, denied without them, denied the instant the
// grant is revoked or expired, and denied to an auditor who asks for any
// repository access at all.
//
// It is a live proof, not a fixture replay: every decision below is made by
// governance/policies as checked out beside backend/, and the proof skips
// only when that checkout is absent.
func TestLiveAuditorGrantProof(t *testing.T) {
	bundle := filepath.Join("..", "..", "..", "governance", "policies")
	if _, err := os.Stat(filepath.Join(bundle, ".manifest")); err != nil {
		t.Skipf("governance/policies not checked out beside backend/ (%v); "+
			"the live auditor grant proof needs the real bundle", err)
	}

	b := bus.NewInProcess()
	pdp, err := policy.NewOPADecisionPoint(bundle, b)
	if err != nil {
		t.Fatalf("the real governance bundle does not load: %v", err)
	}

	// The dev-plane composition: in-memory trail fed by the audit sink, the
	// grant lifecycle on the real PDP, and the evidence service wired to the
	// grant surface — the composition cmd/dataplane-app uses since T-0027.
	trail := audit.NewMemoryTrail()
	auditsink.NewLogSink(trail).Subscribe(b)
	grants := identity.NewAuditorGrantsInMemory(pdp, b, liveWitness{trail})
	// The grants surface is composed twice, exactly as the dataplane does: as
	// the access-changes section's source AND as the decision-time facts
	// source auditor pack reads compose fresh on every decision (SPEC-0033 AC7).
	svc := audit.NewEvidenceService(pdp, b, trail, nil, audit.NewAccessChangesSource(grants), grants)

	const tenant = "t-live-auditor"
	const auditor = "p-auditor-ext"
	now := time.Now().UTC()
	from, to := now.Add(-time.Hour), now.Add(time.Hour)
	ctx := context.Background()

	ownerCtx := func() context.Context {
		return identityapi.WithPrincipal(tenancy.WithTenant(ctx, tenant),
			identityapi.Principal{TenantID: tenant, ActorID: "u-owner", Roles: []string{"owner"}})
	}
	ownerAuditCtx := auditapi.Context{TenantID: tenant, ActorID: "u-owner", ActorRoles: []string{"owner"}, RequestID: "req-ag-owner-1"}

	// 1. Issuing is owner-only in the merged Rego: a member's issue attempt is
	// refused by the real bundle, and the refusal is the one coarse shape.
	memberCtx := identityapi.WithPrincipal(tenancy.WithTenant(ctx, tenant),
		identityapi.Principal{TenantID: tenant, ActorID: "u-member", Roles: []string{"member"}})
	issue := identityapi.GrantIssue{
		AuditorPrincipalID: auditor, RangeFrom: from, RangeTo: to,
		PackIDs: []string{"pack-will-exist"}, ExpiresAt: now.Add(time.Hour),
	}
	if _, err := grants.IssueGrant(memberCtx, identityapi.GrantContext{RequestID: "req-ag-member-1"}, issue); !errors.Is(err, identityapi.ErrGrantUnavailable) {
		t.Fatalf("the real bundle must refuse a member's grant issuance, got %v", err)
	}

	// 2. The owner generates the pack the grant will name.
	packReq := auditapi.PackRequest{RangeFrom: from, RangeTo: to}
	packID, _, err := svc.RequestPack(ctx, ownerAuditCtx, packReq)
	if err != nil {
		t.Fatalf("owner pack generation refused by the real bundle: %v", err)
	}
	waitReady(t, svc, ctx, ownerAuditCtx, packID)

	// 3. The owner issues the grant naming that pack, with the pack's range
	// inside the grant's range and a time-box. The real bundle's
	// auditor.grant.manage decides it.
	issue.PackIDs = []string{packID}
	grant, err := grants.IssueGrant(ownerCtx(),
		identityapi.GrantContext{RequestID: "req-ag-owner-2"}, issue)
	if err != nil {
		t.Fatalf("owner grant issuance refused by the real bundle: %v", err)
	}
	if grant.State != identityapi.GrantActive || grant.GrantedBy != "u-owner" {
		t.Fatalf("issued grant = %+v, want ACTIVE issued by u-owner", grant)
	}

	// 4. The evidence pack's access-changes section is LIVE now: a second pack
	// over the same range cites the witnessed issuance — no
	// SOURCE_UNAVAILABLE gap, a record naming the AC4 pairing.
	replayCtx := auditapi.Context{TenantID: tenant, ActorID: "u-owner", ActorRoles: []string{"owner"}, RequestID: "req-ag-owner-3"}
	pack2ID, _, err := svc.RequestPack(ctx, replayCtx, packReq)
	if err != nil {
		t.Fatalf("second pack generation refused: %v", err)
	}
	waitReady(t, svc, ctx, replayCtx, pack2ID)
	chunks, err := svc.GetPack(ctx, replayCtx, pack2ID)
	if err != nil {
		t.Fatalf("get pack: %v", err)
	}
	var access *auditapi.Section
	for _, c := range chunks {
		if c.Section != nil && c.Section.Type == auditapi.SectionAccessChanges {
			access = c.Section
		}
	}
	if access == nil {
		t.Fatal("pack carries no access-changes section")
	}
	if !access.Complete || len(access.Gaps) != 0 {
		t.Fatalf("access-changes section must be live and complete, got complete=%v gaps=%+v", access.Complete, access.Gaps)
	}
	var cited *auditapi.SectionRecord
	for i := range access.Records {
		if access.Records[i].AccessChange != nil && access.Records[i].AccessChange.GrantID == grant.GrantID {
			cited = &access.Records[i]
		}
	}
	if cited == nil || cited.AccessChange.AccessKind != "auditor_grant_issued" ||
		cited.AccessChange.TargetPrincipalID != auditor || cited.ActorID != "u-owner" ||
		cited.ChainSeq == 0 || cited.RecordHash == "" {
		t.Fatalf("access-changes section must cite the issuance with its chain position, got %+v", access.Records)
	}

	// 5. The read decision, END-TO-END through the evidence service's
	// decide() path: the auditor calls GetPack like any caller, and the
	// service composes the grant's validity facts FRESH from the identity
	// surface into the decision the real bundle answers (SPEC-0033 AC7).
	auditorAPI := func(requestID string) auditapi.Context {
		return auditapi.Context{TenantID: tenant, ActorID: auditor, ActorRoles: []string{"auditor"}, RequestID: requestID}
	}
	readAs := func(c auditapi.Context, pack string) error {
		_, err := svc.GetPack(ctx, c, pack)
		return err
	}

	// Valid fresh facts read the named pack.
	if err := readAs(auditorAPI("req-ag-auditor-1"), packID); err != nil {
		t.Fatalf("the real bundle refused an auditor reading the granted pack under fresh ACTIVE facts: %v", err)
	}
	// Facts are read on EVERY decision, never cached: a second read succeeds
	// through a second, fresh facts composition.
	if err := readAs(auditorAPI("req-ag-auditor-2"), packID); err != nil {
		t.Fatalf("the second auditor read must compose facts fresh again: %v", err)
	}
	// A pack the grant does not name is denied (AC6: unnamed, never enumerated).
	if err := readAs(auditorAPI("req-ag-auditor-3"), pack2ID); err == nil {
		t.Fatal("the real bundle let an auditor read a pack the grant does not name")
	}
	// An auditor without ANY grant facts is denied fail-closed.
	if err := readAs(auditapi.Context{TenantID: tenant, ActorID: "p-stranger", ActorRoles: []string{"auditor"}, RequestID: "req-ag-stranger-1"}, packID); err == nil {
		t.Fatal("an auditor without grant facts must be denied fail-closed")
	}
	// Member principals are UNAFFECTED by the facts hook: the owner's read
	// composes no grant facts and the role-table rule still answers it.
	if err := readAs(ownerAuditCtx, packID); err != nil {
		t.Fatalf("the owner's pack read must be unaffected by the auditor facts hook: %v", err)
	}
	// AC1: the auditor role carries NO repository read — the role table grants
	// it nothing, and there is no grant shape that confers it.
	if d, err := pdp.Decide(ctx, policyapi.Request{
		TenantID: tenant,
		Subject:  policyapi.Subject{ID: auditor, TenantID: tenant, Roles: []string{"auditor"}},
		Action:   "repo.read",
		Resource: policyapi.Resource{Type: "repository", ID: "repo-live"},
	}); err != nil || d.Allowed {
		t.Fatalf("an auditor must never read repositories, got %+v %v", d, err)
	}

	// 6. AC7: revocation takes effect on the very next decision. The state the
	// facts carry is read fresh — there is no cached decision to outlive it.
	if _, err := grants.RevokeGrant(ownerCtx(), identityapi.GrantContext{RequestID: "req-ag-owner-4"}, grant.GrantID); err != nil {
		t.Fatalf("owner revocation refused by the real bundle: %v", err)
	}
	facts, ok, err := grants.GrantFacts(tenancy.WithTenant(ctx, tenant), auditor, packID)
	if err != nil || !ok || facts.State != identityapi.GrantRevoked {
		t.Fatalf("facts after revocation = %+v ok=%v err=%v, want REVOKED", facts, ok, err)
	}
	if err := readAs(auditorAPI("req-ag-auditor-4"), packID); err == nil {
		t.Fatal("the real bundle let an auditor read under a REVOKED grant — AC7 immediacy is broken")
	}

	// 7. AC3: expiry takes effect without an operator action. A second grant
	// with a very near expiry is ACTIVE one instant and EXPIRED the next —
	// the facts surface recognizes it on its own clock, and the real bundle
	// denies the read with no one acting. Both reads go end-to-end through
	// the service's decide() path.
	issue2 := identityapi.GrantIssue{
		AuditorPrincipalID: auditor, RangeFrom: from, RangeTo: to,
		PackIDs: []string{packID}, ExpiresAt: time.Now().UTC().Add(50 * time.Millisecond),
	}
	grant2, err := grants.IssueGrant(ownerCtx(), identityapi.GrantContext{RequestID: "req-ag-owner-5"}, issue2)
	if err != nil {
		t.Fatalf("short-lived grant issuance refused: %v", err)
	}
	if err := readAs(auditorAPI("req-ag-auditor-5"), packID); err != nil {
		t.Fatalf("the real bundle refused the still-ACTIVE short-lived grant: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	facts2, ok2, err := grants.GrantFacts(tenancy.WithTenant(ctx, tenant), auditor, packID)
	if err != nil || !ok2 || facts2.State != identityapi.GrantExpired {
		t.Fatalf("facts past expiry = %+v ok=%v err=%v, want EXPIRED recognized without operator action", facts2, ok2, err)
	}
	if err := readAs(auditorAPI("req-ag-auditor-6"), packID); err == nil {
		t.Fatal("the real bundle let an auditor read under an EXPIRED grant — AC3 is broken")
	}
	_ = grant2

	t.Logf("live proof: auditor grant lifecycle under the real governance bundle — "+
		"member issuance refused, owner issuance witnessed into a live access-changes section "+
		"(grant %s cited at seq %d), end-to-end pack reads through decide() allowed under fresh "+
		"ACTIVE facts, denied unnamed/factless/revoked/expired and for every repository action, "+
		"member reads unaffected",
		grant.GrantID, cited.ChainSeq)
}

// waitReady polls the pack until assembly finishes, exactly as the evidence
// pack live proof does.
func waitReady(t *testing.T, svc auditapi.PackService, ctx context.Context, c auditapi.Context, packID string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		st, err := svc.PackStatus(ctx, c, packID)
		if err != nil {
			t.Fatalf("pack status: %v", err)
		}
		if st.State == auditapi.PackReady {
			return
		}
		if st.State != auditapi.PackPending && st.State != auditapi.PackAssembling {
			t.Fatalf("pack ended in %s: %s", st.State, st.FailureReason)
		}
		if time.Now().After(deadline) {
			t.Fatal("pack never became READY")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// liveWitness adapts the tenant's audit trail onto the grant lifecycle's
// witness port, exactly as cmd/dataplane-app's composition does: a lifecycle
// record is always an authorized, first-party fact.
type liveWitness struct{ trail auditapi.Log }

func (w liveWitness) AppendGrantRecord(ctx context.Context, e identityapi.GrantWitnessEntry) (identityapi.GrantWitnessRecord, error) {
	record, err := w.trail.Append(ctx, auditapi.Entry{
		TenantID:   e.TenantID,
		Action:     auditapi.Action(e.Action),
		ActorID:    e.ActorID,
		Resource:   e.Resource,
		Outcome:    auditapi.OutcomeAllowed,
		Detail:     e.Detail,
		OccurredAt: e.OccurredAt,
		Provenance: auditapi.ProvenanceFirstParty,
	})
	if err != nil {
		return identityapi.GrantWitnessRecord{}, err
	}
	return identityapi.GrantWitnessRecord{Seq: record.Seq, Hash: record.Hash}, nil
}
