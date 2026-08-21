package app

// Behavioral proof of the security merge gate (SPEC-0029 AC3/AC4/AC5/AC9,
// T-0025): the merge service presents its server-derived facts to the REAL
// reviewed policy bundle from governance/policies — never a copy of it — and
// the bundle's decision is the merge's outcome. The governance repo's own CI
// tests the rules' content; this test proves the backend composes the gate
// the rules expect (SPEC-0002 AC4: the fitness function is a tripwire, the
// behavior is proved here).

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/gitfrok/backend/modules/codereview/api"
	"github.com/gitfrok/backend/modules/policy"
	"github.com/gitfrok/backend/platform/bus"
)

// governanceBundleDir is the reviewed policy bundle, mounted beside the
// backend in every development checkout and in CI. The test skips — exactly
// as the policy adapter's composition test does — when it is not there,
// because the proof is about the two repos composing, and one repo alone
// cannot fake the other's half.
func governanceBundleDir() (string, bool) {
	dir := filepath.Join("..", "..", "..", "..", "..", "governance", "policies")
	if _, err := os.Stat(filepath.Join(dir, ".manifest")); err != nil {
		return "", false
	}
	return dir, true
}

// bundleGate is one merge service deciding under the real bundle, with a
// facts provider the test commands.
func bundleGate(t *testing.T, provider api.FindingsFactsProvider) (*Service, *recordingRefs) {
	t.Helper()
	dir, ok := governanceBundleDir()
	if !ok {
		t.Skip("governance/policies not checked out beside backend/; the bundle proof needs both repos")
	}
	events := bus.NewInProcess()
	pdp, err := policy.NewOPADecisionPoint(dir, events)
	if err != nil {
		t.Fatalf("the real governance bundle does not load: %v", err)
	}
	refs := &recordingRefs{}
	service := New(NewMemoryStore(), refs, pdp, events)
	service.SubscribeRefUpdates(events)
	announceTarget(t, events, "refs/heads/main", "sha-target")
	announceTarget(t, events, "refs/heads/feature", "sha-head")
	service.SetFindingsFacts(provider)
	return service, refs
}

// bundleGateMR is the approved merge the gate decides about: two first-party
// non-author approvals — the four-eyes floor (ADR-0085) — against a
// one-approval rule, so the approval gate is satisfied and any denial below is
// attributable to the security gate itself (SPEC-0029 AC3).
func bundleGateMR(t *testing.T, service *Service) api.MergeRequest {
	t.Helper()
	ctx := t.Context()
	if _, err := service.SetProtection(ctx, api.ProtectionRequest{
		Context:   principal("tenant-a", "admin-a", "request-protect", "owner"),
		TargetRef: "refs/heads/main", RequiredApprovals: 1,
	}); err != nil {
		t.Fatalf("SetProtection: %v", err)
	}
	mr := openOne(t, service, "request-open")
	reviewed, err := service.Review(ctx, api.ReviewRequest{
		Context:        principal("tenant-a", "actor-b", "request-review", "member"),
		MergeRequestID: mr.ID, Disposition: api.DispositionApprove,
		HeadRevision: mr.HeadRevision, ExpectedVersion: mr.Version,
	})
	if err != nil {
		t.Fatalf("Review: %v", err)
	}
	return approveAs(t, service, reviewed, "actor-c", "request-review-2")
}

func mergeUnderGate(t *testing.T, service *Service, mr api.MergeRequest) (api.MergeRequest, error) {
	t.Helper()
	return service.Merge(t.Context(), api.MergeRequestCommand{
		Context:        principal("tenant-a", "actor-a", "request-merge", "member"),
		MergeRequestID: mr.ID, ExpectedVersion: mr.Version,
	})
}

// A finding attributed at or above the reviewed severity threshold blocks the
// merge, and the block is a PDP decision over server-derived facts — the
// approvals are sufficient, so only the findings breach explains the denial
// (SPEC-0029 AC3).
func TestBundleGateBlocksAtSeverityThreshold(t *testing.T) {
	for _, severity := range []string{"HIGH", "CRITICAL"} {
		service, refs := bundleGate(t, &fakeFactsProvider{facts: api.FindingsGateFacts{
			High: 1, HighestAttributedSeverity: severity,
		}})
		mr := bundleGateMR(t, service)
		if _, err := mergeUnderGate(t, service, mr); !errors.Is(err, api.ErrDenied) {
			t.Fatalf("severity %s: a threshold-breaching merge was allowed", severity)
		}
		if len(refs.moves) != 0 {
			t.Fatalf("severity %s: a denied merge moved the ref: %v", severity, refs.moves)
		}
	}
}

// Below the threshold an attributed finding does not block, and a clean
// comparison (no attributed findings) does not block (SPEC-0029 AC3).
func TestBundleGateAllowsBelowThreshold(t *testing.T) {
	for _, facts := range []api.FindingsGateFacts{
		{Medium: 3, HighestAttributedSeverity: "MEDIUM"},
		{Low: 1, HighestAttributedSeverity: "LOW"},
		{HighestAttributedSeverity: "NONE"},
	} {
		service, refs := bundleGate(t, &fakeFactsProvider{facts: facts})
		mr := bundleGateMR(t, service)
		merged, err := mergeUnderGate(t, service, mr)
		if err != nil {
			t.Fatalf("facts %+v: a below-threshold merge was denied: %v", facts, err)
		}
		if merged.State != api.StateMerged || len(refs.moves) != 1 {
			t.Fatalf("facts %+v: merged=%+v moves=%v", facts, merged.State, refs.moves)
		}
	}
}

// An ACCEPT/FALSE_POSITIVE triage exemption the facts carry lifts a breach,
// and the merge lands (SPEC-0029 AC4).
func TestBundleGateTriageExemptionLiftsABreach(t *testing.T) {
	service, refs := bundleGate(t, &fakeFactsProvider{facts: api.FindingsGateFacts{
		High: 1, HighestAttributedSeverity: "HIGH",
		ReliedUponTriageIDs: []string{"triage-1"},
	}})
	mr := bundleGateMR(t, service)
	if _, err := mergeUnderGate(t, service, mr); err != nil {
		t.Fatalf("an exempted breach must not block: %v", err)
	}
	if len(refs.moves) != 1 {
		t.Fatalf("an exempted merge must move the ref: %v", refs.moves)
	}
}

// The gate engaged but its facts did not assemble: the reviewed policy FAILS
// CLOSED — a denial, never a fail-open default (SPEC-0029 AC9).
func TestBundleGateFailsClosedOnMissingFacts(t *testing.T) {
	service, refs := bundleGate(t, &fakeFactsProvider{err: errors.New("facts unavailable")})
	mr := bundleGateMR(t, service)
	if _, err := mergeUnderGate(t, service, mr); !errors.Is(err, api.ErrDenied) {
		t.Fatal("an engaged gate with no facts must deny")
	}
	if len(refs.moves) != 0 {
		t.Fatalf("a fail-closed denial moved the ref: %v", refs.moves)
	}
}

// Composition (SPEC-0029 AC5): findings clear, but the approval requirement
// unmet — the approval gate still denies. Neither gate replaces the other.
func TestBundleGateComposesWithTheApprovalGate(t *testing.T) {
	service, _ := bundleGate(t, &fakeFactsProvider{facts: api.FindingsGateFacts{HighestAttributedSeverity: "NONE"}})
	ctx := t.Context()
	if _, err := service.SetProtection(ctx, api.ProtectionRequest{
		Context:   principal("tenant-a", "admin-a", "request-protect", "owner"),
		TargetRef: "refs/heads/main", RequiredApprovals: 1,
	}); err != nil {
		t.Fatalf("SetProtection: %v", err)
	}
	mr := openOne(t, service, "request-open") // opened, never approved
	if _, err := mergeUnderGate(t, service, mr); !errors.Is(err, api.ErrDenied) {
		t.Fatal("a merge with clear findings but no approval must be denied by the approval gate")
	}
}

// No facts provider wired: the SPEC-0019 behaviour stands unchanged — the
// security gate applies only when engaged (backward compatibility).
func TestBundleGateDisengagedLeavesApprovalGateAlone(t *testing.T) {
	service, refs := bundleGate(t, nil)
	mr := bundleGateMR(t, service)
	if _, err := mergeUnderGate(t, service, mr); err != nil {
		t.Fatalf("an approved merge without an engaged findings gate must land: %v", err)
	}
	if len(refs.moves) != 1 {
		t.Fatalf("ref moves = %v", refs.moves)
	}
}
