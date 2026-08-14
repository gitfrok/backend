// The merge-gate findings-facts port (T-0025, SPEC-0029, SPEC-0030).
//
// A security rule may block a merge on the findings SPEC-0028 attributes to
// it, and the block is a PDP decision over SERVER-DERIVED findings context —
// never UI logic, a caller assertion, or a BFF check (SPEC-0029 AC3). The
// facts travel on the merge decision's context map exactly the way
// valid_approvals does: assembled by the calling context from another
// context's own state (ADR-0022), presented to the PDP, and never supplied
// by the caller.
//
// Code Review declares this port and consumes it; Security/Findings
// implements it; the composition root wires the two together
// (cmd/dataplane-app and only cmd/dataplane-app), which is what keeps the
// dependency at api/ surfaces and preserves the no-cross-internal-import
// invariant. A merge service with no provider attached leaves the SPEC-0019
// approval gate exactly as it was: the security gate applies only when
// engaged (governance/policies/gitsaas/authz/authz.rego, findings_gate).
package api

import (
	"context"
	"strconv"
	"strings"
)

// The context-key vocabulary the merge decision presents its findings facts
// under. It is the same vocabulary the reviewed security merge gate consumes
// (governance/policies/gitsaas/authz/authz.rego, T-0025): the keys are part
// of the contract with governance/policies, and a rename here without the
// paired governance PR would silently disengage the gate.
const (
	// ContextKeyFindingsGate engages the security findings gate: "true" when
	// a security rule requires findings facts for this merge, absent
	// otherwise. Its absence leaves the approval gate unchanged.
	ContextKeyFindingsGate = "findings_gate"
	// ContextKeyFindingsHighestSeverity is the highest severity among the
	// merge's attributed findings: NONE / LOW / MEDIUM / HIGH / CRITICAL.
	ContextKeyFindingsHighestSeverity = "findings_highest_severity"
	// ContextKeyFindingsLow..Critical are the merge's attributed counts by
	// severity.
	ContextKeyFindingsLow      = "findings_low"
	ContextKeyFindingsMedium   = "findings_medium"
	ContextKeyFindingsHigh     = "findings_high"
	ContextKeyFindingsCritical = "findings_critical"
	// ContextKeyReliedUponTriageIDs lists the ACCEPT/FALSE_POSITIVE triage
	// record IDs the exemption relied on, comma-separated; empty when no
	// exemption was applied (SPEC-0029 AC4).
	ContextKeyReliedUponTriageIDs = "relied_upon_triage_ids"
)

// FindingsGateSeverityNone names the absence of any attributed finding on the
// merge decision's context. It is a merge-gate vocabulary value, not a
// Security/Findings severity: the findings scale starts at LOW, and "no
// attributed finding" is a fact about the comparison, not a finding.
const FindingsGateSeverityNone = "NONE"

// SecurityGateSeverityThreshold is the severity a merge's attributed findings
// must stay below for the security gate to allow it — the backend's mirror of
// security_severity_threshold in governance/policies/gitsaas/authz/authz.rego
// (T-0025). The facts provider needs it for one purpose only: deciding WHICH
// triage records the gate relies on. Facts assembled under it are never
// over-permissive if the reviewed threshold moves — a drift makes the gate
// stricter, never looser — but a governance PR that changes the policy
// threshold must change this constant in the same change.
const SecurityGateSeverityThreshold = "HIGH"

// FindingsGateFacts is the server-derived findings input one merge decision
// presents to the PDP (SPEC-0030). Every field is a fact Security/Findings
// computed under SPEC-0028 attribution; none is representable as a caller
// claim, and the shape is what the reviewed security merge gate consumes.
type FindingsGateFacts struct {
	// Low, Medium, High and Critical are the merge's attributed counts by
	// severity — the findings SPEC-0028 attributes to it. They are the same
	// counts the attribution summary reports; a triage exemption does not
	// change them, it is recorded in ReliedUponTriageIDs.
	Low      int64
	Medium   int64
	High     int64
	Critical int64
	// HighestAttributedSeverity is the highest severity among the merge's
	// attributed findings, or FindingsGateSeverityNone when the comparison
	// attributed nothing. It is the fact the severity-threshold rule
	// compares, and it is rendered before any triage exemption: the
	// exemption travels in ReliedUponTriageIDs so the decision records both
	// the breach and what covered it.
	HighestAttributedSeverity string
	// ReliedUponTriageIDs lists the ACCEPT/FALSE_POSITIVE triage record IDs
	// covering the attributed findings that breach the security threshold,
	// and ONLY when they fully cover that breach — its presence is both the
	// exemption and the record of what the decision relied on (SPEC-0029
	// AC4). Empty when no exemption was applied.
	ReliedUponTriageIDs []string
}

// Context renders the facts as the merge decision's context entries, under
// the reviewed key vocabulary. It renders every fact, never a default for one
// it does not have.
func (f FindingsGateFacts) Context() map[string]string {
	out := map[string]string{
		ContextKeyFindingsHighestSeverity: f.HighestAttributedSeverity,
		ContextKeyFindingsLow:             strconv.FormatInt(f.Low, 10),
		ContextKeyFindingsMedium:          strconv.FormatInt(f.Medium, 10),
		ContextKeyFindingsHigh:            strconv.FormatInt(f.High, 10),
		ContextKeyFindingsCritical:        strconv.FormatInt(f.Critical, 10),
	}
	if len(f.ReliedUponTriageIDs) > 0 {
		out[ContextKeyReliedUponTriageIDs] = strings.Join(f.ReliedUponTriageIDs, ",")
	}
	return out
}

// FindingsFactsProvider assembles the server-derived findings facts one merge
// decision presents to the PDP (SPEC-0029 AC3, SPEC-0030 AC4).
//
// It is an INPUT ASSEMBLER, not a decision: it performs no authorization of
// its own, because the merge decision it feeds is the authorization — facts
// arrive on the decision's context exactly as ADR-0022 provides, and no
// nested PDP question sits between a context and the facts it assembles. It
// reads no caller claim either: the arguments are the verified identity the
// merge itself was asked under and the merge request the facts are about.
type FindingsFactsProvider interface {
	// FindingsFacts returns the attributed-findings facts for one merge
	// request, current at its head revision. A non-nil error means the facts
	// did not assemble — missing, stale, or malformed — and the merge gate
	// engages the security rule WITHOUT the facts, which the reviewed policy
	// denies: fail closed, never a fail-open default and never a synchronous
	// cross-context table read to recover them (SPEC-0029 AC9, SPEC-0030
	// AC4).
	FindingsFacts(ctx context.Context, tenantID, repositoryID, actorID, mergeRequestID string) (FindingsGateFacts, error)
}
