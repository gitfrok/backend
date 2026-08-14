package app

import (
	"context"
	"errors"
	"slices"

	codereviewapi "github.com/gitfrok/backend/modules/codereview/api"
	"github.com/gitfrok/backend/modules/security/api"
)

// The merge-gate findings-facts assembler (T-0025, SPEC-0029, SPEC-0030).
//
// Code Review's merge decision presents server-derived findings facts to the
// reviewed security gate, and this is where Security/Findings assembles them
// from its OWN state — the SPEC-0028 attribution it already materializes and
// the triage records keyed to finding identities. The facts cross the module
// boundary as values on Code Review's FindingsFacts port, never as a read of
// this context's tables, and the merge decision itself is the authorization:
// the assembler performs no PDP decision of its own (ADR-0022).
//
// Every way the facts can fail to assemble is the same error, and Code
// Review presents it as an engaged gate with no facts — which the reviewed
// policy denies (SPEC-0029 AC9). Missing, stale, and malformed are
// indistinguishable on purpose: a fact that could not be assembled fails
// closed, never a fail-open default and never a synchronous cross-context
// read to recover it.

// errMergeFactsUnavailable is the one shape every failed assembly returns.
var errMergeFactsUnavailable = errors.New("security: merge findings facts unavailable")

// mergeGateSeverityRank orders the FindingSeverity vocabulary so a threshold
// comparison is a single >=, mirroring severity_rank in the reviewed security
// merge gate (governance/policies/gitsaas/authz/authz.rego).
var mergeGateSeverityRank = map[api.Severity]int{
	api.SeverityLow:      1,
	api.SeverityMedium:   2,
	api.SeverityHigh:     3,
	api.SeverityCritical: 4,
}

// MergeFindingsFacts assembles the server-derived findings facts one merge
// decision presents to the security gate (SPEC-0030 AC4): the attributed
// counts by severity, the highest attributed severity, and the
// ACCEPT/FALSE_POSITIVE triage records the exemption relies on.
//
// The merge request must be known to this context's own event-fed projection
// and match the named repository; the comparison must be materialized,
// ATTRIBUTED, and current at the projection's head. Anything else — unknown
// merge request, UNAVAILABLE comparison, stale record, a triage read that
// fails — is errMergeFactsUnavailable, and the merge gate fails closed on it.
func (s *Service) MergeFindingsFacts(ctx context.Context, tenantID, repositoryID, actorID, mergeRequestID string) (codereviewapi.FindingsGateFacts, error) {
	if tenantID == "" || repositoryID == "" || actorID == "" || mergeRequestID == "" {
		return codereviewapi.FindingsGateFacts{}, errMergeFactsUnavailable
	}
	mr, ok := s.projectionFor(tenantID, mergeRequestID)
	if !ok || mr.RepositoryID != repositoryID {
		return codereviewapi.FindingsGateFacts{}, errMergeFactsUnavailable
	}

	// The comparison is the same server fact the read surface serves,
	// recomputed under the merge's own actor — but a gate fact accepts no
	// stale fallback: a record lagging the head is a fail-closed denial, not
	// a served stale page (SPEC-0029 AC9).
	outcome, err := s.computeAttribution(ctx, tenantID, mergeRequestID, actorID)
	if err != nil || outcome.record == nil || outcome.record.status != api.AttributionAttributed {
		return codereviewapi.FindingsGateFacts{}, errMergeFactsUnavailable
	}
	if outcome.record.head != mr.HeadRevision {
		return codereviewapi.FindingsGateFacts{}, errMergeFactsUnavailable
	}
	rec := outcome.record

	// The severity threshold is read from the Code Review contract
	// (SPEC-0029 AC3). A fully PDP-driven threshold would need a governance
	// contract change (recorded follow-up, out of scope for the phase-2 fix
	// wave); until then the constant-parity test in
	// threshold_parity_test.go fails CI when the reviewed rego bundle's
	// security_severity_threshold (governance/policies/gitsaas/authz/
	// authz.rego) drifts from this constant.
	threshold, ok := mergeGateSeverityRank[api.Severity(codereviewapi.SecurityGateSeverityThreshold)]
	if !ok {
		return codereviewapi.FindingsGateFacts{}, errMergeFactsUnavailable
	}

	facts := codereviewapi.FindingsGateFacts{
		Low:                       rec.low,
		Medium:                    rec.medium,
		High:                      rec.high,
		Critical:                  rec.critical,
		HighestAttributedSeverity: codereviewapi.FindingsGateSeverityNone,
	}
	highestRank := 0
	// breachCoverage pairs every ATTRIBUTED finding at or above the security
	// threshold with the ACCEPT/FALSE_POSITIVE triage record covering it. The
	// exemption stands only when every breach-level finding is covered: a
	// partial coverage is no coverage (SPEC-0029 AC4).
	type breachCoverage struct {
		findingID string
		triageID  string
		covered   bool
	}
	var breaches []breachCoverage
	for _, view := range rec.views {
		if view.attribution != api.AttributionAttributed {
			continue
		}
		rank, ok := mergeGateSeverityRank[view.finding.Severity]
		if !ok {
			// A severity outside the vocabulary is a malformed fact: fail
			// closed rather than rendering it to the gate.
			return codereviewapi.FindingsGateFacts{}, errMergeFactsUnavailable
		}
		if rank > highestRank {
			highestRank = rank
			facts.HighestAttributedSeverity = string(view.finding.Severity)
		}
		if rank < threshold {
			continue
		}
		triage, found, err := s.store.GetTriage(ctx, tenantID, view.finding.ID, 0)
		if err != nil {
			return codereviewapi.FindingsGateFacts{}, errMergeFactsUnavailable
		}
		coverage := breachCoverage{findingID: view.finding.ID}
		if found && (triage.State == api.TriageAccept || triage.State == api.TriageFalsePositive) {
			coverage.triageID, coverage.covered = triage.TriageID, true
		}
		breaches = append(breaches, coverage)
	}

	for _, breach := range breaches {
		if !breach.covered {
			// The breach stands: the facts render it uncovered, and the
			// decision records no exemption.
			return facts, nil
		}
	}
	for _, breach := range breaches {
		facts.ReliedUponTriageIDs = append(facts.ReliedUponTriageIDs, breach.triageID)
	}
	slices.Sort(facts.ReliedUponTriageIDs)
	return facts, nil
}
