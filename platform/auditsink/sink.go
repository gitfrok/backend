// Package auditsink composes the platform audit events onto the Postgres trail.
//
// Modules publish audit events onto the bus, and this optional sink is what
// makes them durable; planes compose it, leaving the emission points untouched. A plane without a
// database URL simply never builds the sink; the events are still published and
// still dropped, exactly as they always were. Building the sink and failing to
// append is never silent: the handler returns the error, and the bus joins it
// back into the publish — the PDP reports an unaudited denial as an error
// rather than as a decision (policy service, ADR-0007).
package auditsink

import (
	"context"
	"strconv"
	"strings"

	auditmodule "github.com/gitfrok/backend/modules/audit"
	auditapi "github.com/gitfrok/backend/modules/audit/api"
	platformaudit "github.com/gitfrok/backend/platform/audit"
	"github.com/gitfrok/backend/platform/bus"
	"github.com/gitfrok/backend/platform/db"
	"github.com/gitfrok/backend/platform/tenancy"
)

// Sink appends first-party audit events to the trail. Append and Verify are the
// whole of its surface; it inherits the log's append-only invariant (ADR-0007).
type Sink struct {
	log auditapi.Log
}

// NewSink builds the sink over a tenant-scoped pool and optionally wires the
// pool's own row-level-security violation events onto the same bus it will be
// subscribed to.
func NewSink(pool *db.Pool, events bus.Bus) *Sink {
	pool = pool.WithAuditBus(events)
	return &Sink{log: auditmodule.NewPostgresLog(pool)}
}

// Subscribe registers every audit-bearing event this sink knows. Adding a new
// auditable event is an addition here, never a change to an existing handler.
func (s *Sink) Subscribe(events bus.Bus) {
	bus.SubscribeTyped(events, s.appendDenied)
	bus.SubscribeTyped(events, s.appendIsolationViolation)
	bus.SubscribeTyped(events, s.appendApproval)
	bus.SubscribeTyped(events, s.appendMerge)
	bus.SubscribeTyped(events, s.appendFindingsScanIngested)
	bus.SubscribeTyped(events, s.appendFindingsTriaged)
}

func (s *Sink) appendDenied(ctx context.Context, e platformaudit.PolicyDecisionDenied) error {
	// The provenance keys are the audit contract's decision-provenance fields (SPEC-0029 AC8,
	// SPEC-0030): a denial's record names the decision, the deciding policy version, the digest
	// over the input decided on, and the mode — a DRY_RUN decision would be labelled here, never
	// written as an enforced control record.
	detail := map[string]string{
		"decision_id":     e.DecisionID,
		"policy_revision": e.PolicyRevision,
		"input_digest":    e.InputDigest,
		"policy_mode":     e.PolicyMode,
	}
	if len(e.ReliedUponTriage) > 0 {
		detail["relied_upon_triage_ids"] = strings.Join(e.ReliedUponTriage, ",")
	}
	return s.append(ctx, e.TenantID, auditapi.Entry{
		TenantID:   e.TenantID,
		Action:     auditapi.Action(e.DeniedAction),
		ActorID:    e.ActorID,
		Resource:   e.Resource,
		Outcome:    auditapi.OutcomeDenied,
		Detail:     detail,
		OccurredAt: e.OccurredAt,
	})
}

func (s *Sink) appendIsolationViolation(ctx context.Context, e platformaudit.TenantIsolationViolation) error {
	return s.append(ctx, e.TenantID, auditapi.Entry{
		TenantID:   e.TenantID,
		Action:     auditapi.Action(platformaudit.ActionTenantIsolationViolation),
		Outcome:    auditapi.OutcomeDenied,
		Detail:     map[string]string{"operation": e.Operation, "sqlstate": e.SQLState, "policy_message": e.Detail},
		OccurredAt: e.OccurredAt,
	})
}

func (s *Sink) appendApproval(ctx context.Context, e platformaudit.MergeRequestApproved) error {
	return s.append(ctx, e.TenantID, auditapi.Entry{
		TenantID: e.TenantID,
		Action:   auditapi.Action(platformaudit.ActionMergeRequestApproved),
		ActorID:  e.ActorID,
		Resource: "merge_request/" + e.MergeRequestID,
		Outcome:  auditapi.OutcomeAllowed,
		Detail: map[string]string{
			"repository_id": e.RepositoryID, "head_revision": e.HeadRevision,
			"request_id": e.RequestID, "decision_id": e.PolicyDecisionID,
		},
		OccurredAt: e.OccurredAt,
	})
}

func (s *Sink) appendMerge(ctx context.Context, e platformaudit.MergeRequestMerged) error {
	return s.append(ctx, e.TenantID, auditapi.Entry{
		TenantID: e.TenantID,
		Action:   auditapi.Action(platformaudit.ActionMergeRequestMerged),
		ActorID:  e.ActorID,
		Resource: "merge_request/" + e.MergeRequestID,
		Outcome:  auditapi.OutcomeAllowed,
		Detail: map[string]string{
			"repository_id": e.RepositoryID, "target_ref": e.TargetRef, "head_revision": e.HeadRevision,
			"request_id": e.RequestID, "decision_id": e.PolicyDecisionID,
		},
		OccurredAt: e.OccurredAt,
	})
}

// appendFindingsScanIngested records an accepted security scan ingest
// (SPEC-0025 AC5). The emission point is the ingest service; the replay
// guard there is what makes this append exactly-once per accepted batch.
func (s *Sink) appendFindingsScanIngested(ctx context.Context, e platformaudit.FindingsScanIngested) error {
	return s.append(ctx, e.TenantID, auditapi.Entry{
		TenantID: e.TenantID,
		Action:   auditapi.Action(platformaudit.ActionFindingsScanIngested),
		ActorID:  e.ActorID,
		Resource: "repository/" + e.RepositoryID,
		Outcome:  auditapi.OutcomeAllowed,
		Detail: map[string]string{
			"scan_id": e.ScanID, "request_id": e.RequestID,
			"decision_id":       e.PolicyDecisionID,
			"findings_recorded": strconv.FormatInt(e.FindingsRecorded, 10),
		},
		OccurredAt: e.OccurredAt,
	})
}

// appendFindingsTriaged records an accepted triage transition (SPEC-0026
// AC4). The emission point is the triage service; its replay and
// version-mismatch guards are what make this append exactly-once per
// recorded transition. The record names the actor, the finding, the prior
// and new state, and the decision ID that authorized the transition —
// never the justification text, which stays with the triage record.
func (s *Sink) appendFindingsTriaged(ctx context.Context, e platformaudit.FindingsTriaged) error {
	return s.append(ctx, e.TenantID, auditapi.Entry{
		TenantID: e.TenantID,
		Action:   auditapi.Action(platformaudit.ActionFindingsTriaged),
		ActorID:  e.ActorID,
		Resource: "finding/" + e.FindingID,
		Outcome:  auditapi.OutcomeAllowed,
		Detail: map[string]string{
			"repository_id": e.RepositoryID, "triage_id": e.TriageID,
			"prior_state": e.PriorState, "new_state": e.NewState,
			"request_id": e.RequestID, "decision_id": e.PolicyDecisionID,
		},
		OccurredAt: e.OccurredAt,
	})
}

// append scopes the surrounding transaction to the event's own tenant before
// writing. The trail is tenant-isolated (SPEC-0003), so the scoping is the
// record's read side as much as its write side. Every sink record is first
// party: it is witnessed by a plane of this platform, and ADR-0029 §1 admits
// nothing else — the store rejects any other class.
func (s *Sink) append(ctx context.Context, tenant string, e auditapi.Entry) error {
	e.Provenance = auditapi.ProvenanceFirstParty
	_, err := s.log.Append(tenancy.WithTenant(ctx, tenancy.ID(tenant)), e)
	return err
}
