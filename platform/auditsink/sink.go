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
	"time"

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

// NewLogSink builds the sink over any audit log — the in-memory trail a dev
// plane composes for the evidence pack surface (T-0026), where module audit
// events feed the trail the assembler reads. It wires no pool, so no RLS
// events: those belong to the database and a plane without one has none.
func NewLogSink(log auditapi.Log) *Sink { return &Sink{log: log} }

// Subscribe registers the sink's single handler for the generic AuditEvent
// routing key. Every audit-bearing event shares that one name — the contract
// chose one generic AuditEvent with the specific case in `action` (T-0006) —
// so dispatch is a type switch here, inside one handler: per-type typed
// subscriptions would each fire on every audit event and reject the ones they
// do not match, because the bus routes by name. Adding a new auditable event
// is an addition to this switch, never a change to an existing case.
func (s *Sink) Subscribe(events bus.Bus) {
	events.Subscribe(platformaudit.EventAudit, s.dispatch)
}

// dispatch routes one audit event to its record shape. Events this sink does
// not know are ignored, not rejected: the AuditEvent name is open by design,
// and a new action another emitter publishes is simply not this sink's.
func (s *Sink) dispatch(ctx context.Context, e bus.Event) error {
	switch ev := e.(type) {
	case platformaudit.PolicyDecisionDenied:
		return s.appendDenied(ctx, ev)
	case platformaudit.TenantIsolationViolation:
		return s.appendIsolationViolation(ctx, ev)
	case platformaudit.MergeRequestApproved:
		return s.appendApproval(ctx, ev)
	case platformaudit.MergeRequestMerged:
		return s.appendMerge(ctx, ev)
	case platformaudit.FindingsScanIngested:
		return s.appendFindingsScanIngested(ctx, ev)
	case platformaudit.FindingsTriaged:
		return s.appendFindingsTriaged(ctx, ev)
	case platformaudit.CIScanReportIngested:
		return s.appendCIScanReportIngested(ctx, ev)
	case platformaudit.FindingsScanReportRejected:
		return s.appendFindingsScanReportRejected(ctx, ev)
	case platformaudit.AgentTokenIssued:
		return s.appendAgentTokenIssued(ctx, ev)
	case platformaudit.AgentTokenRevoked:
		return s.appendAgentTokenRevoked(ctx, ev)
	case platformaudit.AgentEnrolment:
		return s.appendAgentEnrolment(ctx, ev)
	case platformaudit.AgentCertificateIssued:
		return s.appendAgentCertificateIssued(ctx, ev)
	case platformaudit.AgentCertificateRotation:
		return s.appendAgentCertificateRotation(ctx, ev)
	case platformaudit.AgentDataPlaneRevoked:
		return s.appendAgentDataPlaneRevoked(ctx, ev)
	case platformaudit.AgentConnectionRefused:
		return s.appendAgentConnectionRefused(ctx, ev)
	case platformaudit.AgentIdentityOverrideRefused:
		return s.appendAgentIdentityOverrideRefused(ctx, ev)
	default:
		return nil
	}
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

// appendCIScanReportIngested records one CI scan report's ingest (SPEC-0037
// AC5), including the job's terminal state — the provenance that a FAILED or
// CANCELLED job's report was taken in like any other. The emission point is
// the CI scan ingester; the ingest core's replay guard keeps it exactly-once
// per (job, attempt, scanner class).
func (s *Sink) appendCIScanReportIngested(ctx context.Context, e platformaudit.CIScanReportIngested) error {
	return s.append(ctx, e.TenantID, auditapi.Entry{
		TenantID: e.TenantID,
		Action:   auditapi.Action(platformaudit.ActionCIScanReportIngested),
		ActorID:  e.ActorID,
		Resource: "repository/" + e.RepositoryID,
		Outcome:  auditapi.OutcomeAllowed,
		Detail: map[string]string{
			"job_id": e.JobID, "attempt_id": e.AttemptID,
			"scanner_class": e.ScannerClass, "terminal_state": e.TerminalState,
			"scan_id": e.ScanID, "findings_recorded": strconv.FormatInt(e.FindingsRecorded, 10),
		},
		OccurredAt: e.OccurredAt,
	})
}

// appendFindingsScanReportRejected records a scan report refused without any
// finding change (SPEC-0037 AC8): unparseable bytes, a class no adapter
// claims, or a principal the PDP refused.
func (s *Sink) appendFindingsScanReportRejected(ctx context.Context, e platformaudit.FindingsScanReportRejected) error {
	return s.append(ctx, e.TenantID, auditapi.Entry{
		TenantID: e.TenantID,
		Action:   auditapi.Action(platformaudit.ActionFindingsScanReportRejected),
		ActorID:  e.ActorID,
		Resource: "repository/" + e.RepositoryID,
		Outcome:  auditapi.OutcomeDenied,
		Detail: map[string]string{
			"job_id": e.JobID, "attempt_id": e.AttemptID,
			"scanner_class": e.ScannerClass, "reason": e.Reason,
		},
		OccurredAt: e.OccurredAt,
	})
}

// appendAgentTokenIssued records an enrolment token's issuance (T-0030, SPEC-0038). The
// secret never enters the record — the token is named by its ID only (AC2).
func (s *Sink) appendAgentTokenIssued(ctx context.Context, e platformaudit.AgentTokenIssued) error {
	return s.append(ctx, e.TenantID, auditapi.Entry{
		TenantID:   e.TenantID,
		Action:     auditapi.Action(platformaudit.ActionAgentTokenIssued),
		ActorID:    e.ActorID,
		Resource:   "enrolment_token/" + e.TokenID,
		Outcome:    auditapi.OutcomeAllowed,
		Detail:     map[string]string{"expires_at": e.ExpiresAt.UTC().Format(time.RFC3339Nano)},
		OccurredAt: e.OccurredAt,
	})
}

// appendAgentTokenRevoked records an operator revoking an unspent enrolment token.
func (s *Sink) appendAgentTokenRevoked(ctx context.Context, e platformaudit.AgentTokenRevoked) error {
	return s.append(ctx, e.TenantID, auditapi.Entry{
		TenantID:   e.TenantID,
		Action:     auditapi.Action(platformaudit.ActionAgentTokenRevoked),
		ActorID:    e.ActorID,
		Resource:   "enrolment_token/" + e.TokenID,
		Outcome:    auditapi.OutcomeAllowed,
		OccurredAt: e.OccurredAt,
	})
}

// appendAgentEnrolment records one enrolment attempt (SPEC-0038 AC7): the allowed act names
// the minted data plane, the refused one the coarse reason — exactly the shape the presenter
// saw on the wire, nothing more (SPEC-0001).
func (s *Sink) appendAgentEnrolment(ctx context.Context, e platformaudit.AgentEnrolment) error {
	detail := map[string]string{}
	if e.TokenID != "" {
		detail["token_id"] = e.TokenID
	}
	if e.Reason != "" {
		detail["reason"] = e.Reason
	}
	resource := "tenant/" + e.TenantID
	if e.DataPlaneID != "" {
		resource = "data_plane/" + e.DataPlaneID
	}
	return s.append(ctx, e.TenantID, auditapi.Entry{
		TenantID:   e.TenantID,
		Action:     auditapi.Action(platformaudit.ActionAgentEnrolment),
		Resource:   resource,
		Outcome:    auditapi.Outcome(e.Outcome),
		Detail:     detail,
		OccurredAt: e.OccurredAt,
	})
}

// appendAgentCertificateIssued records the first certificate a data plane received on
// enrolment. ID and expiry only — the credential itself stays on the channel (AC2).
func (s *Sink) appendAgentCertificateIssued(ctx context.Context, e platformaudit.AgentCertificateIssued) error {
	return s.append(ctx, e.TenantID, auditapi.Entry{
		TenantID: e.TenantID,
		Action:   auditapi.Action(platformaudit.ActionAgentCertificateIssued),
		Resource: "data_plane/" + e.DataPlaneID,
		Outcome:  auditapi.OutcomeAllowed,
		Detail: map[string]string{
			"certificate_id": e.CertificateID,
			"expires_at":     e.ExpiresAt.UTC().Format(time.RFC3339Nano),
		},
		OccurredAt: e.OccurredAt,
	})
}

// appendAgentCertificateRotation records one rotation act over the established stream
// (SPEC-0038 AC4): applied rotations and failed ones alike, one record per act.
func (s *Sink) appendAgentCertificateRotation(ctx context.Context, e platformaudit.AgentCertificateRotation) error {
	detail := map[string]string{"certificate_id": e.CertificateID}
	if e.Reason != "" {
		detail["reason"] = e.Reason
	}
	return s.append(ctx, e.TenantID, auditapi.Entry{
		TenantID:   e.TenantID,
		Action:     auditapi.Action(platformaudit.ActionAgentCertificateRotation),
		Resource:   "data_plane/" + e.DataPlaneID,
		Outcome:    auditapi.Outcome(e.Outcome),
		Detail:     detail,
		OccurredAt: e.OccurredAt,
	})
}

// appendAgentDataPlaneRevoked records the control-plane act of revoking a data plane's
// identity (ADR-0060 §5).
func (s *Sink) appendAgentDataPlaneRevoked(ctx context.Context, e platformaudit.AgentDataPlaneRevoked) error {
	return s.append(ctx, e.TenantID, auditapi.Entry{
		TenantID:   e.TenantID,
		Action:     auditapi.Action(platformaudit.ActionAgentDataPlaneRevoked),
		ActorID:    e.ActorID,
		Resource:   "data_plane/" + e.DataPlaneID,
		Outcome:    auditapi.OutcomeAllowed,
		OccurredAt: e.OccurredAt,
	})
}

// appendAgentConnectionRefused records a refused connection (SPEC-0038 AC7 names refused
// connections explicitly). Tenant and data plane are present when the credential resolved
// far enough to name them; the reason stays coarse.
func (s *Sink) appendAgentConnectionRefused(ctx context.Context, e platformaudit.AgentConnectionRefused) error {
	resource := "tenant/" + e.TenantID
	if e.DataPlaneID != "" {
		resource = "data_plane/" + e.DataPlaneID
	}
	return s.append(ctx, e.TenantID, auditapi.Entry{
		TenantID:   e.TenantID,
		Action:     auditapi.Action(platformaudit.ActionAgentConnectionRefused),
		Resource:   resource,
		Outcome:    auditapi.OutcomeDenied,
		Detail:     map[string]string{"reason": e.Reason},
		OccurredAt: e.OccurredAt,
	})
}

// appendAgentIdentityOverrideRefused records a payload that claimed another tenant's
// identity on a certified stream (SPEC-0038 AC3): ignored at the time, audited here.
func (s *Sink) appendAgentIdentityOverrideRefused(ctx context.Context, e platformaudit.AgentIdentityOverrideRefused) error {
	return s.append(ctx, e.TenantID, auditapi.Entry{
		TenantID:   e.TenantID,
		Action:     auditapi.Action(platformaudit.ActionAgentIdentityOverrideRefused),
		Resource:   "data_plane/" + e.DataPlaneID,
		Outcome:    auditapi.OutcomeDenied,
		Detail:     map[string]string{"claimed_tenant": e.ClaimedTenant, "message_id": e.MessageID},
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
