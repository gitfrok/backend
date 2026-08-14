package main

import (
	"context"
	"time"

	"github.com/gitfrok/backend/modules/agent/api"
	auditapi "github.com/gitfrok/backend/modules/audit/api"
	residencyapi "github.com/gitfrok/backend/modules/residency/api"
)

// residencyDetectionWindowEnv bounds how long a contradiction between declared and
// observed placement may go unflagged (T-0033, SPEC-0040 AC3). Detection runs
// synchronously at observation and declaration time, so the realized latency is bounded
// by this window by construction; the value is per-environment configuration, never a
// compiled-in constant (invariant 13). Unset or unparseable means zero — detection is
// then immediate.
const residencyDetectionWindowEnv = "GITFROK_RESIDENCY_DETECTION_WINDOW"

// residencyReportIntervalEnv is how long a data plane's placement reporting may be
// silent before the evidence pack's residency section renders the silence as a gap
// (T-0033, SPEC-0040 AC5). Unset or unparseable means zero — fail-safe: every interval
// renders as a gap and no silence is ever read as compliance.
const residencyReportIntervalEnv = "GITFROK_RESIDENCY_MAX_REPORT_INTERVAL"

// residencyDuration parses one residency window from the environment; unset or
// unparseable values fall back to zero, which each consumer treats as its fail-safe.
func residencyDuration(getenv func(string) string, name string) time.Duration {
	raw := getenv(name)
	if raw == "" {
		return 0
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d < 0 {
		return 0
	}
	return d
}

// residencyTrailWitness adapts the control plane's audit trail onto the Residency
// context's witness port (T-0033, SPEC-0040). The composition root is the only place
// that may know both surfaces: Residency declares the port in its own terms so the
// module graph stays acyclic (invariant 14), and the control plane supplies the
// rendering — every residency record is a control-plane-observed, first-party fact, so
// the provenance is always FIRST_PARTY and the outcome mirrors the entry's denied flag
// (SPEC-0040 AC7: no customer-supplied value ever reaches this trail).
type residencyTrailWitness struct {
	trail auditapi.Log
}

// AppendResidencyRecord implements residencyapi.Witness over the tenant's audit chain,
// returning the chain position the witnessed fact cites (ADR-0007).
func (w residencyTrailWitness) AppendResidencyRecord(ctx context.Context, e residencyapi.WitnessEntry) (residencyapi.WitnessRecord, error) {
	outcome := auditapi.OutcomeAllowed
	if e.Denied {
		outcome = auditapi.OutcomeDenied
	}
	record, err := w.trail.Append(ctx, auditapi.Entry{
		TenantID:   e.TenantID,
		Action:     auditapi.Action(e.Action),
		ActorID:    e.ActorID,
		Resource:   e.Resource,
		Outcome:    outcome,
		Detail:     e.Detail,
		OccurredAt: e.OccurredAt,
		Provenance: auditapi.ProvenanceFirstParty,
	})
	if err != nil {
		return residencyapi.WitnessRecord{}, err
	}
	return residencyapi.WitnessRecord{Seq: record.Seq, Hash: record.Hash}, nil
}

// residencyPlacementGate adapts the Residency context onto the agent surface's placement
// port (T-0033, SPEC-0040 AC2). The agent context declares the port in its own terms and
// never imports Residency; this adapter is the only seam between them (invariant 14).
// Observing the placement is the gate: an admitted placement is witnessed as observed, a
// contradicting one is witnessed as refused and errors here.
type residencyPlacementGate struct {
	svc residencyapi.Service
}

// CheckPlacement implements api.PlacementGate over the Residency context.
func (g residencyPlacementGate) CheckPlacement(ctx context.Context, tenantID, dataPlaneID, cloud, region string) error {
	return g.svc.ObservePlacement(ctx, tenantID, dataPlaneID, cloud, region)
}

var _ api.PlacementGate = residencyPlacementGate{}
