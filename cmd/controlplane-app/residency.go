package main

import (
	"context"
	"encoding/base64"
	"fmt"
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

// residencyGRPCAddrEnv opens the residency Declare admin door (T-0038, SPEC-0043,
// ADR-0063) when set; an empty value means the control plane serves no residency
// surface. Unlike the Phase-2 doors, this one verifies its caller before any
// policy decision — the subject is a verified principal, never a wire claim
// (SPEC-0043 AC6).
const residencyGRPCAddrEnv = "GITFROK_RESIDENCY_GRPC_ADDR"

// residencyDoorConfig is the residency Declare door's configuration as one unit:
// a door address without a verifier key is a half-configured boundary and fails
// the rollout (ADR-0006 fail-fast), exactly like the Git front door's.
type residencyDoorConfig struct {
	addr   string
	patKey []byte
}

// loadResidencyDoorConfig validates the door's environment: the PAT verifier key
// (the same credential shape the data plane's Git front door verifies, ADR-0043)
// is REQUIRED whenever the door is open, because a door that cannot verify its
// caller has no business serving a surface that writes control state (SPEC-0043
// AC6). An unconfigured door is fine — the plane then serves no residency surface.
func loadResidencyDoorConfig(getenv func(string) string) (residencyDoorConfig, error) {
	cfg := residencyDoorConfig{addr: getenv(residencyGRPCAddrEnv)}
	if cfg.addr == "" {
		return cfg, nil
	}
	key, err := base64.StdEncoding.DecodeString(getenv(patVerifierKeyEnv))
	if err != nil || len(key) < 32 {
		return cfg, fmt.Errorf("%s requires %s holding base64 of at least 32 bytes: the declare "+
			"door verifies its caller before any policy decision (SPEC-0043 AC6)", residencyGRPCAddrEnv, patVerifierKeyEnv)
	}
	cfg.patKey = key
	return cfg, nil
}

// patVerifierKeyEnv is the shared PAT verifier key the data plane's Git front
// door already reads (cmd/dataplane-app): one credential shape, one key, verified
// through the same narrow gateway on both planes (ADR-0043).
const patVerifierKeyEnv = "GITFROK_PAT_VERIFIER_KEY"

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
