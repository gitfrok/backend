package audit

import "time"

// ActionFindingsScanIngested is the `action` value for an accepted security
// scan ingest (SPEC-0025 AC5).
const ActionFindingsScanIngested = "findings.scan_ingested"

// FindingsScanIngested records that a scan's findings batch was accepted and
// completed. SPEC-0025 AC5: an accepted ingest appends exactly one immutable
// audit record — tenant, actor, repository resource, action, outcome, request
// ID, and decision ID. It carries no provenance bytes, scanner output, source
// code, or authorization result; the replay guard in the ingest service is
// what keeps the emission exactly-once.
type FindingsScanIngested struct {
	TenantID         string
	ActorID          string
	RepositoryID     string
	ScanID           string
	RequestID        string
	PolicyDecisionID string
	FindingsRecorded int64
	OccurredAt       time.Time
}

func (FindingsScanIngested) EventName() string { return EventAudit }
func (e FindingsScanIngested) Action() string  { return ActionFindingsScanIngested }
func (e FindingsScanIngested) Tenant() string  { return e.TenantID }
