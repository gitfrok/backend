package audit

import "time"

// ActionCIScanReportIngested is the `action` value recording that one CI scan
// report was taken into the findings plane (SPEC-0037 AC5). It is the
// provenance record for the CI-to-findings handoff: which job attempt's
// report, under which terminal state, landed as which scan.
const ActionCIScanReportIngested = "ci.scan_report_ingested"

// CIScanReportIngested records one scan report's ingest. The terminal state
// rides here — the findings scan record has no field for it and the contracts
// do not change — so a FAILED or CANCELLED job's report is auditable as
// ingested like any other (SPEC-0037 AC5). The replay guard in the ingest
// core keeps the emission exactly-once per (job, attempt, scanner class).
type CIScanReportIngested struct {
	TenantID         string
	ActorID          string
	RepositoryID     string
	JobID            string
	AttemptID        string
	ScannerClass     string
	TerminalState    string
	ScanID           string
	FindingsRecorded int64
	OccurredAt       time.Time
}

func (CIScanReportIngested) EventName() string { return EventAudit }
func (e CIScanReportIngested) Action() string  { return ActionCIScanReportIngested }
func (e CIScanReportIngested) Tenant() string  { return e.TenantID }

// ActionFindingsScanReportRejected is the `action` value recording that a CI
// scan report was refused without changing any finding (SPEC-0037 AC8).
const ActionFindingsScanReportRejected = "findings.scan_report_rejected"

// Rejection reasons are a fixed vocabulary so the trail can be grouped on:
// the report's bytes could not be parsed by its class's adapter, no adapter
// claims the class, or the PDP refused the job's principal.
const (
	ScanReportRejectedUnparseable         = "unparseable"
	ScanReportRejectedUnknownScannerClass = "unknown_scanner_class"
	ScanReportRejectedDenied              = "denied"
)

// FindingsScanReportRejected records one report's refusal. It names the job
// attempt and the reason; it never carries the report's bytes or an error
// string with caller-controlled content beyond the fixed vocabulary.
type FindingsScanReportRejected struct {
	TenantID     string
	ActorID      string
	RepositoryID string
	JobID        string
	AttemptID    string
	ScannerClass string
	Reason       string
	OccurredAt   time.Time
}

func (FindingsScanReportRejected) EventName() string { return EventAudit }
func (e FindingsScanReportRejected) Action() string  { return ActionFindingsScanReportRejected }
func (e FindingsScanReportRejected) Tenant() string  { return e.TenantID }
