package audit

import "time"

// ActionHistoryImported is the `action` value for one accepted repository
// import (ADR-0029 §3, SPEC-0011 AC10). It is the single first-party audit
// event an import produces; the imported content itself is ATTESTED_IMPORT and
// never enters the trail.
const ActionHistoryImported = "repository.import.completed"

// ActionHistoryImportRevoked is the `action` value for one accepted import
// revocation (ADR-0029 §5, SPEC-0011 AC17). Revocation is forward-only: the
// records are tombstoned, the original HistoryImported chain entry stays
// unaltered (invariant 5).
const ActionHistoryImportRevoked = "repository.import.revoked"

// HistoryImported records the auditable fact — this authenticated operator
// imported this attested set from there at this time — plus the manifest digest
// over the imported payload set, so the set is reproducible after the fact
// without claiming it is true.
type HistoryImported struct {
	TenantID       string
	ActorID        string
	RepositoryID   string
	ImportID       string
	SourceSystem   string
	SourceInstance string
	RecordCounts   map[string]int64
	ManifestDigest string
	OccurredAt     time.Time
}

// EventName is the routing key — the audit event message's full name.
func (HistoryImported) EventName() string { return EventAudit }

// Action is the dotted action this event records.
func (HistoryImported) Action() string { return ActionHistoryImported }

// Tenant reports the scope the import happened under.
func (e HistoryImported) Tenant() string { return e.TenantID }

// HistoryImportRevoked records the revocation of a prior import. It carries the
// import_id, never the imported content.
type HistoryImportRevoked struct {
	TenantID     string
	ActorID      string
	RepositoryID string
	ImportID     string
	OccurredAt   time.Time
}

// EventName is the routing key — the audit event message's full name.
func (HistoryImportRevoked) EventName() string { return EventAudit }

// Action is the dotted action this event records.
func (HistoryImportRevoked) Action() string { return ActionHistoryImportRevoked }

// Tenant reports the scope the revocation happened under.
func (e HistoryImportRevoked) Tenant() string { return e.TenantID }
