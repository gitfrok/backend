// Evidence pack export — the Audit context's first read surface (SPEC-0031, SPEC-0032, T-0026).
//
// api.Log stays Append and Verify only; this file adds what Phase 2 owed forward (T-0018 AC19):
// trail queries and action records for the tenant's own chain, and the date-ranged evidence pack
// assembled from them. The two surfaces are separate ports on purpose: handing a reader out of Log
// would make every holder of the append surface a reader of the trail, and the absence of Read on
// Log is a property SPEC-0003 AC1 pins, not an oversight this file may quietly undo.
//
// The structural commitment of SPEC-0032 AC2 is encoded here as a Go type property, mirroring the
// contract schema: SectionRecord — the only shape a control section can carry — has no field
// capable of holding an attested imported record (no provenance block, no foreign handle, no
// declared time, no import reference). Attested history is representable only in the Appendix
// types, labelled as foreign history (ADR-0029 §6). Exclusion therefore holds by construction,
// not by a filter applied at assembly time.
package api

import (
	"context"
	"errors"
	"time"
)

// Context is the verified identity an evidence operation is evaluated under, mirroring
// EvidenceContext in contracts/proto/audit/v1. The actor and roles come from authenticated
// identity; a caller cannot assert them. A pack is always tenant-scoped and can never span two
// tenants (SPEC-0031 AC6), so the context carries no repository: repository scope is a
// per-request filter, never part of the verified identity.
type Context struct {
	TenantID   string
	ActorID    string
	ActorRoles []string
	RequestID  string
}

// ---------------------------------------------------------------------------
// Trail queries and action records
// ---------------------------------------------------------------------------

// TrailQuery delimits one read of the tenant's append-only chain. It is a
// date range and filters, never a record list: a caller selects a range, it
// does not choose which records an answer contains (SPEC-0032's
// server-determined assembly applies to the trail read as much as to packs).
type TrailQuery struct {
	// From and To are inclusive bounds on when the platform witnessed the
	// record. A zero bound leaves that side open; the trail itself is still
	// the only source.
	From time.Time
	To   time.Time
	// Actions restricts the read to these audited actions. Empty reads every
	// action — the stable audit vocabulary from contracts/events/audit/v1.
	Actions []Action
	// RepositoryID restricts to records attributed to one repository. Records
	// the platform witnessed at tenant scope carry no repository attribution
	// and are included either way: a tenant-wide control is evidence of the
	// tenant whatever repository is named.
	RepositoryID string
	// Limit caps the records one read returns, in chain-sequence order. Zero
	// or negative means the store default.
	Limit int
}

// TrailReader reads the tenant's chain. Reading is a separate port from Log:
// the trail's write surface stays Append and Verify only (SPEC-0003 AC1), and
// a plane hands this port only to what the product surface authorizes to read
// — the evidence pack assembler today (SPEC-0031), never a general query API.
type TrailReader interface {
	// Query returns the tenant's records matching q, in chain-sequence order.
	// The ctx carries the tenant scope (SPEC-0001); an unscoped query is an
	// error, not a cross-tenant read. truncated is true when the matching
	// range holds more records than the effective limit: the returned slice
	// is the EARLIEST prefix, and whatever follows it is missing from the
	// answer. A reader that cannot say it truncated would present a partial
	// range as complete — the precise failure SPEC-0031 AC10 forbids.
	Query(ctx context.Context, q TrailQuery) (records []Record, truncated bool, err error)
}

// TrailStore is the audit trail with its Phase 2 read port: append, verify and
// date-ranged queries over action records. Planes compose one implementation;
// the evidence assembler takes this interface and nothing narrower.
type TrailStore interface {
	Log
	TrailReader
}

// ---------------------------------------------------------------------------
// Evidence pack sections
// ---------------------------------------------------------------------------

// SectionType names the five control sections a pack always carries
// (SPEC-0031 AC1, SPEC-0040 AC4). The labelled appendix is deliberately not a
// member: it is a distinct shape, so a section type can never be widened to
// render attested history as a control.
type SectionType int

const (
	// SectionApprovals: approvals witnessed by Code Review.
	SectionApprovals SectionType = iota + 1
	// SectionPolicyDecisions: enforced PDP decisions recorded with their
	// provenance (SPEC-0030).
	SectionPolicyDecisions
	// SectionScanGates: scan gates witnessed by Security/Findings.
	SectionScanGates
	// SectionAccessChanges: access changes witnessed by Identity & Access.
	SectionAccessChanges
	// SectionResidency: the residency facts witnessed by the Residency
	// context (T-0033, SPEC-0040 AC4) — the declarations in force and the
	// observed placement of every data plane that served the tenant.
	// First-party only: a customer attestation can never enter a control
	// section (SPEC-0040 AC7, SPEC-0032 AC2).
	SectionResidency
)

// String renders the section name used in events and status counts — the same
// keys EvidencePackCompleted.section_counts carries.
func (s SectionType) String() string {
	switch s {
	case SectionApprovals:
		return "approvals"
	case SectionPolicyDecisions:
		return "policy_decisions"
	case SectionScanGates:
		return "scan_gates"
	case SectionAccessChanges:
		return "access_changes"
	case SectionResidency:
		return "residency"
	default:
		return "unspecified"
	}
}

// AllSectionTypes is the closed set, in assembly order.
var AllSectionTypes = []SectionType{SectionApprovals, SectionPolicyDecisions, SectionScanGates, SectionAccessChanges, SectionResidency}

// PackState is the lifecycle of an asynchronous assembly (SPEC-0031
// non-functional: observable per section; a large range does not block
// interactive traffic).
type PackState int

const (
	PackPending    PackState = iota + 1 // authorized; assembly has not reported yet
	PackAssembling                      // assembly in progress; per-section counts are live
	PackReady                           // fully assembled and retrievable
	PackFailed                          // could not complete; nothing is retrievable
)

// String renders the state as audit.v1.PackState does, which is what
// EvidencePackCompleted carries as a string.
func (s PackState) String() string {
	switch s {
	case PackPending:
		return "PACK_STATE_PENDING"
	case PackAssembling:
		return "PACK_STATE_ASSEMBLING"
	case PackReady:
		return "PACK_STATE_READY"
	case PackFailed:
		return "PACK_STATE_FAILED"
	default:
		return "PACK_STATE_UNSPECIFIED"
	}
}

// GapReason names why a section could not be fully assembled for part of the
// range (SPEC-0031 AC10, SPEC-0032 AC8). The reason is an honest rendering of
// a source that was unavailable or lagged — never "no records".
type GapReason int

const (
	// GapSourceUnavailable: the owning context's contract surface was
	// unreachable for a bounded part of the range (ADR-0022: sections assemble
	// through contracts or projections only).
	GapSourceUnavailable GapReason = iota + 1
	// GapProjectionLagged: the event-fed projection feeding the section lagged
	// past its freshness bound while the section assembled.
	GapProjectionLagged
	// GapAssemblyFailed: assembly of the section's records failed; nothing is
	// guessed or substituted for the missing part.
	GapAssemblyFailed
	// GapReadTruncated: the trail read hit its bounded limit, so the tail of
	// the range is missing from the section (SPEC-0031 AC10, SPEC-0032 AC8:
	// a truncated section says so instead of presenting the earliest prefix
	// as complete). The wire enum in contracts/proto/audit/v1 predates this
	// reason and renders it as GAP_REASON_UNSPECIFIED until a governance
	// contract change adds a dedicated value; Complete=false plus the gap is
	// the machine-checkable marker either way.
	GapReadTruncated
	// GapRecordsExcluded: the trail witnessed policy-decision records inside
	// the range that the control section cannot admit — enforced decisions
	// lacking part of their SPEC-0030 provenance (decision ID, policy
	// revision, or input digest). They are excluded from the section's
	// records (SPEC-0031 AC3) but their presence is marked, never dropped
	// silently: the section renders Complete: false with one point gap per
	// excluded record (SPEC-0031 AC10). Like GapReadTruncated, the wire
	// enum renders it UNSPECIFIED until a governance contract change adds a
	// dedicated value; Complete=false plus the gap is the machine-checkable
	// marker either way.
	GapRecordsExcluded
	// GapPlacementSilent: the residency section's AC5 gap (SPEC-0040) — an
	// interval in which a data plane's placement reporting was silent past
	// the configured reporting interval, or a range with a declaration in
	// force but no observed placement at all. Silence renders as a gap,
	// never as compliance: absence of contradiction is not evidence of
	// pinning (SPEC-0031 AC10 applied to residency).
	GapPlacementSilent
)

// SectionGap marks the parts of a section's range that could not be assembled.
// The bounds are inclusive; an unbounded or reasonless gap is not representable.
type SectionGap struct {
	From   time.Time
	To     time.Time
	Reason GapReason
}

// ChainAnchor bounds a section's cited slice of the append-only chain
// (ADR-0007, SPEC-0032 verification data). With the anchors a consumer
// re-derives that every cited record sits in the chain and that no cited
// record was mutated (SPEC-0032 AC7).
type ChainAnchor struct {
	FirstSeq int64
	LastSeq  int64
	// FirstRecordHash and LastRecordHash are the chain hashes of the section's
	// first and last cited record, each including its prev-hash link.
	FirstRecordHash string
	LastRecordHash  string
	// PrevRecordHash is the hash of the chain record immediately before
	// FirstSeq — the continuity anchor that closes the section into the chain
	// rather than leaving it a self-certifying list. Empty only when the
	// section cites no records.
	PrevRecordHash string
}

// ApprovalDetail is one first-party approval witnessed by Code Review.
type ApprovalDetail struct {
	MergeRequestID   string
	ProtectionRuleID string
}

// PolicyDecisionDetail is one enforced PDP decision with the provenance
// SPEC-0030 requires a pack to carry: the deciding policy version and the
// digest over the input decided on. There is no mode field — ENFORCED is the
// only mode a control section admits, and a closed shape with one value
// represents that in Go exactly as ControlDecisionMode does in the contract.
type PolicyDecisionDetail struct {
	DecisionID     string
	BundleRevision string
	InputDigest    string
}

// ScanGateDetail is one scan gate witnessed by Security/Findings.
type ScanGateDetail struct {
	MergeRequestID      string
	ScanID              string
	ReliedUponTriageIDs []string
}

// AccessChangeDetail is one access change witnessed by Identity & Access.
type AccessChangeDetail struct {
	AccessKind        string
	TargetPrincipalID string
	GrantID           string
}

// ResidencyFactKind names which residency fact one ResidencyDetail carries —
// the in-process mirror of the contract's closed ResidencyFactKind enum
// (contracts/proto/audit/v1, T-0033). The set is exhaustive and pairwise
// distinguishable: a consumer tells a pinning from an observation, and a
// refused placement from a contradiction, without guessing.
type ResidencyFactKind string

const (
	// ResidencyFactPinning: a declaration taking effect, with its effective
	// time (SPEC-0040 AC1, AC6).
	ResidencyFactPinning ResidencyFactKind = "PINNING"
	// ResidencyFactPlacement: a placement observed for a data plane and
	// admitted under the declaration in force (SPEC-0040 AC4).
	ResidencyFactPlacement ResidencyFactKind = "PLACEMENT"
	// ResidencyFactPlacementRefused: a placement attempt outside the
	// declaration, refused with both placements on the record (SPEC-0040
	// AC2).
	ResidencyFactPlacementRefused ResidencyFactKind = "PLACEMENT_REFUSED"
	// ResidencyFactPlacementContradiction: a declaration taking effect
	// against an already-observed placement — the visible violation state
	// (SPEC-0040 AC3).
	ResidencyFactPlacementContradiction ResidencyFactKind = "PLACEMENT_CONTRADICTION"
)

// ResidencyDetail is one residency fact witnessed by the Residency context —
// always a control-plane-observed, first-party record (SPEC-0040 AC7). It
// carries BOTH placements the fact relates: the pinned half is the
// declaration in force (empty for an observation of an undeclared tenant),
// the observed half is the placement reported or attempted. It has no field
// capable of carrying a customer claim — no provenance, no import reference,
// no attested handle — mirroring the contract's ResidencyRecord, so a
// customer attestation is representable only in the appendix (SPEC-0032
// AC2, applied to residency).
type ResidencyDetail struct {
	FactKind       ResidencyFactKind
	DataPlaneID    string
	PinnedCloud    string
	PinnedRegion   string
	ObservedCloud  string
	ObservedRegion string
}

// SectionRecord is one cited record of a control section: the chain position,
// actor, resource, action, outcome and timestamp the platform witnessed, plus
// exactly one section-specific detail.
//
// This type is the boundary SPEC-0032 AC2 pins, in Go: it has no field capable
// of carrying an attested imported record — no provenance block, no declared
// actor, no declared time, no import ID, no foreign source reference. Those
// exist only in the Appendix types below.
type SectionRecord struct {
	ChainSeq   int64
	RecordHash string
	ActorID    string
	Resource   string
	Action     Action
	Allowed    bool
	OccurredAt time.Time

	// Exactly one detail is set; a record with none is an assembly defect and
	// is dropped rather than presented as an unspecified section.
	Approval       *ApprovalDetail
	PolicyDecision *PolicyDecisionDetail
	ScanGate       *ScanGateDetail
	AccessChange   *AccessChangeDetail
	Residency      *ResidencyDetail
}

// Section is one of the five sections a pack always carries. It embeds its
// records — a self-contained snapshot, not a view (ADR-0055 rule 3) — with the
// anchors tying them to the chain and explicit gaps where the source was
// incomplete.
type Section struct {
	Type    SectionType
	Anchor  ChainAnchor
	Records []SectionRecord
	// Complete is true only when the section was fully assembled across the
	// whole range. False with one or more gaps is the only honest shape of a
	// partial section (SPEC-0032 AC8).
	Complete bool
	Gaps     []SectionGap
	// RecordsDigest is the digest over the section's embedded records as
	// canonically serialized: a consumer recomputes it to detect a mutated
	// section, alongside the per-record chain check (SPEC-0032 AC7).
	RecordsDigest string
}

// ---------------------------------------------------------------------------
// The labelled appendix — the only place attested history is representable
// ---------------------------------------------------------------------------

// AttestedProvenance is the ADR-0029 block labelling a record as foreign
// history: what was fetched from where, declared by whom, declared when. It
// asserts what the source said; it never claims the content is true.
type AttestedProvenance struct {
	ImportID       string
	SourceSystem   string
	SourceInstance string
	// SourceRef is the foreign object's stable identifier as fetched.
	SourceRef string
	// ForeignHandle is the source's own actor assertion — never a platform
	// principal, never resolvable as one (ADR-0029 §4).
	ForeignHandle string
	// DeclaredAt is the source-asserted time, display-only.
	DeclaredAt    time.Time
	PayloadDigest string
}

// AttestedRecord is one attested imported record, representable ONLY in the
// appendix. It embeds the record's payload bytes at generation time
// (ADR-0055 rule 3), so the appendix stays readable after the attested
// store's retention expires the original.
type AttestedRecord struct {
	// RecordKind names what the payload renders — "merge_request",
	// "approval", "thread" — a label for the reader, never a control claim.
	RecordKind string
	// Payload is the embedded rendering of the imported record.
	Payload    []byte
	Provenance AttestedProvenance
}

// HistoryImportedRef is the admitting HistoryImported event, embedded in the
// pack (events/audit/v1.HistoryImported, ADR-0029 §3). Field names mirror the
// event's; the event itself is what the appendix's records reconcile against.
type HistoryImportedRef struct {
	EventID        string
	ActorID        string
	RepositoryID   string
	ImportID       string
	SourceSystem   string
	SourceInstance string
	RecordCounts   map[string]int64
	ManifestDigest string
	OccurredAt     time.Time
}

// AttestedGroup is one import's contribution to the appendix: the admitting
// HistoryImported event and the attested records it admitted.
type AttestedGroup struct {
	Import  HistoryImportedRef
	Records []AttestedRecord
}

// Appendix is the labelled appendix carrying attested imported history
// (SPEC-0031 AC2, ADR-0029 §6). Its label is server-set and travels with the
// records so no renderer can drop it. An empty appendix is a legitimate
// answer: the range admitted no imported history.
type Appendix struct {
	Label  string
	Groups []AttestedGroup
}

// AppendixLabel is the server-set label every generated appendix carries
// (ADR-0029 §6): attested imported history is display-only and makes no
// control-effectiveness claim.
const AppendixLabel = "attested imported history — display-only, no control-effectiveness claim"

// ---------------------------------------------------------------------------
// The pack and its lifecycle
// ---------------------------------------------------------------------------

// Pack is the full self-contained snapshot (ADR-0055 rule 3): identity, the
// closed range it covers, the five control sections and the labelled
// appendix. Sections embed their records and anchors; nothing references the
// chain without embedding what it cites.
type Pack struct {
	PackID       string
	TenantID     string
	RangeFrom    time.Time
	RangeTo      time.Time
	RepositoryID string
	// RequestedBy is the verified actor whose request produced the pack, and
	// DecisionID the PDP decision that authorized generation — both server
	// facts (SPEC-0032 AC6).
	RequestedBy string
	DecisionID  string
	GeneratedAt time.Time
	// Sections is always five, one per SectionType, in assembly order.
	Sections []Section
	// Appendix is always present, possibly empty of records.
	Appendix Appendix
}

// PackChunk is one bounded chunk of a READY pack, mirroring the streamed
// GetEvidencePack shape: the header first, then control sections in
// SectionType order, then the appendix, then a closing chunk carrying no
// content. Exactly one of Header/Section/Appendix is set, or none for the
// closing chunk.
type PackChunk struct {
	Index    int64
	Final    bool
	Header   *Pack
	Section  *Section
	Appendix *Appendix
}

// PackRequest asks for a pack over one closed date range and an optional
// repository scope, and nothing else (SPEC-0032): no record list, no section
// filter, no retention override. A request that would shape the pack's
// contents has no fields to shape them in.
type PackRequest struct {
	RangeFrom    time.Time
	RangeTo      time.Time
	RepositoryID string
}

// PackStatus is one pack's live assembly view (SPEC-0031 non-functional).
type PackStatus struct {
	State         PackState
	FailureReason string
	RangeFrom     time.Time
	RangeTo       time.Time
	RepositoryID  string
	// SectionCounts and SectionGaps are keyed per section, in assembly order;
	// counts are live while assembly runs and final once READY.
	SectionCounts []SectionStatus
	// AppendixRecordCount is a statistic, never record content: the status
	// surface carries no payload, source or provenance bytes (SPEC-0032 G9).
	AppendixRecordCount int64
}

// SectionStatus is one section's observable assembly state.
type SectionStatus struct {
	Type        SectionType
	RecordCount int64
	Gaps        []SectionGap
}

// ErrInvalidPackRequest reports a request that is malformed: an empty context,
// an open or inverted range. Rejected, never partially honoured (SPEC-0032
// AC4).
var ErrInvalidPackRequest = errors.New("audit: invalid evidence pack request")

// ErrPackUnavailable is the ONE coarse shape for every failed read of a pack:
// nonexistent, cross-tenant, unauthorized, and not-yet-ready are
// indistinguishable by design (SPEC-0001, SPEC-0032 AC5), so the surface
// cannot enumerate packs or probe their state.
var ErrPackUnavailable = errors.New("audit: evidence pack unavailable")

// PackService is the evidence export surface in-process, mirroring
// EvidenceService in contracts/proto/audit/v1: request a pack over a closed
// range, observe its assembly, retrieve it. Assembly — which sections, which
// records — is entirely server-determined.
type PackService interface {
	// RequestPack starts the asynchronous assembly of a pack over one closed
	// date range. Generation is a PDP decision (evidence.pack.generate) and is
	// itself audited; replaying the same context, range and request ID returns
	// the same pack and creates no second pack or audit record (SPEC-0032
	// AC1/AC6).
	RequestPack(ctx context.Context, c Context, req PackRequest) (packID string, state PackState, err error)
	// PackStatus observes assembly: the pack's state and per-section counts.
	// Not-found, cross-tenant and unauthorized are one coarse denial.
	PackStatus(ctx context.Context, c Context, packID string) (PackStatus, error)
	// GetPack retrieves a READY pack as its bounded chunk sequence. Retrieval
	// is a PDP decision (evidence.pack.read); reading a pack that is not
	// READY, does not exist, or belongs to another tenant is the same coarse
	// denial.
	GetPack(ctx context.Context, c Context, packID string) ([]PackChunk, error)
}

// AttestedHistorySource supplies the appendix: the attested imported history
// admitted within a range, grouped by the admitting import. It is a port
// rather than a table read (ADR-0022): Audit assembles the appendix through
// the owning context's own surface — Code Review's ImportService today — and
// never reads its storage. A nil source means the plane has no import surface
// at all, in which case an empty appendix is the truthful answer.
type AttestedHistorySource interface {
	AttestedHistory(ctx context.Context, tenantID string, from, to time.Time, repositoryID string) ([]AttestedGroup, error)
}

// AccessChangesSource supplies the access-changes section from Identity &
// Access's own contract surface (SPEC-0032 assumption), never from its
// tables. No such surface exists yet — the auditor-grant lifecycle lands in a
// later task — so a plane composes none and the section degrades per
// contract: an explicit gap marker over the range rather than a partial
// section presented as complete (SPEC-0031 AC10). When the identity surface
// lands, wiring it is a composition-line change.
type AccessChangesSource interface {
	AccessChanges(ctx context.Context, tenantID string, from, to time.Time, repositoryID string) ([]SectionRecord, error)
}
