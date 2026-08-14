package app

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/gitfrok/backend/modules/codereview/api"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
	"github.com/gitfrok/backend/platform/audit"
	"github.com/gitfrok/backend/platform/bus"
	"github.com/gitfrok/backend/platform/ids"
)

// GitImporter is Repository/Git's contract boundary for the import git phase
// (SPEC-0011 AC1-AC3). The caller has already been PDP-authorized by this
// context; storage asks its own PDP and runs the fetch through the ordinary
// durability path before the refs are announced.
type GitImporter interface {
	// ImportRefs fetches the source repository's refs and tags into the storage
	// node and returns the refs that moved. The source URL and token are
	// request-only secrets.
	ImportRefs(ctx context.Context, command ImportRefsCommand) (GitResult, error)
}

// GitResult is what one git phase produced: the refs that moved, and the bytes
// the storage tier actually wrote while writing them.
//
// ImportedBytes is measured by the tier that did the writing, not counted off
// the wire. The wire number is a different quantity — it includes protocol
// framing and excludes what repacking costs — and charging it to a tenant would
// bill them for something other than what they now store (SPEC-0011 AC21).
type GitResult struct {
	Refs          []RefUpdate
	ImportedBytes int64
}

// StorageMeter records imported bytes against the tenant's fair-use storage
// dimension (SPEC-0011 AC9/AC21, PRD PR-23).
//
// It is a port, and a build with no meter wired passes nil: fair-use metering
// itself is unbuilt (PRD §12 lists PR-23 as needing its own spec and task), and
// this module must not invent an accounting subsystem to fill the gap. What it
// owes AC9 is the honest number, measured where it can be measured, handed to
// whoever will charge it.
type StorageMeter interface {
	// RecordImportedBytes attributes bytes an import wrote to a tenant's
	// repository. It is called once per completed git phase, after the write is
	// durable — never for a fetch that failed or was refused.
	RecordImportedBytes(ctx context.Context, tenantID, repositoryID, importID string, bytes int64) error
}

// ImportRefsCommand is the verified principal plus the source identity for one
// git-phase fetch.
type ImportRefsCommand struct {
	TenantID, RepositoryID, ActorID, RequestID string
	ActorRoles                                 []string
	SourceURL, SourceToken                     string
}

// RefUpdate is one ref that moved during an import fetch.
type RefUpdate struct {
	Ref, Revision string
}

// HistoryImporter imports pull/merge-request history as ATTESTED_IMPORT
// records (SPEC-0011 AC4). It returns per-type record counts for the
// HistoryImported manifest.
type HistoryImporter interface {
	// ImportHistory fetches and stores the source's review history under the
	// given import ID, returning per-type counts. The source token is a
	// request-only secret.
	ImportHistory(ctx context.Context, command ImportHistoryCommand) (HistoryResult, error)
}

// HistoryResult is what one history phase produced: the per-type record counts
// the manifest is computed over, and the bytes read from the source API.
//
// SourceBytesRead is ingress, not storage. It is what the source's responses
// weighed on the wire, including fields this import never keeps, so it is
// observability rather than the number AC21 charges to a tenant's fair-use
// storage dimension — that one is measured by the storage tier that wrote it
// and arrives with the git phase.
type HistoryResult struct {
	Counts          map[string]int64
	SourceBytesRead int64
}

// ImportHistoryCommand is the verified principal plus the source identity for
// one history-phase import.
type ImportHistoryCommand struct {
	TenantID, RepositoryID, ActorID, RequestID string
	ActorRoles                                 []string
	ImportID                                   string
	SourceURL, SourceToken                     string
	SourceSystem, SourceInstance               string
}

// ImportStore persists import job state, tenant-scoped and append-only in the
// context's own schema (ADR-0029 §2).
type ImportStore interface {
	// CreateOrGetImport records an import under an idempotency key, or returns
	// the one already recorded under it.
	CreateOrGetImport(ctx context.Context, key string, candidate api.Import) (api.Import, bool, error)
	GetImport(ctx context.Context, id string) (api.Import, error)
	ListImports(ctx context.Context, tenantID, repositoryID string) ([]api.Import, error)
	// MarkImportPhase flips one phase flag and the state, guarding on the
	// current state so a revoked import cannot be resumed. counts are the
	// per-type record counts an import produced.
	MarkImportPhase(ctx context.Context, id string, gitPhase, historyPhase bool, state api.ImportState, digest, reason string, counts map[string]int64) (api.Import, error)
	// TombstoneImport marks an import revoked. Imported records with that
	// import_id are excluded from all reads; the original HistoryImported chain
	// entry stays unaltered (invariant 5).
	TombstoneImport(ctx context.Context, id string) (api.Import, error)
}

// ImportService is the Code Review context's import surface.
type ImportService struct {
	store   ImportStore
	records api.ImportedRecordStore
	git     GitImporter
	history HistoryImporter
	pdp     policyapi.DecisionPoint
	bus     bus.Bus
	pacer   Pacer
	meter   StorageMeter
	newID   func() string
	now     func() time.Time
}

// NewImportService wires the import service. history may be nil in a build that
// has not landed the history phase; git and records are required.
func NewImportService(store ImportStore, records api.ImportedRecordStore, git GitImporter, history HistoryImporter, pdp policyapi.DecisionPoint, events bus.Bus) *ImportService {
	return &ImportService{
		store:   store,
		records: records,
		git:     git,
		history: history,
		pdp:     pdp,
		bus:     events,
		// An unconfigured plane imports unpaced rather than refusing to import;
		// WithPacer replaces it.
		pacer: NoPacer{},
		newID: ids.NewULID,
		now:   time.Now,
	}
}

// WithPacer sets the throttle import work runs under (SPEC-0011 AC21). A nil
// pacer leaves the current one in place.
func (s *ImportService) WithPacer(pacer Pacer) *ImportService {
	if pacer != nil {
		s.pacer = pacer
	}
	return s
}

// WithStorageMeter sets where imported bytes are attributed. A nil meter leaves
// the current one in place; a service with no meter still imports, and the
// number it would have charged is simply not recorded anywhere — which is the
// truth about this build, and better than a plausible number nobody measured.
func (s *ImportService) WithStorageMeter(meter StorageMeter) *ImportService {
	if meter != nil {
		s.meter = meter
	}
	return s
}

// ErrImportDenied is the coarse refusal an unauthorized import command returns.
var ErrImportDenied = errors.New("codereview: import unavailable")

// ErrImportStalled is returned when the source rate-limits the import. The
// state machine records STALLED, not FAILED (SPEC-0011 AC8).
var ErrImportStalled = errors.New("codereview: import stalled by the source")

// ErrUnknownSourceSystem is returned when an import names a source system no
// adapter handles. It is a configuration failure, not a stall: retrying cannot
// help until the caller names a supported system.
var ErrUnknownSourceSystem = errors.New("codereview: unknown source system")

// SourceHistoryImporter selects the history adapter by the import's
// source_system, so one plane can import from GitHub or GitLab behind the same
// port.
type SourceHistoryImporter struct {
	adapters map[string]HistoryImporter
}

// NewSourceHistoryImporter wires the per-system adapters.
func NewSourceHistoryImporter(adapters map[string]HistoryImporter) *SourceHistoryImporter {
	return &SourceHistoryImporter{adapters: adapters}
}

// ImportHistory dispatches to the adapter for the command's source system.
func (s *SourceHistoryImporter) ImportHistory(ctx context.Context, command ImportHistoryCommand) (HistoryResult, error) {
	adapter, ok := s.adapters[command.SourceSystem]
	if !ok {
		return HistoryResult{}, ErrUnknownSourceSystem
	}
	return adapter.ImportHistory(ctx, command)
}

// Create starts (or resumes) an import of one source repository. It is
// idempotent per (tenant, repository, source URL): a retried Create returns the
// import already running (SPEC-0011 AC6).
func (s *ImportService) Create(ctx context.Context, req api.CreateImportRequest) (api.Import, error) {
	if !validContext(req.Context) || req.SourceURL == "" || req.SourceSystem == "" {
		return api.Import{}, ErrImportDenied
	}
	if !s.allowed(ctx, req.Context, "repository.import", "repository", req.RepositoryID, map[string]string{
		"source_system": req.SourceSystem,
	}) {
		return api.Import{}, ErrImportDenied
	}

	now := s.now().UTC()
	candidate := api.Import{
		ID: s.newID(), TenantID: req.TenantID, RepositoryID: req.RepositoryID,
		SourceURL: req.SourceURL, SourceSystem: req.SourceSystem, SourceInstance: req.SourceInstance,
		State: api.ImportPending, CreatedAt: now, UpdatedAt: now,
	}
	// The idempotency key is the source identity: resuming an interrupted
	// import reaches the same end state without duplicating work (AC6).
	imp, created, err := s.store.CreateOrGetImport(ctx, "import:"+req.TenantID+":"+req.RepositoryID+":"+req.SourceURL, candidate)
	if err != nil {
		return api.Import{}, ErrImportDenied
	}
	if !created && !resumable(imp) {
		// Complete, failed or revoked: a retry observes it, it does not restart it.
		return imp, nil
	}

	// Import work yields to the interactive traffic it shares the plane with:
	// each phase asks the pacer first, and a refusal stops the import instead of
	// running it unthrottled (AC21).
	if err := s.pacer.Wait(ctx); err != nil {
		// Being paced out is neither the caller's fault nor the source's: the
		// import waited and its turn did not come. That is a stall, the resumable
		// state, not the terminal one a real failure earns (AC4, AC8).
		s.stallPaced(ctx, imp)
		return api.Import{}, ErrImportStalled
	}
	// The git phase runs inline for the dev posture. The source token is used
	// once, here, and never stored. A resumed import skips the phases it already
	// finished, which is what makes resuming free of duplicated work (AC4).
	if !imp.GitPhaseComplete {
		if err := s.runGitPhase(ctx, req, &imp); err != nil {
			s.fail(ctx, imp, "git phase failed")
			return api.Import{}, ErrImportDenied
		}
	}
	if s.history != nil && !imp.HistoryPhaseComplete {
		if err := s.pacer.Wait(ctx); err != nil {
			s.stallPaced(ctx, imp)
			return api.Import{}, ErrImportStalled
		}
		result, err := s.history.ImportHistory(ctx, ImportHistoryCommand{
			TenantID: req.TenantID, RepositoryID: req.RepositoryID, ActorID: req.ActorID,
			RequestID: req.RequestID, ActorRoles: append([]string(nil), req.ActorRoles...),
			ImportID: imp.ID, SourceURL: req.SourceURL, SourceToken: req.SourceToken,
			SourceSystem: req.SourceSystem, SourceInstance: req.SourceInstance,
		})
		if err != nil {
			if errors.Is(err, ErrImportStalled) {
				// Source-side rate limiting is a stall, not a failure (AC8):
				// the import can be resumed.
				s.stall(ctx, imp)
				return api.Import{}, ErrImportStalled
			}
			s.fail(ctx, imp, "history phase failed")
			return api.Import{}, ErrImportDenied
		}
		imp.RecordCounts = result.Counts
		imp.HistoryPhaseComplete = true
	}

	// One first-party HistoryImported audit event per import, chained normally,
	// carrying the manifest digest over the imported set (ADR-0029 §3, AC10).
	imp.State = api.ImportComplete
	// The digest is computed over the records as stored, read back from the
	// store rather than from what the importer said it wrote. A digest over the
	// importer's own claim would verify the importer, not the imported set.
	stored, err := s.records.ListImport(ctx, imp.ID)
	if err != nil {
		s.fail(ctx, imp, "imported records unreadable")
		return api.Import{}, ErrImportDenied
	}
	imp.ManifestDigest = manifestDigest(imp, recordsDigest(stored))
	imp, err = s.store.MarkImportPhase(ctx, imp.ID, true, imp.HistoryPhaseComplete, api.ImportComplete, imp.ManifestDigest, "", imp.RecordCounts)
	if err != nil {
		return api.Import{}, ErrImportDenied
	}
	if err := s.bus.Publish(ctx, audit.HistoryImported{
		TenantID:       imp.TenantID,
		ActorID:        req.ActorID,
		RepositoryID:   imp.RepositoryID,
		ImportID:       imp.ID,
		SourceSystem:   req.SourceSystem,
		SourceInstance: req.SourceInstance,
		RecordCounts:   imp.RecordCounts,
		ManifestDigest: imp.ManifestDigest,
		OccurredAt:     s.now().UTC(),
	}); err != nil {
		return api.Import{}, err
	}
	return imp, nil
}

// runGitPhase fetches the source refs through the storage durability path.
func (s *ImportService) runGitPhase(ctx context.Context, req api.CreateImportRequest, imp *api.Import) error {
	if s.git == nil {
		return fmt.Errorf("import: no git importer configured")
	}
	result, err := s.git.ImportRefs(ctx, ImportRefsCommand{
		TenantID: req.TenantID, RepositoryID: req.RepositoryID, ActorID: req.ActorID,
		RequestID: req.RequestID, ActorRoles: append([]string(nil), req.ActorRoles...),
		SourceURL: req.SourceURL, SourceToken: req.SourceToken,
	})
	if err != nil {
		return err
	}
	imp.GitPhaseComplete = true

	// Metering happens only after the fetch succeeded: a refused or failed
	// import writes nothing durable, and charging a tenant for it would bill
	// them for storage they do not hold (SPEC-0011 AC7/AC9).
	//
	// A meter failure does not fail the import. The bytes are already written
	// and already durable; refusing the import at this point would leave the
	// data in place and report otherwise, which is a worse lie than an
	// unrecorded charge.
	if s.meter != nil && result.ImportedBytes > 0 {
		_ = s.meter.RecordImportedBytes(ctx, imp.TenantID, imp.RepositoryID, imp.ID, result.ImportedBytes)
	}
	return nil
}

// fail marks an import failed with a reason, which is the only place a reason
// is ever written (it names no credential, no URL, no audit content).
func (s *ImportService) fail(ctx context.Context, imp api.Import, reason string) {
	if _, err := s.store.MarkImportPhase(ctx, imp.ID, imp.GitPhaseComplete, imp.HistoryPhaseComplete, api.ImportFailed, "", reason, imp.RecordCounts); err != nil {
		// The failure state itself failed to record; nothing more can be done.
		return
	}
}

// stall marks an import stalled by source-side rate limiting (SPEC-0011 AC8).
// A stalled import is resumable, unlike a failed one.
func (s *ImportService) stall(ctx context.Context, imp api.Import) {
	if _, err := s.store.MarkImportPhase(ctx, imp.ID, imp.GitPhaseComplete, imp.HistoryPhaseComplete, api.ImportStalled, "", "source rate limit", imp.RecordCounts); err != nil {
		return
	}
}

// resumable reports whether an import may be picked up where it stopped. A
// stalled or half-run import is resumable; a completed, failed or revoked one is
// terminal — retrying observes it rather than restarting it (AC4).
func resumable(imp api.Import) bool {
	switch imp.State {
	case api.ImportPending, api.ImportRunning, api.ImportStalled:
		return true
	default:
		return false
	}
}

// stallPaced records an import that could not get a turn. It keeps whatever
// phases already completed, so a resumed import does not redo them.
func (s *ImportService) stallPaced(ctx context.Context, imp api.Import) {
	if _, err := s.store.MarkImportPhase(ctx, imp.ID, imp.GitPhaseComplete, imp.HistoryPhaseComplete, api.ImportStalled, "", "import paced out", imp.RecordCounts); err != nil {
		return
	}
}

// Get returns one import within the caller's tenant. A request in another
// tenant is indistinguishable from one that does not exist.
func (s *ImportService) Get(ctx context.Context, principal api.Context, importID string) (api.Import, error) {
	if !validContext(principal) || importID == "" {
		return api.Import{}, ErrImportDenied
	}
	imp, err := s.store.GetImport(ctx, importID)
	if err != nil || imp.TenantID != principal.TenantID {
		return api.Import{}, ErrImportDenied
	}
	return imp, nil
}

// List returns the imports for a repository within the caller's tenant.
func (s *ImportService) List(ctx context.Context, principal api.Context, repositoryID string) ([]api.Import, error) {
	if !validContext(principal) || repositoryID == "" {
		return nil, ErrImportDenied
	}
	return s.store.ListImports(ctx, principal.TenantID, repositoryID)
}

// Revoke tombstones every record of an import and emits HistoryImportRevoked.
// The original HistoryImported chain entry stays unaltered (SPEC-0011 AC17).
func (s *ImportService) Revoke(ctx context.Context, req api.RevokeImportRequest) (api.Import, error) {
	if !validContext(req.Context) || req.ImportID == "" {
		return api.Import{}, ErrImportDenied
	}
	imp, err := s.store.GetImport(ctx, req.ImportID)
	if err != nil || imp.TenantID != req.TenantID {
		return api.Import{}, ErrImportDenied
	}
	if !s.allowed(ctx, req.Context, "repository.import.revoke", "import", req.ImportID, nil) {
		return api.Import{}, ErrImportDenied
	}
	revoked, err := s.store.TombstoneImport(ctx, req.ImportID)
	if err != nil {
		return api.Import{}, ErrImportDenied
	}
	// Tombstone the imported records too: they are excluded from all reads and
	// exports (AC17). The record store's tombstone is separate from the import
	// state tombstone, but both are forward-only.
	if err := s.records.Tombstone(ctx, req.ImportID); err != nil {
		return api.Import{}, ErrImportDenied
	}
	if err := s.bus.Publish(ctx, audit.HistoryImportRevoked{
		TenantID:     revoked.TenantID,
		ActorID:      req.ActorID,
		RepositoryID: revoked.RepositoryID,
		ImportID:     revoked.ID,
		OccurredAt:   s.now().UTC(),
	}); err != nil {
		return api.Import{}, err
	}
	return revoked, nil
}

// ListImportedHistory returns one page of an import's imported merge requests,
// so a reader can render them beside first-party history while telling the two
// apart (SPEC-0011 AC20, which AC23's rendering depends on).
//
// Reading imported history is a read of the repository the import landed in, so
// it is scoped exactly as the other import reads are: the import must belong to
// the caller's tenant, and a cross-tenant read is indistinguishable from one for
// an import that does not exist (invariants 1-2, AC21). A revoked import returns
// nothing — the tombstone drops its records from every read (AC17).
func (s *ImportService) ListImportedHistory(ctx context.Context, req api.ListImportedHistoryRequest) (api.ImportedHistoryPage, error) {
	if !validContext(req.Context) || req.ImportID == "" {
		return api.ImportedHistoryPage{}, ErrImportDenied
	}
	imp, err := s.store.GetImport(ctx, req.ImportID)
	if err != nil || imp.TenantID != req.TenantID {
		return api.ImportedHistoryPage{}, ErrImportDenied
	}
	records, err := s.records.ListImport(ctx, req.ImportID)
	if err != nil {
		return api.ImportedHistoryPage{}, ErrImportDenied
	}
	// The page is keyed on the merge request ID rather than on an offset: an
	// import is append-only, so a key that names the last record read cannot
	// skip or repeat one the way an offset into a growing set can.
	slices.SortFunc(records, func(a, b api.ImportedMergeRequest) int {
		return cmp.Compare(a.MergeRequestID, b.MergeRequestID)
	})
	if req.PageToken != "" {
		records = after(records, req.PageToken)
	}

	size := req.PageSize
	if size <= 0 {
		size = api.DefaultImportedHistoryPageSize
	}
	size = min(size, api.MaxImportedHistoryPageSize)
	page := api.ImportedHistoryPage{}
	if len(records) > size {
		page.MergeRequests = records[:size]
		page.NextPageToken = page.MergeRequests[size-1].MergeRequestID
		return page, nil
	}
	page.MergeRequests = records
	return page, nil
}

// after returns the records ordered strictly beyond token. A token at or past
// the last record yields none: a reader handed a token this import has already
// exhausted sees the page end rather than reading the set a second time.
func after(records []api.ImportedMergeRequest, token string) []api.ImportedMergeRequest {
	index := sort.Search(len(records), func(i int) bool {
		return records[i].MergeRequestID > token
	})
	return records[index:]
}

func (s *ImportService) allowed(ctx context.Context, principal api.Context, action, resourceType, resourceID string, attributes map[string]string) bool {
	decision, err := s.pdp.Decide(ctx, policyapi.Request{
		TenantID: principal.TenantID,
		Subject: policyapi.Subject{
			ID: principal.ActorID, TenantID: principal.TenantID,
			Roles: append([]string(nil), principal.ActorRoles...),
		},
		Action:   action,
		Resource: policyapi.Resource{Type: resourceType, ID: resourceID},
		Context:  attributes,
	})
	return err == nil && decision.Allowed
}

// manifestDigest is a SHA-256 over the import's metadata, its per-type record
// counts, and a digest of the imported set itself — the reproducible handle an
// auditor can re-verify (SPEC-0011 AC16).
//
// The set digest is what makes the manifest detect tampering. Metadata and
// counts alone would verify that the same number of records exists, not that
// they still say what they said: editing a comment's body leaves both unchanged.
func manifestDigest(imp api.Import, setDigest string) string {
	h := sha256.New()
	for _, part := range []string{imp.ID, imp.TenantID, imp.RepositoryID, imp.SourceSystem, imp.SourceInstance, imp.SourceURL} {
		fmt.Fprintf(h, "%d:%s", len(part), part)
	}
	// Record counts are hashed in sorted key order so the digest is stable.
	keys := make([]string, 0, len(imp.RecordCounts))
	for k := range imp.RecordCounts {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		fmt.Fprintf(h, "%d:%s%d", len(k), k, imp.RecordCounts[k])
	}
	fmt.Fprintf(h, "%d:%s", len(setDigest), setDigest)
	return hex.EncodeToString(h.Sum(nil))
}

// recordsDigest is a SHA-256 over the imported set as stored: every field of
// every record, thread, comment and approval, in a canonical order.
//
// Length-prefixed, so no two different sets can hash the same by shifting a
// boundary — a comment body ending in a field separator must not be able to
// impersonate the next field. Order-independent by construction: records are
// sorted by ID before hashing, because two stores may return the same set in
// different orders and that is not tampering.
//
// The stored provenance payload digest is included as a field like any other. It
// is the source's own attestation of the fetched object, so altering it is
// itself a mutation the manifest must catch.
func recordsDigest(records []api.ImportedMergeRequest) string {
	sorted := slices.Clone(records)
	slices.SortFunc(sorted, func(a, b api.ImportedMergeRequest) int { return cmp.Compare(a.MergeRequestID, b.MergeRequestID) })

	h := sha256.New()
	write := func(parts ...string) {
		for _, part := range parts {
			fmt.Fprintf(h, "%d:%s", len(part), part)
		}
	}
	writeProvenance := func(p api.Provenance) {
		write(p.Class, p.ImportID, p.SourceSystem, p.SourceInstance, p.SourceRef, p.DeclaredActor, p.PayloadDigest)
		// A declared time is hashed as an instant, not as a formatted string, so
		// a store that round-trips it in another layout still verifies.
		fmt.Fprintf(h, "%d", p.DeclaredAt.UTC().UnixNano())
	}

	for _, record := range sorted {
		write(record.MergeRequestID, record.SourceRef, record.TargetRef, record.Title,
			record.Description, record.State, record.DeclaredCreator)
		writeProvenance(record.Provenance)

		threads := slices.Clone(record.Threads)
		slices.SortFunc(threads, func(a, b api.ImportedThread) int { return cmp.Compare(a.ThreadID, b.ThreadID) })
		for _, thread := range threads {
			write(thread.ThreadID, thread.MergeRequestID, thread.Path, thread.Anchor)
			writeProvenance(thread.Provenance)
			comments := slices.Clone(thread.Comments)
			slices.SortFunc(comments, func(a, b api.ImportedComment) int { return cmp.Compare(a.CommentID, b.CommentID) })
			for _, comment := range comments {
				write(comment.CommentID, comment.DeclaredActor, comment.Body)
				fmt.Fprintf(h, "%d", comment.DeclaredAt.UTC().UnixNano())
				writeProvenance(comment.Provenance)
			}
		}

		approvals := slices.Clone(record.Approvals)
		slices.SortFunc(approvals, func(a, b api.ImportedApproval) int { return cmp.Compare(a.ApprovalID, b.ApprovalID) })
		for _, approval := range approvals {
			write(approval.ApprovalID, approval.MergeRequestID, approval.DeclaredActor)
			fmt.Fprintf(h, "%d", approval.DeclaredAt.UTC().UnixNano())
			writeProvenance(approval.Provenance)
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

// VerifyImport recomputes the manifest digest over the imported set as it stands
// now and reports whether it still matches the digest the HistoryImported event
// recorded (SPEC-0011 AC16).
//
// It is a read: it never repairs a mismatch and never rewrites the digest. A
// failed verification is a finding, and the audit chain entry that recorded the
// original digest stays exactly as it was (invariant 5).
//
// A revoked import verifies as false: its records are tombstoned and dropped
// from reads, so there is nothing left to verify the digest against. That is not
// tampering, and the caller can tell the two apart from the import's state.
func (s *ImportService) VerifyImport(ctx context.Context, principal api.Context, importID string) (bool, error) {
	if !validContext(principal) || importID == "" {
		return false, ErrImportDenied
	}
	imp, err := s.store.GetImport(ctx, importID)
	if err != nil || imp.TenantID != principal.TenantID {
		return false, ErrImportDenied
	}
	if imp.ManifestDigest == "" {
		return false, ErrImportDenied
	}
	stored, err := s.records.ListImport(ctx, imp.ID)
	if err != nil {
		return false, ErrImportDenied
	}
	return manifestDigest(imp, recordsDigest(stored)) == imp.ManifestDigest, nil
}

// memoryImportStore is the dev/in-memory ImportStore. The create-or-get
// atomicity a tenant-scoped database unique constraint must also preserve is
// kept here by the mutex.
type memoryImportStore struct {
	mu      sync.Mutex
	imports map[string]api.Import
	idem    map[string]string
	revoked map[string]bool
}

// NewMemoryImportStore returns the dev/in-memory import store.
func NewMemoryImportStore() ImportStore {
	return &memoryImportStore{
		imports: map[string]api.Import{}, idem: map[string]string{}, revoked: map[string]bool{},
	}
}

func (m *memoryImportStore) CreateOrGetImport(_ context.Context, key string, candidate api.Import) (api.Import, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if id, ok := m.idem[key]; ok {
		return m.imports[id], false, nil
	}
	m.imports[candidate.ID], m.idem[key] = candidate, candidate.ID
	return candidate, true, nil
}

func (m *memoryImportStore) GetImport(_ context.Context, id string) (api.Import, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	imp, ok := m.imports[id]
	if !ok {
		return api.Import{}, errors.New("not found")
	}
	return imp, nil
}

func (m *memoryImportStore) ListImports(_ context.Context, tenantID, repositoryID string) ([]api.Import, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []api.Import
	for _, imp := range m.imports {
		if imp.TenantID == tenantID && imp.RepositoryID == repositoryID {
			out = append(out, imp)
		}
	}
	return out, nil
}

func (m *memoryImportStore) MarkImportPhase(_ context.Context, id string, gitPhase, historyPhase bool, state api.ImportState, digest, reason string, counts map[string]int64) (api.Import, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	imp := m.imports[id]
	imp.GitPhaseComplete = gitPhase
	imp.HistoryPhaseComplete = historyPhase
	imp.State = state
	imp.ManifestDigest = digest
	imp.FailureReason = reason
	imp.RecordCounts = counts
	imp.UpdatedAt = time.Now().UTC()
	m.imports[id] = imp
	return imp, nil
}

func (m *memoryImportStore) TombstoneImport(_ context.Context, id string) (api.Import, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	imp := m.imports[id]
	imp.State = api.ImportRevoked
	imp.UpdatedAt = time.Now().UTC()
	m.imports[id] = imp
	m.revoked[id] = true
	return imp, nil
}

// memoryRecordStore is the dev/in-memory imported-record store. It persists
// ATTESTED_IMPORT history within the Code Review context (ADR-0029 §2), with
// tombstone-on-revoke and no individual update or delete path (AC13).
type memoryRecordStore struct {
	mu      sync.Mutex
	records map[string][]api.ImportedMergeRequest
	// mappings are keyed by import, then by (declared_actor, source_instance):
	// the handle is only meaningful within its instance.
	mappings map[string]map[string]api.DeclaredActorMapping
	dead     map[string]bool
}

// NewMemoryRecordStore returns the dev/in-memory imported-record store.
func NewMemoryRecordStore() api.ImportedRecordStore {
	return &memoryRecordStore{
		records:  map[string][]api.ImportedMergeRequest{},
		mappings: map[string]map[string]api.DeclaredActorMapping{},
		dead:     map[string]bool{},
	}
}

func (m *memoryRecordStore) PutImport(_ context.Context, importID string, records []api.ImportedMergeRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.dead[importID] {
		return fmt.Errorf("codereview: cannot write to a revoked import %s", importID)
	}
	m.records[importID] = records
	return nil
}

func (m *memoryRecordStore) ListImport(_ context.Context, importID string) ([]api.ImportedMergeRequest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.dead[importID] {
		return nil, nil
	}
	return append([]api.ImportedMergeRequest(nil), m.records[importID]...), nil
}

func (m *memoryRecordStore) Tombstone(_ context.Context, importID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dead[importID] = true
	delete(m.records, importID)
	// The mappings go with the records they describe (SPEC-0011 AC24). They are
	// dropped from reads, not from the audit trail: the DeclaredActorMapped events
	// that recorded who asserted them stay in the chain (invariant 5).
	delete(m.mappings, importID)
	return nil
}

// mappingKey identifies a handle within its source instance. The instance is part
// of the key, not decoration: the same handle on two source instances is two
// people, and a key that ignored it would let one mapping claim both.
func mappingKey(declaredActor, sourceInstance string) string {
	return fmt.Sprintf("%d:%s%d:%s", len(sourceInstance), sourceInstance, len(declaredActor), declaredActor)
}

func (m *memoryRecordStore) PutMapping(_ context.Context, mapping api.DeclaredActorMapping) (api.DeclaredActorMapping, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.dead[mapping.ImportID] {
		return api.DeclaredActorMapping{}, fmt.Errorf("codereview: cannot write to a revoked import %s", mapping.ImportID)
	}
	key := mappingKey(mapping.DeclaredActor, mapping.SourceInstance)
	if existing, ok := m.mappings[mapping.ImportID][key]; ok {
		// Re-asserting the same identity is idempotent, so a retried command does
		// not produce a second claim. Asserting a *different* identity is refused:
		// silently replacing one admin's claim with another's would erase who
		// believed what, which is the whole reason this record names an asserter.
		if existing.ActorID != mapping.ActorID {
			return api.DeclaredActorMapping{}, api.ErrMappingConflict
		}
		return existing, nil
	}
	if m.mappings[mapping.ImportID] == nil {
		m.mappings[mapping.ImportID] = map[string]api.DeclaredActorMapping{}
	}
	m.mappings[mapping.ImportID][key] = mapping
	return mapping, nil
}

func (m *memoryRecordStore) ListMappings(_ context.Context, importID string) ([]api.DeclaredActorMapping, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.dead[importID] {
		return nil, nil
	}
	out := make([]api.DeclaredActorMapping, 0, len(m.mappings[importID]))
	for _, mapping := range m.mappings[importID] {
		out = append(out, mapping)
	}
	slices.SortFunc(out, func(a, b api.DeclaredActorMapping) int { return cmp.Compare(a.MappingID, b.MappingID) })
	return out, nil
}
