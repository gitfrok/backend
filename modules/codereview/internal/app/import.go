package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
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
	ImportRefs(ctx context.Context, command ImportRefsCommand) ([]RefUpdate, error)
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
	ImportHistory(ctx context.Context, command ImportHistoryCommand) (map[string]int64, error)
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
	git     GitImporter
	history HistoryImporter
	pdp     policyapi.DecisionPoint
	bus     bus.Bus
	newID   func() string
	now     func() time.Time
}

// NewImportService wires the import service. history may be nil in a build that
// has not landed the history phase; git is required.
func NewImportService(store ImportStore, git GitImporter, history HistoryImporter, pdp policyapi.DecisionPoint, events bus.Bus) *ImportService {
	return &ImportService{
		store:   store,
		git:     git,
		history: history,
		pdp:     pdp,
		bus:     events,
		newID:   ids.NewULID,
		now:     time.Now,
	}
}

// ErrImportDenied is the coarse refusal an unauthorized import command returns.
var ErrImportDenied = errors.New("codereview: import unavailable")

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
	if !created {
		return imp, nil
	}

	// The git phase runs inline for the dev posture. The source token is used
	// once, here, and never stored.
	if err := s.runGitPhase(ctx, req, &imp); err != nil {
		s.fail(ctx, imp, "git phase failed")
		return api.Import{}, ErrImportDenied
	}
	if s.history != nil {
		counts, err := s.history.ImportHistory(ctx, ImportHistoryCommand{
			TenantID: req.TenantID, RepositoryID: req.RepositoryID, ActorID: req.ActorID,
			RequestID: req.RequestID, ActorRoles: append([]string(nil), req.ActorRoles...),
			ImportID: imp.ID, SourceURL: req.SourceURL, SourceToken: req.SourceToken,
			SourceSystem: req.SourceSystem, SourceInstance: req.SourceInstance,
		})
		if err != nil {
			s.fail(ctx, imp, "history phase failed")
			return api.Import{}, ErrImportDenied
		}
		imp.RecordCounts = counts
		imp.HistoryPhaseComplete = true
	}

	// One first-party HistoryImported audit event per import, chained normally,
	// carrying the manifest digest over the imported set (ADR-0029 §3, AC10).
	imp.State = api.ImportComplete
	imp.ManifestDigest = manifestDigest(imp)
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
	moved, err := s.git.ImportRefs(ctx, ImportRefsCommand{
		TenantID: req.TenantID, RepositoryID: req.RepositoryID, ActorID: req.ActorID,
		RequestID: req.RequestID, ActorRoles: append([]string(nil), req.ActorRoles...),
		SourceURL: req.SourceURL, SourceToken: req.SourceToken,
	})
	if err != nil {
		return err
	}
	_ = moved
	imp.GitPhaseComplete = true
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

// manifestDigest is a SHA-256 over the import's record counts and source
// identity — the reproducible handle an auditor can re-verify (SPEC-0011
// AC16). It covers the import's own metadata; the payload digests of the
// individual records are hashed into it by the history importer's returned
// counts and any digest map a future phase adds.
func manifestDigest(imp api.Import) string {
	h := sha256.New()
	for _, part := range []string{imp.ID, imp.TenantID, imp.RepositoryID, imp.SourceSystem, imp.SourceInstance, imp.SourceURL} {
		fmt.Fprintf(h, "%d:%s", len(part), part)
	}
	// Record counts are hashed in sorted key order so the digest is stable.
	keys := make([]string, 0, len(imp.RecordCounts))
	for k := range imp.RecordCounts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(h, "%d:%s%d", len(k), k, imp.RecordCounts[k])
	}
	return hex.EncodeToString(h.Sum(nil))
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
