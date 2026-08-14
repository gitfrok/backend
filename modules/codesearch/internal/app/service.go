package app

import (
	"cmp"
	"context"
	"crypto/rand"
	"regexp"
	"slices"
	"strconv"
	"sync"
	"time"

	csapi "github.com/gitfrok/backend/modules/codesearch/api"
	"github.com/gitfrok/backend/modules/codesearch/internal/engine"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
	repoapi "github.com/gitfrok/backend/modules/repository/api"
	"github.com/gitfrok/backend/platform/bus"
	"github.com/gitfrok/backend/platform/ids"
)

// The reviewed action vocabulary this context asks the PDP about (SPEC-0035, governance
// policies/gitsaas/authz): search.query on the tenant, search.read per repository at query time,
// search.index.status.read per repository at status time. Scope, freshness and lag are facts
// produced here and by Identity & Access; none is a caller claim.
const (
	actionSearchQuery      = "search.query"
	actionSearchRead       = "search.read"
	actionSearchStatusRead = "search.index.status.read"

	resourceTenant     = "tenant"
	resourceRepository = "repository"
)

// Config carries the stated bounds SPEC-0034 and SPEC-0035 require. Every value is a server
// fact; no request can override one.
type Config struct {
	// FreshnessBound is the stated index-freshness bound. A measured lag above it is reported
	// as IndexLagged, not a silent delay (SPEC-0034 AC4). The spec requires a stated, measured
	// bound rather than a particular number; this default is the Phase-2 statement.
	FreshnessBound time.Duration
	// CursorLifetime bounds one pagination token (SPEC-0035 AC5 open question).
	CursorLifetime time.Duration
	// DefaultPageLimit is the page size a zero result_limit asks for; MaxPageLimit clamps the
	// rest. No query streams unbounded memory (SPEC-0035 non-functional).
	DefaultPageLimit int32
	MaxPageLimit     int32
	// MaxContextLines clamps the context around each match.
	MaxContextLines int32
	// MaxFilesPerRepo and MaxFileBytes bound what one indexing pass absorbs, so one enormous
	// repository cannot monopolize the index or the fair-use footprint (PRD §6).
	MaxFilesPerRepo int
	MaxFileBytes    int64
	// BackfillPace is the interval a backfill yields between repositories, so backfill does not
	// starve interactive indexing.
	BackfillPace time.Duration
	// JobTimeout bounds one indexing job. The single worker must never sit on one hung content
	// fetch; a job that exceeds the bound is abandoned (and its lag reported) so the remaining
	// repositories keep indexing (L15).
	JobTimeout time.Duration
}

// DefaultConfig is the Phase-2 statement of the bounds.
func DefaultConfig() Config {
	return Config{
		FreshnessBound:   30 * time.Second,
		CursorLifetime:   5 * time.Minute,
		DefaultPageLimit: 50,
		MaxPageLimit:     200,
		MaxContextLines:  10,
		MaxFilesPerRepo:  20000,
		MaxFileBytes:     1 << 20,
		JobTimeout:       2 * time.Minute,
	}
}

type repoKey struct {
	tenant string
	repo   string
}

// freshness is the measured indexing state of one repository (SPEC-0034 AC4).
type freshness struct {
	AdmittedRevision string
	AdmittedAt       time.Time
	IndexedRevision  string
	IndexedAt        time.Time
}

type indexJob struct {
	tenant   string
	repo     string
	revision string
}

// Service is the Code Search context: the repository projection, the per-repository shards, the
// incremental indexer, and the permission-filtered query and status paths. It reaches the
// Repository context the only two ways a module may — the bus and the api/ port — and the PDP
// through its one permitted port (invariant 2).
type Service struct {
	proj   *Projection
	repos  repoapi.Reader
	pdp    policyapi.DecisionPoint
	events bus.Bus
	cfg    Config

	cursorKey [32]byte

	mu          sync.RWMutex
	shards      map[repoKey]*engine.Shard
	fresh       map[repoKey]freshness
	lagReported map[string]struct{} // one IndexLagged per repo per admitted revision
	content     csapi.ContentSource

	jobs    chan indexJob
	pending sync.WaitGroup
}

// NewService assembles the context and starts its indexer. content may be nil: the context then
// tracks admission and freshness but absorbs no revisions until AttachContentSource wires the
// route to repository content.
func NewService(repos repoapi.Reader, pdp policyapi.DecisionPoint, events bus.Bus, content csapi.ContentSource, cfg Config) *Service {
	if pdp == nil {
		panic("codesearch: no PDP — every result path needs a decision (invariant 2)")
	}
	d := DefaultConfig()
	if cfg.FreshnessBound <= 0 {
		cfg.FreshnessBound = d.FreshnessBound
	}
	if cfg.CursorLifetime <= 0 {
		cfg.CursorLifetime = d.CursorLifetime
	}
	if cfg.DefaultPageLimit <= 0 {
		cfg.DefaultPageLimit = d.DefaultPageLimit
	}
	if cfg.MaxPageLimit <= 0 {
		cfg.MaxPageLimit = d.MaxPageLimit
	}
	if cfg.MaxContextLines <= 0 {
		cfg.MaxContextLines = d.MaxContextLines
	}
	if cfg.MaxFilesPerRepo <= 0 {
		cfg.MaxFilesPerRepo = d.MaxFilesPerRepo
	}
	if cfg.MaxFileBytes <= 0 {
		cfg.MaxFileBytes = d.MaxFileBytes
	}
	if cfg.JobTimeout <= 0 {
		cfg.JobTimeout = d.JobTimeout
	}
	s := &Service{
		proj:        NewProjection(repos),
		repos:       repos,
		pdp:         pdp,
		events:      events,
		cfg:         cfg,
		shards:      make(map[repoKey]*engine.Shard),
		fresh:       make(map[repoKey]freshness),
		lagReported: make(map[string]struct{}),
		content:     content,
		jobs:        make(chan indexJob, 256),
	}
	if _, err := rand.Read(s.cursorKey[:]); err != nil {
		panic("codesearch: cursor key generation failed: " + err.Error())
	}
	go s.worker()
	return s
}

// Register subscribes the context to the Repository events that drive indexing. Wiring happens
// in cmd/, which is the only place that knows both modules exist.
func (s *Service) Register(b bus.Bus) {
	bus.SubscribeTyped(b, s.onRepositoryCreated)
	bus.SubscribeTyped(b, s.onRefUpdated)
}

func (s *Service) onRepositoryCreated(ctx context.Context, e repoapi.RepositoryCreated) error {
	return s.proj.HandleRepositoryCreated(ctx, e)
}

// onRefUpdated admits the new revision and enqueues its indexing. The admission — revision and
// when it happened — is recorded in the freshness table here, because the measured lag is
// time-since-admission and admission is this event (SPEC-0034 AC4). Indexing runs off the
// worker, not inside the publisher's Publish: a slow fetch must not block the write that
// announced it.
func (s *Service) onRefUpdated(ctx context.Context, e repoapi.RefUpdated) error {
	if err := s.proj.HandleRefUpdated(ctx, e); err != nil {
		return err
	}
	if e.NewSha == "" {
		return nil
	}
	at := e.OccurredAt
	if at.IsZero() {
		at = time.Now().UTC()
	}
	s.mu.Lock()
	f := s.fresh[repoKey{tenant: e.TenantID, repo: e.RepoID}]
	f.AdmittedRevision = e.NewSha
	f.AdmittedAt = at.UTC()
	s.fresh[repoKey{tenant: e.TenantID, repo: e.RepoID}] = f
	s.mu.Unlock()
	s.enqueue(indexJob{tenant: e.TenantID, repo: e.RepoID, revision: e.NewSha})
	return nil
}

func (s *Service) enqueue(job indexJob) {
	s.pending.Add(1)
	select {
	case s.jobs <- job:
	default:
		// The queue is full: one more push than the plane can absorb is an IndexLagged
		// condition, not a dropped write. Drop the job and let the measured lag report it.
		s.pending.Done()
		s.reportLagIfBoundExceeded(repoKey{tenant: job.tenant, repo: job.repo})
	}
}

// AttachContentSource wires the route to repository content. See api.Service.
func (s *Service) AttachContentSource(cs csapi.ContentSource) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.content = cs
}

func (s *Service) contentSource() csapi.ContentSource {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.content
}

func (s *Service) worker() {
	for job := range s.jobs {
		s.indexOne(job)
	}
}

// indexOne absorbs one revision for one repository: fetch through the Repository contract only,
// build the shard whole, then swap it atomically (SPEC-0034 AC5). Other repositories are never
// touched, and the old shard keeps serving until the new one is complete — a partially rebuilt
// repository never serves a half-built shard as authorized.
func (s *Service) indexOne(job indexJob) {
	defer s.pending.Done()
	key := repoKey{tenant: job.tenant, repo: job.repo}

	cs := s.contentSource()
	if cs == nil {
		// No route to content yet: freshness tracking still reports the lag honestly.
		return
	}

	// Detached context, deliberately: indexOne runs from the absorb worker after the admitting
	// request has returned, so there is no caller context to inherit. The work must outlive any
	// single request; cancellation belongs to the plane, not to a query. The per-job timeout is
	// the plane's own bound, not a caller's: one hung content fetch must not stall the single
	// worker and every repository queued behind it. A timed-out job reports its lag and re-enters
	// on the next admission or backfill (L15).
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.JobTimeout)
	defer cancel()
	entries, err := cs.ListFiles(ctx, job.tenant, job.repo, job.revision)
	if err != nil {
		s.reportLagIfBoundExceeded(key)
		return
	}

	docs := make([]engine.File, 0, len(entries))
	for _, fe := range entries {
		if len(docs) >= s.cfg.MaxFilesPerRepo {
			break
		}
		if fe.SizeBytes > s.cfg.MaxFileBytes {
			continue
		}
		content, err := cs.ReadFile(ctx, job.tenant, job.repo, job.revision, fe.Path)
		if err != nil {
			// One unreadable file does not fail the revision; the rest still indexes.
			continue
		}
		docs = append(docs, engine.File{Path: fe.Path, Content: content})
	}

	shard := engine.Build(job.revision, docs)
	now := time.Now().UTC()
	s.mu.Lock()
	s.shards[key] = shard
	f := s.fresh[key]
	f.IndexedRevision = job.revision
	f.IndexedAt = now
	s.fresh[key] = f
	s.mu.Unlock()

	// Publishing is best-effort: the index absorbed the revision regardless of whether a
	// consumer is listening. Events carry opaque identifiers and revision only (SPEC-0035).
	_ = s.events.Publish(ctx, csapi.RepositoryIndexed{
		EventID:      ids.NewULID(),
		TenantID:     job.tenant,
		RepositoryID: job.repo,
		Revision:     job.revision,
		OccurredAt:   now,
	})

	// A backlog can leave the measured lag above the bound even after a successful absorb;
	// that is still a reported condition.
	s.reportLagIfBoundExceeded(key)
}

// measureLag is the freshness measurement (SPEC-0034 AC4): when the index is caught up, the time
// the absorb took; while it is behind, the time since admission.
func (s *Service) measureLag(key repoKey, now time.Time) (freshness, time.Duration) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	f := s.fresh[key]
	switch {
	case f.AdmittedRevision == "":
		return f, 0
	case f.IndexedRevision == f.AdmittedRevision:
		return f, f.IndexedAt.Sub(f.AdmittedAt)
	default:
		return f, now.Sub(f.AdmittedAt)
	}
}

// reportLagIfBoundExceeded publishes IndexLagged when the measured lag exceeds the stated bound,
// once per repository per admitted revision: exceeding the bound is a reported condition, not a
// silent delay, and not an event storm either (SPEC-0034 non-functional).
func (s *Service) reportLagIfBoundExceeded(key repoKey) {
	if s.contentSource() == nil {
		// A plane with no route to content cannot index; lag there is a wiring state, not an
		// index condition.
		return
	}
	now := time.Now().UTC()
	f, lag := s.measureLag(key, now)
	if f.AdmittedRevision == "" || lag <= s.cfg.FreshnessBound {
		return
	}
	dedupe := key.tenant + "/" + key.repo + "/" + f.AdmittedRevision
	s.mu.Lock()
	if _, seen := s.lagReported[dedupe]; seen {
		s.mu.Unlock()
		return
	}
	s.lagReported[dedupe] = struct{}{}
	s.mu.Unlock()

	// Detached context, deliberately: lag reporting fires from measurement paths that hold no
	// caller context (query-path callers must not pay for an out-of-band publish); the report
	// must not be canceled by the request whose lag it describes (SPEC-0036: comment-only
	// clarification, no behavior change).
	_ = s.events.Publish(context.Background(), csapi.IndexLagged{
		EventID:             ids.NewULID(),
		TenantID:            key.tenant,
		RepositoryID:        key.repo,
		LastIndexedRevision: f.IndexedRevision,
		Lag:                 lag,
		OccurredAt:          now,
	})
}

// Backfill enqueues indexing for every admitted revision the index has not absorbed, paced so it
// yields to interactive indexing. See api.Service.
func (s *Service) Backfill(ctx context.Context) error {
	for _, admitted := range s.proj.AllAdmitted() {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		key := repoKey{tenant: admitted.TenantID, repo: admitted.RepoID}
		s.mu.RLock()
		indexed := s.fresh[key].IndexedRevision
		s.mu.RUnlock()
		if indexed == admitted.Revision {
			continue
		}
		// The admission may predate this process: take it from the projection so the measured
		// lag stays honest across restarts (SPEC-0034 AC4).
		if sha, at, ok := s.proj.AdmittedHead(admitted.TenantID, admitted.RepoID); ok {
			s.mu.Lock()
			f := s.fresh[key]
			if f.AdmittedRevision == "" {
				f.AdmittedRevision = sha
				f.AdmittedAt = at.UTC()
				s.fresh[key] = f
			}
			s.mu.Unlock()
		}
		if s.cfg.BackfillPace > 0 {
			select {
			case <-time.After(s.cfg.BackfillPace):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		s.enqueue(indexJob{tenant: admitted.TenantID, repo: admitted.RepoID, revision: admitted.Revision})
	}
	return nil
}

// Drain blocks until every enqueued indexing job has completed or ctx is done. See api.Service.
func (s *Service) Drain(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		s.pending.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Search runs one tenant-scoped, permission-filtered query. See api.Service.
func (s *Service) Search(ctx context.Context, q csapi.Query) (csapi.Page, error) {
	var zero csapi.Page
	re, err := s.validate(q)
	if err != nil {
		return zero, err
	}

	// Derive the searchable repository set from the projection and the PDP at query time — no
	// cross-query permission cache, so a revocation binds on this query (SPEC-0034 AC6).
	scope := s.deriveScope(ctx, q)

	// One tenant-level search.query decision, carrying the mode and the derived scope as
	// server-derived context (SPEC-0035 vocabulary).
	allowed, err := s.decide(ctx, q, actionSearchQuery, resourceTenant, q.TenantID, map[string]string{
		"query_mode":       strconv.Itoa(int(q.Mode)),
		"repository_scope": strconv.Itoa(len(scope)),
	})
	if err != nil || !allowed {
		return zero, csapi.ErrDenied
	}

	// A cursor is honoured only if it verifies, is bound to this tenant, this query, and the
	// principal it was issued to, and is not expired; anything else yields no content
	// (SPEC-0035 AC1, L17).
	offset := 0
	if q.PageToken != "" {
		claims, ok := s.decodeCursor(q.PageToken)
		if !ok || claims.Tenant != q.TenantID || claims.Actor != q.ActorID ||
			claims.Text != q.Text || claims.Mode != int(q.Mode) ||
			time.Now().UTC().After(claims.Exp) {
			return zero, nil
		}
		offset = claims.Offset
	}

	limit := s.clampPageLimit(q.ResultLimit)
	ctxLines := s.clampContextLines(q.ContextLineLimit)
	need := offset + int(limit) + 1

	matches := s.collect(scope, q, re, ctxLines, need)
	if len(matches) <= offset {
		// The zero Page is the one shape a no-match query and an unauthorized-only query both
		// return (SPEC-0034 AC3, SPEC-0035 AC4).
		return zero, nil
	}
	page := matches[offset:]
	var next string
	if len(page) > int(limit) {
		page = page[:limit]
		next = s.encodeCursor(q.TenantID, q.ActorID, q.Text, int(q.Mode), offset+int(limit),
			time.Now().UTC().Add(s.cfg.CursorLifetime))
	}
	return csapi.Page{Matches: page, NextPageToken: next}, nil
}

// deriveScope asks the PDP search.read per known repository — one decision each, at query time
// (SPEC-0035 AC2). A PDP error is a refusal for that repository: deny-by-default (ADR-0006).
func (s *Service) deriveScope(ctx context.Context, q csapi.Query) []string {
	repos := s.proj.ReposOfTenant(q.TenantID)
	scope := make([]string, 0, len(repos))
	for _, repoID := range repos {
		allowed, err := s.decide(ctx, q, actionSearchRead, resourceRepository, repoID, nil)
		if err == nil && allowed {
			scope = append(scope, repoID)
		}
	}
	return scope
}

// collect runs the engine over the authorized shards only and returns at most need matches in
// deterministic order. Counts and the "more" indicator therefore exist only over authorized
// matches — by construction, not by a late filter (SPEC-0035 AC3).
func (s *Service) collect(scope []string, q csapi.Query, re *regexp.Regexp, ctxLines, need int) []csapi.Match {
	var out []csapi.Match
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, repoID := range scope {
		key := repoKey{tenant: q.TenantID, repo: repoID}
		shard := s.shards[key]
		if shard == nil {
			continue
		}
		remaining := need - len(out)
		if remaining <= 0 {
			break
		}
		var hits []engine.Hit
		switch q.Mode {
		case csapi.QueryModeSubstring:
			hits = shard.SearchSubstring(q.Text, remaining, ctxLines)
		case csapi.QueryModeRegex:
			hits = shard.SearchRegex(re, remaining, ctxLines)
		case csapi.QueryModeSymbol:
			hits = shard.SearchSymbol(q.Text, remaining, ctxLines)
		}
		for _, h := range hits {
			out = append(out, csapi.Match{
				RepositoryID:   repoID,
				Revision:       shard.Revision(),
				Path:           h.Path,
				LineStart:      int64(h.LineStart),
				LineEnd:        int64(h.LineEnd),
				MatchedContent: h.Content,
			})
		}
	}
	slices.SortStableFunc(out, func(a, b csapi.Match) int {
		if c := cmp.Compare(a.RepositoryID, b.RepositoryID); c != 0 {
			return c
		}
		if c := cmp.Compare(a.Path, b.Path); c != 0 {
			return c
		}
		return cmp.Compare(a.LineStart, b.LineStart)
	})
	return out
}

// GetIndexStatus reports freshness for repositories the caller may read and nothing else — not
// even existence (SPEC-0035 AC6).
func (s *Service) GetIndexStatus(ctx context.Context, q csapi.Query) ([]csapi.IndexStatusEntry, error) {
	if q.TenantID == "" || q.ActorID == "" || q.RequestID == "" {
		return nil, csapi.ErrMalformed
	}
	now := time.Now().UTC()
	var entries []csapi.IndexStatusEntry
	for _, repoID := range s.proj.ReposOfTenant(q.TenantID) {
		allowed, err := s.decide(ctx, q, actionSearchStatusRead, resourceRepository, repoID, nil)
		if err != nil || !allowed {
			continue
		}
		key := repoKey{tenant: q.TenantID, repo: repoID}
		f, lag := s.measureLag(key, now)
		if f.IndexedRevision == "" {
			// Nothing absorbed yet: nothing to report. An empty entry would leak existence
			// without freshness.
			continue
		}
		entries = append(entries, csapi.IndexStatusEntry{
			RepositoryID:        repoID,
			LastIndexedRevision: f.IndexedRevision,
			IndexedAt:           f.IndexedAt,
			FreshnessLag:        lag,
		})
		if lag > s.cfg.FreshnessBound {
			s.reportLagIfBoundExceeded(key)
		}
	}
	slices.SortFunc(entries, func(a, b csapi.IndexStatusEntry) int { return cmp.Compare(a.RepositoryID, b.RepositoryID) })
	return entries, nil
}

// TenantIndexSize measures the tenant's index footprint in bytes (SPEC-0034 AC7). It is an
// in-process measurement only: the wire contract has no field capable of carrying it, and this
// method sits outside the permission-filtered query path because no caller request reaches it —
// fair-use metering is a later spec.
func (s *Service) TenantIndexSize(_ context.Context, tenantID string) (int64, error) {
	if tenantID == "" {
		return 0, csapi.ErrMalformed
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	var total int64
	for key, shard := range s.shards {
		if key.tenant == tenantID && shard != nil {
			total += shard.SizeBytes()
		}
	}
	return total, nil
}

// Lookup keeps the Phase-1 projection read. See api.Index.
func (s *Service) Lookup(ctx context.Context, tenantID, repoID string) (csapi.IndexedRepository, error) {
	return s.proj.Lookup(ctx, tenantID, repoID)
}

// validate bounds the request at the contract's edges; every refusal is the same coarse error
// (SPEC-0035 non-functional). A valid regex query returns its compiled pattern.
func (s *Service) validate(q csapi.Query) (*regexp.Regexp, error) {
	if q.TenantID == "" || q.ActorID == "" || q.RequestID == "" {
		return nil, csapi.ErrMalformed
	}
	if q.Text == "" || len(q.Text) > csapi.MaxQueryTextLength {
		return nil, csapi.ErrMalformed
	}
	switch q.Mode {
	case csapi.QueryModeSubstring, csapi.QueryModeSymbol:
		return nil, nil
	case csapi.QueryModeRegex:
		if len(q.Text) > csapi.MaxRegexPatternLength {
			return nil, csapi.ErrMalformed
		}
		re, err := regexp.Compile(q.Text)
		if err != nil {
			return nil, csapi.ErrMalformed
		}
		return re, nil
	default:
		return nil, csapi.ErrMalformed
	}
}

func (s *Service) clampPageLimit(limit int32) int32 {
	if limit <= 0 {
		return s.cfg.DefaultPageLimit
	}
	if limit > s.cfg.MaxPageLimit {
		return s.cfg.MaxPageLimit
	}
	return limit
}

func (s *Service) clampContextLines(limit int32) int {
	if limit <= 0 {
		return 0
	}
	if limit > s.cfg.MaxContextLines {
		return int(s.cfg.MaxContextLines)
	}
	return int(limit)
}

// decide asks the PDP one question with the caller's verified context. Both an error and a
// non-allowed decision are refusals; there is no third outcome (ADR-0006).
func (s *Service) decide(ctx context.Context, q csapi.Query, action, resourceType, resourceID string, extra map[string]string) (bool, error) {
	d, err := s.pdp.Decide(ctx, policyapi.Request{
		TenantID: q.TenantID,
		Subject: policyapi.Subject{
			ID:       q.ActorID,
			TenantID: q.TenantID,
			Roles:    q.ActorRoles,
		},
		Action:   action,
		Resource: policyapi.Resource{Type: resourceType, ID: resourceID},
		Context:  extra,
	})
	if err != nil {
		return false, err
	}
	return d.Allowed, nil
}

var _ csapi.Service = (*Service)(nil)
