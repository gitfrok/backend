package app

import (
	"cmp"
	"context"
	"errors"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/gitfrok/backend/modules/security/api"
	"github.com/gitfrok/backend/platform/ids"
)

// scanState is the one-way state machine of a scan record (SPEC-0025): a
// scan is INGESTING while chunks accumulate and becomes COMPLETE when its
// final chunk lands. Nothing of the scan is readable before COMPLETE, and a
// COMPLETE scan never re-opens.
type scanState string

const (
	scanIngesting scanState = "INGESTING"
	scanComplete  scanState = "COMPLETE"
)

// chunkRecord is the recorded outcome of one accepted chunk, kept so a
// redelivery of the same (tenant, scan, chunk, request ID) replays instead
// of re-applying (SPEC-0025 AC1).
type chunkRecord struct {
	findingsRecorded int64
	completed        bool
	opened           []api.Finding
	resolved         []api.Finding
}

// scanRecord is one scan's accumulated ingest state.
type scanRecord struct {
	state      scanState
	params     IngestParams
	chunks     int
	chunkCount int
	// prepared accumulates the scan's findings as chunks arrive, keyed by
	// identity: a tool reports a given identity once per scan, so the map is
	// the scan's reported set. Nothing reads it before COMPLETE.
	prepared map[string]PreparedFinding
	// outcomes keys recorded chunk outcomes by chunk index and request ID,
	// the idempotency key of SPEC-0025 AC1.
	outcomes map[int]map[string]chunkRecord
}

// findingRecord is one stored finding.
type findingRecord struct {
	finding api.Finding
	// identity is the SPEC-0024 identity the record is stored under.
	identity string
	// firstSeenAt is when the finding was first sighted; the age filters
	// (SPEC-0026 AC2) measure whole days from it. The Postgres adapter
	// measures from the row's created_at, which the upsert never touches.
	firstSeenAt time.Time
}

// MemoryStore is the in-memory Store for dev and tests. It implements the
// same contract the Postgres adapter does: serializable per-scan ingest
// (a single mutex stands in for the transaction), chunk visibility only
// after the final chunk, idempotency per request ID, the
// resolved-not-deleted lifecycle (SPEC-0024 AC9, SPEC-0025), and the
// append-only, version-guarded triage history (SPEC-0026 AC5).
type MemoryStore struct {
	mu    sync.Mutex
	scans map[string]*scanRecord
	finds map[string]map[string]*findingRecord // tenant -> finding ID -> record
	// byIdentity indexes findings by their SPEC-0024 identity so a re-report
	// lands on the same record: the dedup the Postgres adapter gets from
	// UNIQUE (tenant_id, repository_id, identity).
	byIdentity map[string]map[string]string // tenant -> identity -> finding ID
	// triages is the append-only triage history per finding: tenant ->
	// finding ID -> records in ascending version order. Superseding a
	// decision appends; nothing here is ever mutated (SPEC-0026 AC5).
	triages map[string]map[string][]api.TriageRecord
	// triageReplays keys recorded triage outcomes by (tenant, finding,
	// request ID): the idempotency of SPEC-0027 AC1.
	triageReplays map[string]map[string]map[string]api.TriageRecord
	// ownership is the repository-level owning-team attribution projection
	// (SPEC-0026): tenant -> repository ID -> team.
	ownership map[string]map[string]string
	nextID    func() string
}

// NewMemoryStore builds the in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		scans:         map[string]*scanRecord{},
		finds:         map[string]map[string]*findingRecord{},
		byIdentity:    map[string]map[string]string{},
		triages:       map[string]map[string][]api.TriageRecord{},
		triageReplays: map[string]map[string]map[string]api.TriageRecord{},
		ownership:     map[string]map[string]string{},
		nextID:        ids.NewULID,
	}
}

var (
	errChunkOutOfOrder = errors.New("security: chunk out of order")
	errScanClosed      = errors.New("security: scan already complete")
)

// IngestChunk applies one chunk, serializably per scan. A redelivered chunk
// replays its recorded outcome; a chunk that skips ahead or arrives for a
// completed scan is refused whole.
func (m *MemoryStore) IngestChunk(_ context.Context, p IngestParams) (IngestOutcome, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	rec, ok := m.scans[p.ScanID]
	if !ok {
		rec = &scanRecord{
			state:    scanIngesting,
			params:   p,
			prepared: map[string]PreparedFinding{},
			outcomes: map[int]map[string]chunkRecord{},
		}
		m.scans[p.ScanID] = rec
	}

	// Idempotency first: the same (scan, chunk, request ID) replays the
	// recorded outcome, whatever the scan's current state (SPEC-0025 AC1).
	if byReq, ok := rec.outcomes[p.ChunkIndex]; ok {
		if cr, ok := byReq[p.RequestID]; ok {
			return IngestOutcome{
				ScanID:           p.ScanID,
				FindingsRecorded: cr.findingsRecorded,
				Completed:        cr.completed,
				Replayed:         true,
				Opened:           cr.opened,
				Resolved:         cr.resolved,
			}, nil
		}
	}

	if rec.state == scanComplete {
		// A new request ID against a completed scan is a contract
		// violation, not a replay.
		return IngestOutcome{}, errScanClosed
	}
	if p.ChunkIndex != rec.chunks {
		return IngestOutcome{}, errChunkOutOfOrder
	}

	// Accumulate the chunk; nothing becomes visible yet.
	rec.chunkCount += len(p.Findings)
	rec.chunks++
	for _, pf := range p.Findings {
		rec.prepared[pf.Identity] = pf
	}

	out := IngestOutcome{ScanID: p.ScanID, FindingsRecorded: int64(len(p.Findings))}
	if !p.FinalChunk {
		rec.outcomes[p.ChunkIndex] = map[string]chunkRecord{
			p.RequestID: {findingsRecorded: out.FindingsRecorded},
		}
		return out, nil
	}

	// Final chunk: apply the lifecycle consequences and make the scan
	// visible. Everything below happens inside the same critical section,
	// which is the in-memory stand-in for the serializable transaction.
	rec.state = scanComplete
	out.Completed = true
	out.Opened, out.Resolved = m.applyLifecycle(rec, p)

	rec.outcomes[p.ChunkIndex] = map[string]chunkRecord{
		p.RequestID: {
			findingsRecorded: out.FindingsRecorded,
			completed:        true,
			opened:           out.Opened,
			resolved:         out.Resolved,
		},
	}
	return out, nil
}

// applyLifecycle runs the set comparison of SPEC-0024 AC9 / SPEC-0025 for
// one completed scan: identities the scan reports that no scan has reported
// before are opened; open findings of the same reporting tool that the scan
// no longer reports are resolved — never deleted.
func (m *MemoryStore) applyLifecycle(rec *scanRecord, final IngestParams) ([]api.Finding, []api.Finding) {
	tenant := m.finds[final.TenantID]
	if tenant == nil {
		tenant = map[string]*findingRecord{}
		m.finds[final.TenantID] = tenant
	}
	identityIndex := m.byIdentity[final.TenantID]
	if identityIndex == nil {
		identityIndex = map[string]string{}
		m.byIdentity[final.TenantID] = identityIndex
	}

	// The reported set is the completed scan's accumulated identities.
	reported := make([]string, 0, len(rec.prepared))
	for id := range rec.prepared {
		reported = append(reported, id)
	}
	slices.Sort(reported)

	opened := []api.Finding{}
	for _, id := range reported {
		pf := rec.prepared[id]
		if findingID, ok := identityIndex[id]; ok {
			fr := tenant[findingID]
			// Known finding: still reported, so it is open again (a resolved
			// finding a scan reports again re-opens); the last sight
			// refreshes severity, location, and provenance.
			fr.finding.Severity = pf.Raw.Severity
			fr.finding.Location = pf.Raw.Location
			fr.finding.Lifecycle = api.LifecycleOpen
			fr.finding.Provenance = pf.Raw.Provenance
			fr.finding.ProvenanceMediaType = pf.Raw.ProvenanceMediaType
			fr.finding.LastSeenScanID = final.ScanID
			continue
		}
		findingID := m.nextID()
		f := api.Finding{
			ID:                  findingID,
			TenantID:            final.TenantID,
			RepositoryID:        final.RepositoryID,
			ScannerClass:        final.Scan.ScannerClass,
			ToolName:            final.Scan.ToolName,
			ToolVersion:         final.Scan.ToolVersion,
			RuleID:              pf.Raw.RuleID,
			Severity:            pf.Raw.Severity,
			Location:            pf.Raw.Location,
			Lifecycle:           api.LifecycleOpen,
			FirstSeenScanID:     final.ScanID,
			LastSeenScanID:      final.ScanID,
			Provenance:          pf.Raw.Provenance,
			ProvenanceMediaType: pf.Raw.ProvenanceMediaType,
		}
		tenant[findingID] = &findingRecord{finding: f, identity: id, firstSeenAt: final.Scan.StartedAt.UTC()}
		identityIndex[id] = findingID
		opened = append(opened, f)
	}

	// Resolution: open findings of the same repository, scanner class, and
	// tool that this scan no longer reports. Scope is the reporting tool —
	// a semgrep scan never resolves a gitleaks finding (SPEC-0024 AC3).
	seenSet := make(map[string]struct{}, len(reported))
	for _, id := range reported {
		seenSet[id] = struct{}{}
	}
	resolved := []api.Finding{}
	for _, rec := range tenant {
		if rec.finding.RepositoryID != final.RepositoryID ||
			rec.finding.ScannerClass != final.Scan.ScannerClass ||
			rec.finding.ToolName != final.Scan.ToolName {
			continue
		}
		// Only currently-open findings the scan no longer reports are
		// resolved; an already-resolved finding is never resolved twice.
		if rec.finding.Lifecycle != api.LifecycleOpen {
			continue
		}
		if _, seen := seenSet[rec.identity]; seen {
			continue
		}
		rec.finding.Lifecycle = api.LifecycleResolved
		resolved = append(resolved, rec.finding)
	}

	slices.SortFunc(opened, func(a, b api.Finding) int { return cmp.Compare(a.ID, b.ID) })
	slices.SortFunc(resolved, func(a, b api.Finding) int { return cmp.Compare(a.ID, b.ID) })
	return opened, resolved
}

// GetFinding returns one tenant-scoped finding.
func (m *MemoryStore) GetFinding(_ context.Context, tenantID, findingID string) (api.Finding, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if tenant, ok := m.finds[tenantID]; ok {
		if rec, ok := tenant[findingID]; ok {
			return rec.finding, nil
		}
	}
	return api.Finding{}, errors.New("security: not found")
}

// ListFindings returns one page of the tenant's findings in identity order.
func (m *MemoryStore) ListFindings(_ context.Context, tenantID string, f ListFilter) ([]api.Finding, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	rows := []api.Finding{}
	for _, rec := range m.finds[tenantID] {
		if !m.repoMatches(tenantID, rec.finding.RepositoryID, f) {
			continue
		}
		if f.ScannerClass != "" && rec.finding.ScannerClass != f.ScannerClass {
			continue
		}
		if f.Severity != "" && rec.finding.Severity != f.Severity {
			continue
		}
		if f.Lifecycle != "" && rec.finding.Lifecycle != f.Lifecycle {
			continue
		}
		if !m.ageMatches(rec.firstSeenAt, f.MinAgeDays, f.MaxAgeDays) {
			continue
		}
		if f.OwningTeam != "" && m.ownership[tenantID][rec.finding.RepositoryID] != f.OwningTeam {
			continue
		}
		rows = append(rows, rec.finding)
	}
	slices.SortFunc(rows, func(a, b api.Finding) int { return cmp.Compare(a.ID, b.ID) })

	if f.AfterID != "" {
		i := sort.Search(len(rows), func(i int) bool { return rows[i].ID > f.AfterID })
		rows = rows[i:]
	}
	if f.Limit > 0 && len(rows) > f.Limit {
		rows = rows[:f.Limit]
	}
	return rows, nil
}

// repoMatches applies the repository scoping of a filter: the
// authorization-derived RepositoryIDs set wins when non-nil — and a non-nil
// empty set matches nothing, fail closed (SPEC-0026 AC6).
func (m *MemoryStore) repoMatches(tenantID, repoID string, f ListFilter) bool {
	if f.RepositoryIDs != nil {
		for _, r := range f.RepositoryIDs {
			if r == repoID {
				return true
			}
		}
		return false
	}
	return f.RepositoryID == "" || f.RepositoryID == repoID
}

// ageMatches bounds the finding's age in whole days since first sight
// (SPEC-0026 AC2); zero on a bound leaves that side unbounded.
func (m *MemoryStore) ageMatches(firstSeenAt time.Time, minDays, maxDays int) bool {
	if minDays == 0 && maxDays == 0 {
		return true
	}
	ageDays := int(time.Now().UTC().Sub(firstSeenAt) / (24 * time.Hour))
	if minDays > 0 && ageDays < minDays {
		return false
	}
	if maxDays > 0 && ageDays > maxDays {
		return false
	}
	return true
}

// SetTriage appends one triage record under the single mutex — the
// in-memory stand-in for the per-finding serializable transaction. Replay
// first, then the version guard, then the append (SPEC-0027 AC1, SPEC-0026
// AC5).
func (m *MemoryStore) SetTriage(_ context.Context, p SetTriageParams) (SetTriageResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if byReq, ok := m.triageReplays[p.TenantID][p.FindingID]; ok {
		if rec, ok := byReq[p.RequestID]; ok {
			return SetTriageResult{Record: rec, Replayed: true}, nil
		}
	}

	history := m.triages[p.TenantID][p.FindingID]
	var current int64
	if len(history) > 0 {
		current = history[len(history)-1].Version
	}
	if current != p.ExpectedVersion {
		var inForce api.TriageRecord
		if len(history) > 0 {
			inForce = history[len(history)-1]
		}
		return SetTriageResult{Record: inForce, Mismatch: true}, nil
	}

	rec := api.TriageRecord{
		TriageID: p.TriageID, FindingID: p.FindingID, TenantID: p.TenantID,
		RepositoryID: p.RepositoryID, State: p.State, Justification: p.Justification,
		Version: current + 1, ActorID: p.ActorID, OccurredAt: p.OccurredAt,
	}
	if m.triages[p.TenantID] == nil {
		m.triages[p.TenantID] = map[string][]api.TriageRecord{}
	}
	m.triages[p.TenantID][p.FindingID] = append(history, rec)
	if m.triageReplays[p.TenantID] == nil {
		m.triageReplays[p.TenantID] = map[string]map[string]api.TriageRecord{}
	}
	if m.triageReplays[p.TenantID][p.FindingID] == nil {
		m.triageReplays[p.TenantID][p.FindingID] = map[string]api.TriageRecord{}
	}
	m.triageReplays[p.TenantID][p.FindingID][p.RequestID] = rec
	return SetTriageResult{Record: rec}, nil
}

// GetTriage returns the finding's triage record: the latest when version is
// zero, the exact history version otherwise.
func (m *MemoryStore) GetTriage(_ context.Context, tenantID, findingID string, version int64) (api.TriageRecord, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	history := m.triages[tenantID][findingID]
	if len(history) == 0 {
		return api.TriageRecord{}, false, nil
	}
	if version == 0 {
		return history[len(history)-1], true, nil
	}
	for _, rec := range history {
		if rec.Version == version {
			return rec, true, nil
		}
	}
	return api.TriageRecord{}, false, nil
}

// RepositoriesWithFindings returns the distinct repositories holding the
// tenant's findings, in stable order.
func (m *MemoryStore) RepositoriesWithFindings(_ context.Context, tenantID string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	set := map[string]struct{}{}
	for _, rec := range m.finds[tenantID] {
		set[rec.finding.RepositoryID] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for r := range set {
		out = append(out, r)
	}
	slices.Sort(out)
	return out, nil
}

// FindingsSummary computes counts and facets under the query's filters —
// the authorization-derived repository set among them — so a value that
// exists only outside the caller's readable set can appear in no facet
// (SPEC-0027 AC4).
func (m *MemoryStore) FindingsSummary(_ context.Context, tenantID string, q SummaryQuery) (api.FindingsSummary, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	out := api.FindingsSummary{Facets: []api.SummaryFacet{}}
	counts := make(map[string]map[string]int64, len(q.Facets))
	for _, dim := range q.Facets {
		counts[dim] = map[string]int64{}
	}
	for _, rec := range m.finds[tenantID] {
		if !m.repoMatches(tenantID, rec.finding.RepositoryID, q.ListFilter) {
			continue
		}
		if q.ScannerClass != "" && rec.finding.ScannerClass != q.ScannerClass {
			continue
		}
		if q.Severity != "" && rec.finding.Severity != q.Severity {
			continue
		}
		if q.Lifecycle != "" && rec.finding.Lifecycle != q.Lifecycle {
			continue
		}
		if !m.ageMatches(rec.firstSeenAt, q.MinAgeDays, q.MaxAgeDays) {
			continue
		}
		team := m.ownership[tenantID][rec.finding.RepositoryID]
		if q.OwningTeam != "" && team != q.OwningTeam {
			continue
		}
		out.TotalCount++
		for _, dim := range q.Facets {
			var value string
			switch dim {
			case api.FacetSeverity:
				value = string(rec.finding.Severity)
			case api.FacetScannerClass:
				value = string(rec.finding.ScannerClass)
			case api.FacetLifecycle:
				value = string(rec.finding.Lifecycle)
			case api.FacetOwningTeam:
				value = team
			}
			// A finding whose repository carries no owning-team attribution
			// contributes to no owning_team value: absence, not an empty
			// bucket.
			if value == "" {
				continue
			}
			counts[dim][value]++
		}
	}
	for _, dim := range q.Facets {
		facet := api.SummaryFacet{Dimension: dim, Values: []api.SummaryFacetValue{}}
		values := make([]string, 0, len(counts[dim]))
		for v := range counts[dim] {
			values = append(values, v)
		}
		slices.Sort(values)
		for _, v := range values {
			facet.Values = append(facet.Values, api.SummaryFacetValue{Value: v, Count: counts[dim][v]})
		}
		out.Facets = append(out.Facets, facet)
	}
	return out, nil
}

// SetRepositoryOwningTeam records the repository-level owning-team
// attribution (SPEC-0026 v1 assumption).
func (m *MemoryStore) SetRepositoryOwningTeam(_ context.Context, tenantID, repositoryID, owningTeam string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ownership[tenantID] == nil {
		m.ownership[tenantID] = map[string]string{}
	}
	m.ownership[tenantID][repositoryID] = owningTeam
	return nil
}

// ScanReportAt returns the reported set of the latest COMPLETE scan at the
// repository's revision. The reported set is the scan's own accumulated
// identities — nothing ever removes from it, so a later scan re-reporting an
// identity leaves the earlier scan's set intact (SPEC-0028 attribution
// rule). Each identity joins to the finding row recorded for it; a row
// always exists, because ingestion creates one for every reported identity
// and never deletes.
func (m *MemoryStore) ScanReportAt(_ context.Context, tenantID, repositoryID, revision string) (ScanReport, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var best *scanRecord
	for _, rec := range m.scans {
		if rec.state != scanComplete {
			continue
		}
		p := rec.params
		if p.TenantID != tenantID || p.RepositoryID != repositoryID || p.Revision != revision {
			continue
		}
		if best == nil || p.Scan.StartedAt.After(best.params.Scan.StartedAt) ||
			(p.Scan.StartedAt.Equal(best.params.Scan.StartedAt) && p.ScanID > best.params.ScanID) {
			best = rec
		}
	}
	if best == nil {
		return ScanReport{}, false, nil
	}
	tenant := m.finds[tenantID]
	identityIndex := m.byIdentity[tenantID]
	out := []ReportedFinding{}
	for identity := range best.prepared {
		findingID, ok := identityIndex[identity]
		if !ok {
			continue
		}
		out = append(out, ReportedFinding{Identity: identity, Finding: tenant[findingID].finding})
	}
	slices.SortFunc(out, func(a, b ReportedFinding) int { return cmp.Compare(a.Finding.ID, b.Finding.ID) })
	return ScanReport{ScanID: best.params.ScanID, Findings: out}, true, nil
}
