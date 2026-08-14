package app

import (
	"context"
	"errors"
	"sort"
	"sync"

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
}

// MemoryStore is the in-memory Store for dev and tests. It implements the
// same contract the Postgres adapter does: serializable per-scan ingest
// (a single mutex stands in for the transaction), chunk visibility only
// after the final chunk, idempotency per request ID, and the
// resolved-not-deleted lifecycle (SPEC-0024 AC9, SPEC-0025).
type MemoryStore struct {
	mu     sync.Mutex
	scans  map[string]*scanRecord
	finds  map[string]map[string]*findingRecord // tenant -> finding ID -> record
	// byIdentity indexes findings by their SPEC-0024 identity so a re-report
	// lands on the same record: the dedup the Postgres adapter gets from
	// UNIQUE (tenant_id, repository_id, identity).
	byIdentity map[string]map[string]string // tenant -> identity -> finding ID
	nextID     func() string
}

// NewMemoryStore builds the in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		scans:      map[string]*scanRecord{},
		finds:      map[string]map[string]*findingRecord{},
		byIdentity: map[string]map[string]string{},
		nextID:     ids.NewULID,
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
	sort.Strings(reported)

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
			ID:           findingID,
			TenantID:     final.TenantID,
			RepositoryID: final.RepositoryID,
			ScannerClass: final.Scan.ScannerClass,
			ToolName:     final.Scan.ToolName,
			ToolVersion:  final.Scan.ToolVersion,
			RuleID:       pf.Raw.RuleID,
			Severity:     pf.Raw.Severity,
			Location:     pf.Raw.Location,
			Lifecycle:    api.LifecycleOpen,
			FirstSeenScanID: final.ScanID,
			LastSeenScanID:  final.ScanID,
			Provenance:          pf.Raw.Provenance,
			ProvenanceMediaType: pf.Raw.ProvenanceMediaType,
		}
		tenant[findingID] = &findingRecord{finding: f, identity: id}
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

	sort.Slice(opened, func(i, j int) bool { return opened[i].ID < opened[j].ID })
	sort.Slice(resolved, func(i, j int) bool { return resolved[i].ID < resolved[j].ID })
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
		if f.RepositoryID != "" && rec.finding.RepositoryID != f.RepositoryID {
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
		rows = append(rows, rec.finding)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })

	if f.AfterID != "" {
		i := sort.Search(len(rows), func(i int) bool { return rows[i].ID > f.AfterID })
		rows = rows[i:]
	}
	if f.Limit > 0 && len(rows) > f.Limit {
		rows = rows[:f.Limit]
	}
	return rows, nil
}
