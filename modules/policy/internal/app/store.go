// Decision-record storage for the Policy context (SPEC-0029 AC1, SPEC-0030).
//
// Policy owns decision records: every decision the PDP makes is appended here, immutable, with
// the provenance it was made under — the deciding bundle revision, the digest over the
// canonicalized input, and the mode. Records are append-only by construction: the port has no
// update and no delete, because a decision that could be rewritten after the fact would be
// worthless as evidence (G5).
package app

import (
	"context"
	"sort"
	"sync"

	"github.com/gitfrok/backend/modules/policy/api"
)

// RecordStore persists decision records and serves the reads a dry-run and a retrieval need.
//
// Every method is tenant-scoped by the record's own TenantID: a store implementation that let
// one tenant read another's records would fail SPEC-0030 AC6 regardless of how correct its
// queries were.
type RecordStore interface {
	// Append records one decision. Appending a DecisionID the store already holds for that
	// tenant is a programming error the store refuses, never a silent overwrite: a decision's
	// record is that decision's evidence, and replacing it would be indistinguishable from
	// having made a different decision.
	Append(ctx context.Context, r api.Record) error
	// Get returns the record with this decision ID in this tenant, or api.ErrNotFound. A
	// cross-tenant ID is exactly as not-found as a nonexistent one — one coarse shape.
	Get(ctx context.Context, tenantID, decisionID string) (api.Record, error)
	// Range replays recorded ENFORCED decisions — the tenant's real decision history — within
	// the bounds of q, oldest first, up to limit+1 entries. Returning one beyond the limit is
	// how the service detects a range that exceeds its cap and rejects it instead of
	// truncating (SPEC-0030). DRY_RUN records are never replayed: a dry-run over dry-run
	// inputs would replay a simulation of a simulation, and history is the enforced record.
	Range(ctx context.Context, tenantID string, q api.HistoricalRange, limit int) ([]api.Record, error)
}

// MemoryStore is the in-memory RecordStore: dev and tests, and any plane without a database
// URL. It offers none of the Postgres adapter's properties — no RLS, no durability — and makes
// no claim to: planes that need those compose the Postgres adapter instead, exactly as the
// other contexts do.
type MemoryStore struct {
	mu      sync.Mutex
	records map[string]api.Record // key: tenantID + "\x00" + decisionID
}

// NewMemoryStore returns an empty in-memory record store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{records: make(map[string]api.Record)}
}

var _ RecordStore = (*MemoryStore)(nil)

func recordKey(tenantID, decisionID string) string { return tenantID + "\x00" + decisionID }

// Append records one decision, refusing a duplicate decision ID within its tenant.
func (s *MemoryStore) Append(_ context.Context, r api.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := recordKey(r.TenantID, r.DecisionID)
	if _, exists := s.records[key]; exists {
		return api.ErrInvalidRequest
	}
	s.records[key] = cloneRecord(r)
	return nil
}

// Get retrieves one record within its tenant.
func (s *MemoryStore) Get(_ context.Context, tenantID, decisionID string) (api.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[recordKey(tenantID, decisionID)]
	if !ok {
		return api.Record{}, api.ErrNotFound
	}
	return cloneRecord(r), nil
}

// Range replays ENFORCED records within the bounds, oldest first.
func (s *MemoryStore) Range(_ context.Context, tenantID string, q api.HistoricalRange, limit int) ([]api.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []api.Record
	for _, r := range s.records {
		if r.TenantID != tenantID || r.Mode != api.ModeEnforced {
			continue
		}
		if q.Action != "" && r.Action != q.Action {
			continue
		}
		if q.Resource.Type != "" && r.Resource.Type != q.Resource.Type {
			continue
		}
		if q.Resource.ID != "" && r.Resource.ID != q.Resource.ID {
			continue
		}
		if !q.From.IsZero() && r.DecidedAt.Before(q.From) {
			continue
		}
		if !q.To.IsZero() && r.DecidedAt.After(q.To) {
			continue
		}
		out = append(out, cloneRecord(r))
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].DecidedAt.Equal(out[j].DecidedAt) {
			return out[i].DecidedAt.Before(out[j].DecidedAt)
		}
		return out[i].DecisionID < out[j].DecisionID
	})
	if limit >= 0 && len(out) > limit {
		out = out[:limit+1]
	}
	return out, nil
}

// cloneRecord deep-copies the mutable parts of a record so the store's contents and a caller's
// copy can never mutate each other.
func cloneRecord(r api.Record) api.Record {
	if r.SubjectRoles != nil {
		r.SubjectRoles = append([]string(nil), r.SubjectRoles...)
	}
	if r.Context != nil {
		m := make(map[string]string, len(r.Context))
		for k, v := range r.Context {
			m[k] = v
		}
		r.Context = m
	}
	return r
}
