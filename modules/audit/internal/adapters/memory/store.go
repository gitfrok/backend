// Package memory is the in-memory audit trail: the same append-only,
// hash-chained shape as the Postgres adapter, for dev planes and tests.
//
// It exists because T-0026's evidence assembler needs a trail to query and a
// plane without GITFROK_DATABASE_URL still has a product surface (the
// composition pattern every other context follows: memory by default,
// Postgres when configured). What it is NOT is a durable store — a restart
// empties it, exactly like the other in-memory adapters, and a configured
// plane never composes it for evidence that must outlive the process.
package memory

import (
	"context"
	"fmt"
	"sync"

	"github.com/gitfrok/backend/modules/audit/api"
	"github.com/gitfrok/backend/modules/audit/internal/domain"
	"github.com/gitfrok/backend/platform/tenancy"
)

// defaultQueryLimit caps one trail read, mirroring the bounded-read principle
// the evidence contract applies to packs: no operation is unbounded.
const defaultQueryLimit = 10_000

// Store is the in-memory audit trail, keyed per tenant. Safe for concurrent
// use.
type Store struct {
	mu      sync.Mutex
	entries map[string][]api.Record // tenant -> chain, in sequence order
}

// New returns an empty in-memory trail.
func New() *Store { return &Store{entries: map[string][]api.Record{}} }

// Append adds one entry and returns the record as persisted. Like the
// Postgres adapter, the sequence number and hashes are assigned here, never
// taken from the caller (ADR-0007), and only FIRST_PARTY records may be
// appended (ADR-0029 §1).
func (s *Store) Append(ctx context.Context, e api.Entry) (api.Record, error) {
	if e.Provenance != api.ProvenanceFirstParty {
		return api.Record{}, fmt.Errorf("audit: only FIRST_PARTY records may be appended")
	}
	tenant, ok := tenancy.FromContext(ctx)
	if !ok {
		return api.Record{}, fmt.Errorf("audit: append without tenant scope")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	chain := s.entries[string(tenant)]
	var prevHash string
	if len(chain) > 0 {
		prevHash = chain[len(chain)-1].Hash
	}
	rec := api.Record{
		Seq:        int64(len(chain) + 1),
		TenantID:   e.TenantID,
		Action:     e.Action,
		ActorID:    e.ActorID,
		Resource:   e.Resource,
		Outcome:    e.Outcome,
		Detail:     e.Detail,
		OccurredAt: e.OccurredAt,
		PrevHash:   prevHash,
	}
	rec.Hash = domain.Hash(prevHash, domain.Fields{
		Seq: rec.Seq, TenantID: rec.TenantID, Action: string(rec.Action), ActorID: rec.ActorID,
		Resource: rec.Resource, Outcome: string(rec.Outcome), Detail: rec.Detail, OccurredAt: rec.OccurredAt,
	})
	s.entries[string(tenant)] = append(chain, rec)
	return rec, nil
}

// Verify walks the tenant's chain and reports the first fault.
func (s *Store) Verify(ctx context.Context) (api.VerifyResult, error) {
	tenant, ok := tenancy.FromContext(ctx)
	if !ok {
		return api.VerifyResult{}, fmt.Errorf("audit: verify without tenant scope")
	}
	s.mu.Lock()
	chain := append([]api.Record(nil), s.entries[string(tenant)]...)
	s.mu.Unlock()

	links := make([]domain.Link, 0, len(chain))
	for _, r := range chain {
		links = append(links, domain.Link{
			Fields: domain.Fields{
				Seq: r.Seq, TenantID: r.TenantID, Action: string(r.Action), ActorID: r.ActorID,
				Resource: r.Resource, Outcome: string(r.Outcome), Detail: r.Detail, OccurredAt: r.OccurredAt,
			},
			PrevHash: r.PrevHash, Hash: r.Hash,
		})
	}
	okChain, brokenAt, reason := domain.VerifyChain(links)
	return api.VerifyResult{Checked: int64(len(links)), OK: okChain, BrokenAtSeq: brokenAt, Reason: reason}, nil
}

// Query returns the tenant's records matching q, in chain-sequence order. The
// tenant comes from the ctx scope, not the query: a caller cannot read a
// chain it is not scoped to (SPEC-0001).
func (s *Store) Query(ctx context.Context, q api.TrailQuery) ([]api.Record, error) {
	tenant, ok := tenancy.FromContext(ctx)
	if !ok {
		return nil, fmt.Errorf("audit: query without tenant scope")
	}

	s.mu.Lock()
	chain := append([]api.Record(nil), s.entries[string(tenant)]...)
	s.mu.Unlock()

	limit := q.Limit
	if limit <= 0 {
		limit = defaultQueryLimit
	}
	actions := map[api.Action]struct{}{}
	for _, a := range q.Actions {
		actions[a] = struct{}{}
	}

	out := make([]api.Record, 0, len(chain))
	for _, r := range chain {
		if !q.From.IsZero() && r.OccurredAt.Before(q.From) {
			continue
		}
		if !q.To.IsZero() && r.OccurredAt.After(q.To) {
			continue
		}
		if len(actions) > 0 {
			if _, ok := actions[r.Action]; !ok {
				continue
			}
		}
		if q.RepositoryID != "" {
			if repo, ok := r.Detail["repository_id"]; ok && repo != q.RepositoryID {
				continue
			}
		}
		out = append(out, r)
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}
