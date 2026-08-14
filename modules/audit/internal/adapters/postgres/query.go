// Trail queries over the Postgres audit trail (T-0026, SPEC-0031).
//
// This file adds the READ port Phase 2 owed forward; store.go stays Append
// and Verify only, and the database grants that make "no update path" true
// are untouched — a read needs no new privilege on an append-only table.
package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/gitfrok/backend/modules/audit/api"
)

// defaultQueryLimit caps one trail read; zero or negative means this.
const defaultQueryLimit = 10_000

// Query returns the tenant's records matching q, in chain-sequence order.
//
// Tenant isolation is inherited from the pool's row-level security: the
// surrounding transaction is scoped before this runs, so one tenant's read
// cannot see another's chain (SPEC-0001) — the same inheritance Append gets.
func (s *Store) Query(ctx context.Context, q api.TrailQuery) ([]api.Record, error) {
	var out []api.Record
	err := s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		// Filters compose additively; every bound is a parameter, never text.
		var conds []string
		args := []any{}
		add := func(cond string, v any) {
			args = append(args, v)
			conds = append(conds, fmt.Sprintf(cond, len(args)))
		}
		if !q.From.IsZero() {
			add("occurred_at >= $%d", q.From)
		}
		if !q.To.IsZero() {
			add("occurred_at <= $%d", q.To)
		}
		if len(q.Actions) > 0 {
			actions := make([]string, len(q.Actions))
			for i, a := range q.Actions {
				actions[i] = string(a)
			}
			add("action = ANY($%d)", actions)
		}
		if q.RepositoryID != "" {
			// Records attributed to another repository are excluded; records
			// with no repository attribution are tenant-scoped controls and
			// stay — a tenant-wide control is evidence whatever repository is
			// named (mirrors the in-memory adapter).
			add("(detail->>'repository_id' IS NULL OR detail->>'repository_id' = $%d)", q.RepositoryID)
		}

		limit := q.Limit
		if limit <= 0 {
			limit = defaultQueryLimit
		}

		query := `SELECT tenant_seq, tenant_id, action, actor_id, resource, outcome, detail,
		                 occurred_at, prev_hash, hash
		          FROM audit.entries`
		if len(conds) > 0 {
			query += " WHERE " + strings.Join(conds, " AND ")
		}
		query += fmt.Sprintf(" ORDER BY tenant_seq ASC LIMIT %d", limit)

		rows, err := tx.Query(ctx, query, args...)
		if err != nil {
			return fmt.Errorf("audit: query trail: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var r api.Record
			var action, outcome string
			var detail []byte
			if err := rows.Scan(&r.Seq, &r.TenantID, &action, &r.ActorID, &r.Resource, &outcome,
				&detail, &r.OccurredAt, &r.PrevHash, &r.Hash); err != nil {
				return fmt.Errorf("audit: scan trail: %w", err)
			}
			r.Action = api.Action(action)
			r.Outcome = api.Outcome(outcome)
			if err := json.Unmarshal(detail, &r.Detail); err != nil {
				return fmt.Errorf("audit: decode detail at seq %d: %w", r.Seq, err)
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}
