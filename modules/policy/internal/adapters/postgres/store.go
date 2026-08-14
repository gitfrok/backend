// Package postgres is the Policy context's decision-record persistence adapter (SPEC-0029,
// SPEC-0030).
//
// The schema's load-bearing properties live in the migration, not here: the PRIMARY KEY
// (tenant_id, decision_id) IS the append-only rule, the CHECK constraint IS the mode vocabulary,
// and RLS IS the tenant boundary (SPEC-0001). This adapter merely refuses to work outside those
// properties: every call runs inside a transaction pinned to the record's own tenant, and the
// only verbs it knows are INSERT and SELECT — a decision record is evidence, and evidence is
// never updated.
package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/gitfrok/backend/modules/policy/api"
	"github.com/gitfrok/backend/modules/policy/internal/app"
	"github.com/gitfrok/backend/platform/db"
	"github.com/gitfrok/backend/platform/tenancy"
)

// sqlStateUniqueViolation is what Postgres returns when an append re-uses a decision ID the
// tenant already recorded.
const sqlStateUniqueViolation = "23505"

// Store is the Postgres decision-record store.
type Store struct {
	pool *db.Pool
}

// New builds the store over a tenant-scoped pool.
func New(pool *db.Pool) *Store { return &Store{pool: pool} }

var _ app.RecordStore = (*Store)(nil)

// Append records one decision inside a transaction scoped to the record's tenant.
func (s *Store) Append(ctx context.Context, r api.Record) error {
	roles, err := json.Marshal(orEmptyStrings(r.SubjectRoles))
	if err != nil {
		return fmt.Errorf("policy: encoding subject roles: %w", err)
	}
	contextAttrs, err := json.Marshal(orEmptyContext(r.Context))
	if err != nil {
		return fmt.Errorf("policy: encoding context: %w", err)
	}

	ctx = tenancy.WithTenant(ctx, tenancy.ID(r.TenantID))
	return s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO policy.decision_records
			   (tenant_id, decision_id, policy_revision, input_digest, mode,
			    actor_id, action, resource_type, resource_id, allowed, reason,
			    subject_tenant_id, subject_roles, context, decided_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
			r.TenantID, r.DecisionID, r.PolicyRevision, r.InputDigest, string(r.Mode),
			r.ActorID, r.Action, r.Resource.Type, r.Resource.ID, r.Allowed, r.Reason,
			r.SubjectTenantID, roles, contextAttrs, r.DecidedAt.UTC())
		if err != nil {
			if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == sqlStateUniqueViolation {
				// A decision ID this tenant already holds: the store refuses a rewrite rather
				// than performing one. The record that exists stands exactly as recorded.
				return api.ErrInvalidRequest
			}
			return fmt.Errorf("append decision record: %w", err)
		}
		return nil
	})
}

// Get retrieves one record within its tenant. A cross-tenant or nonexistent ID is
// api.ErrNotFound — one coarse shape (SPEC-0030 AC6): RLS has already made another tenant's
// record invisible to this transaction, so the adapter genuinely cannot tell the cases apart
// and does not pretend to.
func (s *Store) Get(ctx context.Context, tenantID, decisionID string) (api.Record, error) {
	ctx = tenancy.WithTenant(ctx, tenancy.ID(tenantID))
	var rec api.Record
	err := s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var roles, contextAttrs []byte
		err := tx.QueryRow(ctx,
			`SELECT decision_id, policy_revision, input_digest, mode, actor_id, action,
			        resource_type, resource_id, allowed, reason, subject_tenant_id,
			        subject_roles, context, decided_at
			   FROM policy.decision_records
			  WHERE decision_id = $1`, decisionID,
		).Scan(&rec.DecisionID, &rec.PolicyRevision, &rec.InputDigest, &rec.Mode,
			&rec.ActorID, &rec.Action, &rec.Resource.Type, &rec.Resource.ID,
			&rec.Allowed, &rec.Reason, &rec.SubjectTenantID, &roles, &contextAttrs,
			&rec.DecidedAt)
		if err != nil {
			return err
		}
		rec.TenantID = tenantID
		if err := json.Unmarshal(roles, &rec.SubjectRoles); err != nil {
			return fmt.Errorf("decoding subject roles: %w", err)
		}
		if err := json.Unmarshal(contextAttrs, &rec.Context); err != nil {
			return fmt.Errorf("decoding context: %w", err)
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return api.Record{}, api.ErrNotFound
		}
		return api.Record{}, fmt.Errorf("policy: reading decision %s: %w", decisionID, err)
	}
	return rec, nil
}

// Range replays recorded ENFORCED decisions within the bounds, oldest first, returning up to
// limit+1 rows — the extra row is the service's signal that the range exceeds its cap and must
// be rejected rather than truncated (SPEC-0030).
//
// The WHERE clause is assembled from constant fragments plus one placeholder per bound; the
// caller's values never enter the SQL text itself.
func (s *Store) Range(ctx context.Context, tenantID string, q api.HistoricalRange, limit int) ([]api.Record, error) {
	ctx = tenancy.WithTenant(ctx, tenancy.ID(tenantID))
	var out []api.Record
	err := s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var conds []string
		var args []any
		conds = append(conds, "mode = 'ENFORCED'")
		if q.Action != "" {
			args = append(args, q.Action)
			conds = append(conds, fmt.Sprintf("action = $%d", len(args)))
		}
		if q.Resource.Type != "" {
			args = append(args, q.Resource.Type)
			conds = append(conds, fmt.Sprintf("resource_type = $%d", len(args)))
		}
		if q.Resource.ID != "" {
			args = append(args, q.Resource.ID)
			conds = append(conds, fmt.Sprintf("resource_id = $%d", len(args)))
		}
		if !q.From.IsZero() {
			args = append(args, q.From.UTC())
			conds = append(conds, fmt.Sprintf("decided_at >= $%d", len(args)))
		}
		if !q.To.IsZero() {
			args = append(args, q.To.UTC())
			conds = append(conds, fmt.Sprintf("decided_at <= $%d", len(args)))
		}
		query := `SELECT decision_id, policy_revision, input_digest, mode, actor_id, action,
		                 resource_type, resource_id, allowed, reason, subject_tenant_id,
		                 subject_roles, context, decided_at
		            FROM policy.decision_records
		           WHERE ` + strings.Join(conds, " AND ") +
			` ORDER BY decided_at, decision_id LIMIT ` + fmt.Sprintf("%d", limit+1)

		rows, err := tx.Query(ctx, query, args...)
		if err != nil {
			return fmt.Errorf("range decision records: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var rec api.Record
			var roles, contextAttrs []byte
			if err := rows.Scan(&rec.DecisionID, &rec.PolicyRevision, &rec.InputDigest, &rec.Mode,
				&rec.ActorID, &rec.Action, &rec.Resource.Type, &rec.Resource.ID,
				&rec.Allowed, &rec.Reason, &rec.SubjectTenantID, &roles, &contextAttrs,
				&rec.DecidedAt); err != nil {
				return fmt.Errorf("scanning decision record: %w", err)
			}
			rec.TenantID = tenantID
			if err := json.Unmarshal(roles, &rec.SubjectRoles); err != nil {
				return fmt.Errorf("decoding subject roles: %w", err)
			}
			if err := json.Unmarshal(contextAttrs, &rec.Context); err != nil {
				return fmt.Errorf("decoding context: %w", err)
			}
			out = append(out, rec)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func orEmptyStrings(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

func orEmptyContext(v map[string]string) map[string]string {
	if v == nil {
		return map[string]string{}
	}
	return v
}
