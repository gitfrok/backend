// Postgres persistence for the auditor grant lifecycle (T-0027, SPEC-0033).
//
// The store keeps grant records and their witnessed transitions inside
// platform/db's tenant-scoped transactions; row-level security scopes every
// row as well (0002_identity_auditor_grants.sql), so a cross-tenant grant is
// invisible before any application check runs. It carries no authorization
// of its own: the service decides before it stores.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/gitfrok/backend/modules/identity/api"
	"github.com/gitfrok/backend/platform/db"
	"github.com/gitfrok/backend/platform/tenancy"
)

// GrantStore persists auditor grants on db.Pool.
type GrantStore struct {
	pool *db.Pool
}

// NewGrantStore builds the store on a tenant-scoped pool.
func NewGrantStore(pool *db.Pool) *GrantStore {
	if pool == nil {
		panic("identity grants postgres: pool is required")
	}
	return &GrantStore{pool: pool}
}

// FindByRequest implements app.GrantStore.
func (s *GrantStore) FindByRequest(ctx context.Context, tenantID, requestID string) (api.AuditorGrant, bool, error) {
	if requestID == "" {
		return api.AuditorGrant{}, false, nil
	}
	var grant api.AuditorGrant
	found := false
	err := s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		row := tx.QueryRow(ctx, grantSelect+
			` WHERE g.tenant_id = $1 AND g.request_id = $2`, tenantID, requestID)
		scanned, scanErr := scanGrant(row)
		if scanErr != nil {
			if errors.Is(scanErr, pgx.ErrNoRows) {
				return nil
			}
			return scanErr
		}
		grant, found = scanned, true
		return nil
	})
	if err != nil {
		return api.AuditorGrant{}, false, fmt.Errorf("identity grants postgres: replay lookup: %w", err)
	}
	return grant, found, nil
}

// Insert implements app.GrantStore.
func (s *GrantStore) Insert(ctx context.Context, g api.AuditorGrant, requestID string) error {
	err := s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO identity.auditor_grants
			   (grant_id, tenant_id, auditor_principal_id, range_from, range_to,
			    repository_id, pack_ids, expires_at, granted_by, issued_at, request_id)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
			g.GrantID, g.TenantID, g.AuditorPrincipalID, g.RangeFrom, g.RangeTo,
			g.RepositoryID, g.PackIDs, g.ExpiresAt, g.GrantedBy, g.IssuedAt, requestID,
		)
		return err
	})
	if err != nil {
		return fmt.Errorf("identity grants postgres: insert: %w", err)
	}
	return nil
}

// Revoke implements app.GrantStore: only a grant that is still authorizing
// — never revoked and strictly before its expiry — can be revoked.
// Not-found, cross-tenant (RLS-invisible), already-revoked and expired all
// yield ok=false: the same coarse answer (SPEC-0001).
func (s *GrantStore) Revoke(ctx context.Context, tenantID, grantID string, at time.Time) (api.AuditorGrant, bool, error) {
	var grant api.AuditorGrant
	found := false
	err := s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		row := tx.QueryRow(ctx,
			`UPDATE identity.auditor_grants
			    SET revoked_at = $1
			  WHERE grant_id = $2 AND tenant_id = $3
			    AND revoked_at IS NULL AND expires_at > $1
			  RETURNING grant_id, tenant_id, auditor_principal_id, range_from, range_to,
			            repository_id, pack_ids, expires_at, granted_by, issued_at, revoked_at`,
			at, grantID, tenantID)
		scanned, scanErr := scanGrant(row)
		if scanErr != nil {
			if errors.Is(scanErr, pgx.ErrNoRows) {
				return nil
			}
			return scanErr
		}
		grant, found = scanned, true
		return nil
	})
	if err != nil {
		return api.AuditorGrant{}, false, fmt.Errorf("identity grants postgres: revoke: %w", err)
	}
	return grant, found, nil
}

// List implements app.GrantStore.
func (s *GrantStore) List(ctx context.Context, tenantID, auditorPrincipalID string) ([]api.AuditorGrant, error) {
	return s.queryGrants(ctx,
		` WHERE g.tenant_id = $1 AND ($2::text = '' OR g.auditor_principal_id = $2)
		 ORDER BY g.issued_at ASC, g.grant_id ASC`, tenantID, auditorPrincipalID)
}

// FindForRead implements app.GrantStore: the grants naming packID that were
// issued to auditorPrincipalID — the PEP's decision-time lookup.
func (s *GrantStore) FindForRead(ctx context.Context, tenantID, auditorPrincipalID, packID string) ([]api.AuditorGrant, error) {
	return s.queryGrants(ctx,
		` WHERE g.tenant_id = $1 AND g.auditor_principal_id = $2 AND $3 = ANY (g.pack_ids)
		 ORDER BY g.issued_at ASC, g.grant_id ASC`, tenantID, auditorPrincipalID, packID)
}

// Transitions implements app.GrantStore.
func (s *GrantStore) Transitions(ctx context.Context, tenantID string, from, to time.Time, repositoryID string) ([]api.GrantTransition, error) {
	var out []api.GrantTransition
	err := s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT kind, grant_id, actor_id, granted_by, auditor_principal_id,
			        repository_id, decision_id, chain_seq, record_hash, occurred_at
			   FROM identity.auditor_grant_transitions
			  WHERE tenant_id = $1
			    AND ($2::timestamptz IS NULL OR occurred_at >= $2)
			    AND ($3::timestamptz IS NULL OR occurred_at <= $3)
			    AND ($4::text = '' OR repository_id = '' OR repository_id = $4)
			  ORDER BY chain_seq ASC`,
			tenantID, nullableTime(from), nullableTime(to), repositoryID,
		)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var t api.GrantTransition
			if err := rows.Scan(&t.Kind, &t.GrantID, &t.ActorID, &t.GrantedBy,
				&t.AuditorPrincipalID, &t.RepositoryID, &t.DecisionID,
				&t.ChainSeq, &t.RecordHash, &t.OccurredAt); err != nil {
				return err
			}
			out = append(out, t)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("identity grants postgres: transitions: %w", err)
	}
	return out, nil
}

// TransitionRecorded implements app.GrantStore.
func (s *GrantStore) TransitionRecorded(ctx context.Context, tenantID, grantID string, kind api.GrantTransitionKind) (bool, error) {
	var exists bool
	err := s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT EXISTS (
			   SELECT 1 FROM identity.auditor_grant_transitions
			    WHERE tenant_id = $1 AND grant_id = $2 AND kind = $3)`,
			tenantID, grantID, string(kind)).Scan(&exists)
	})
	if err != nil {
		return false, fmt.Errorf("identity grants postgres: transition lookup: %w", err)
	}
	return exists, nil
}

// AppendTransition implements app.GrantStore. The primary key is the
// exactly-once rule: a second witness of the same transition inserts
// nothing.
func (s *GrantStore) AppendTransition(ctx context.Context, t api.GrantTransition) (bool, error) {
	var inserted bool
	err := s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`INSERT INTO identity.auditor_grant_transitions
			   (tenant_id, grant_id, kind, actor_id, granted_by, auditor_principal_id,
			    repository_id, decision_id, chain_seq, record_hash, occurred_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
			 ON CONFLICT (tenant_id, grant_id, kind) DO NOTHING`,
			tenantOf(ctx), t.GrantID, string(t.Kind), t.ActorID, t.GrantedBy, t.AuditorPrincipalID,
			t.RepositoryID, t.DecisionID, t.ChainSeq, t.RecordHash, t.OccurredAt,
		)
		if err != nil {
			return err
		}
		inserted = tag.RowsAffected() == 1
		return nil
	})
	if err != nil {
		return false, fmt.Errorf("identity grants postgres: append transition: %w", err)
	}
	return inserted, nil
}

// tenantOf reads the tenant scope the surrounding transaction runs under.
func tenantOf(ctx context.Context) string {
	if id, ok := tenancy.FromContext(ctx); ok {
		return string(id)
	}
	return ""
}

const grantSelect = `SELECT g.grant_id, g.tenant_id, g.auditor_principal_id, g.range_from, g.range_to,
       g.repository_id, g.pack_ids, g.expires_at, g.granted_by, g.issued_at, g.revoked_at
  FROM identity.auditor_grants AS g`

type rowScanner interface {
	Scan(dest ...any) error
}

func scanGrant(row rowScanner) (api.AuditorGrant, error) {
	var g api.AuditorGrant
	var revokedAt *time.Time
	err := row.Scan(&g.GrantID, &g.TenantID, &g.AuditorPrincipalID, &g.RangeFrom, &g.RangeTo,
		&g.RepositoryID, &g.PackIDs, &g.ExpiresAt, &g.GrantedBy, &g.IssuedAt, &revokedAt)
	if err != nil {
		return api.AuditorGrant{}, err
	}
	if revokedAt != nil {
		g.RevokedAt = *revokedAt
	}
	g.PackIDs = append([]string(nil), g.PackIDs...)
	return g, nil
}

func (s *GrantStore) queryGrants(ctx context.Context, tail string, args ...any) ([]api.AuditorGrant, error) {
	var out []api.AuditorGrant
	err := s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, grantSelect+tail, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			g, scanErr := scanGrant(rows)
			if scanErr != nil {
				return scanErr
			}
			out = append(out, g)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("identity grants postgres: query: %w", err)
	}
	return out, nil
}

func nullableTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	value := t
	return &value
}
