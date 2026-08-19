// Package postgres persists release records (T-0064, SPEC-0056, ADR-0075).
//
// Follows the shape ADR-0062 set and ADR-0071 reused: a durable adapter behind the context's own
// port, tenant-scoped through platform/db.InTx, with RLS as the backstop rather than the mechanism.
//
// There is no artifact column and no code here that would read one.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/gitfrok/backend/modules/release/api"
	"github.com/gitfrok/backend/modules/release/internal/app"
	"github.com/gitfrok/backend/platform/db"
	"github.com/gitfrok/backend/platform/tenancy"
)

// Store implements the Release persistence port over one db.Pool.
type Store struct {
	pool *db.Pool
}

// New wires the store. A nil pool is a composition bug, not a runtime shape.
func New(pool *db.Pool) *Store {
	if pool == nil {
		panic("release postgres: pool is required")
	}
	return &Store{pool: pool}
}

var _ app.Store = (*Store)(nil)

const columns = `tenant_id, repository_id, tag, published_commit, notes, published_by, published_at, notes_updated_at`

// Insert records a release.
//
// A duplicate is refused rather than resolved: the primary key IS the rule that a tag has at most
// one release, and two releases of v1.2.0 is not a state this product has an answer for.
func (s *Store) Insert(ctx context.Context, r api.Release) error {
	ctx, err := scoped(ctx, r.TenantID)
	if err != nil {
		return err
	}
	return s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`INSERT INTO release.releases
			   (tenant_id, repository_id, tag, published_commit, notes, published_by, published_at)
			 VALUES ($1,$2,$3,$4,$5,$6,$7)
			 ON CONFLICT (tenant_id, repository_id, tag) DO NOTHING`,
			r.TenantID, r.RepositoryID, r.Tag, r.PublishedCommit, r.Notes, r.PublishedBy, r.PublishedAt,
		)
		if err != nil {
			return fmt.Errorf("release postgres: insert %s: %w", r.Tag, err)
		}
		if tag.RowsAffected() == 0 {
			return api.ErrAlreadyPublished
		}
		return nil
	})
}

// Get returns one release exactly as recorded. A release of another tenant is ABSENT — RLS makes
// that true at the database rather than by a check here that could be forgotten.
func (s *Store) Get(ctx context.Context, tenantID, repositoryID, tag string) (api.Release, error) {
	ctx, err := scoped(ctx, tenantID)
	if err != nil {
		return api.Release{}, err
	}
	var r api.Release
	err = s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return scan(tx.QueryRow(ctx,
			`SELECT `+columns+` FROM release.releases WHERE repository_id = $1 AND tag = $2`,
			repositoryID, tag), &r)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return api.Release{}, api.ErrNotFound
	}
	if err != nil {
		return api.Release{}, fmt.Errorf("release postgres: get %s: %w", tag, err)
	}
	return r, nil
}

// UpdateNotes corrects the prose and records when. The tag and published_commit are not in the SET
// clause, which is where SPEC-0056 AC4 is actually enforced.
func (s *Store) UpdateNotes(ctx context.Context, tenantID, repositoryID, tag, notes string, at time.Time) (api.Release, error) {
	ctx, err := scoped(ctx, tenantID)
	if err != nil {
		return api.Release{}, err
	}
	var r api.Release
	err = s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return scan(tx.QueryRow(ctx,
			`UPDATE release.releases SET notes = $3, notes_updated_at = $4
			  WHERE repository_id = $1 AND tag = $2
			 RETURNING `+columns, repositoryID, tag, notes, at), &r)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return api.Release{}, api.ErrNotFound
	}
	if err != nil {
		return api.Release{}, fmt.Errorf("release postgres: update notes %s: %w", tag, err)
	}
	return r, nil
}

// Page walks a repository's releases newest first, after the cursor.
func (s *Store) Page(ctx context.Context, tenantID, repositoryID string, after app.Cursor, limit int) ([]api.Release, error) {
	ctx, err := scoped(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if limit <= 0 {
		return nil, nil
	}
	at := after.PublishedAt
	if at.IsZero() {
		at = time.Now().Add(24 * time.Hour)
	}
	var out []api.Release
	err = s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT `+columns+`
			   FROM release.releases
			  WHERE repository_id = $1 AND (published_at, tag) < ($2, $3)
			  ORDER BY published_at DESC, tag DESC
			  LIMIT $4`, repositoryID, at, after.Tag, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r api.Release
			if err := scan(rows, &r); err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("release postgres: page: %w", err)
	}
	return out, nil
}

func scan(row interface{ Scan(dest ...any) error }, r *api.Release) error {
	var updated *time.Time
	if err := row.Scan(&r.TenantID, &r.RepositoryID, &r.Tag, &r.PublishedCommit,
		&r.Notes, &r.PublishedBy, &r.PublishedAt, &updated); err != nil {
		return err
	}
	if updated != nil {
		r.NotesUpdatedAt = *updated
	}
	return nil
}

// scoped returns ctx carrying tenantID, and REFUSES when the context already names a different one.
// See the residency, repository and CI adapters for why RLS cannot make this refusal itself.
func scoped(ctx context.Context, tenantID string) (context.Context, error) {
	if tenantID == "" {
		return nil, errors.New("release postgres: tenant required")
	}
	if current, ok := tenancy.FromContext(ctx); ok && string(current) != tenantID {
		return nil, fmt.Errorf("release postgres: refusing a call for tenant %q under a context scoped to %q",
			tenantID, current)
	}
	return tenancy.WithTenant(ctx, tenancy.ID(tenantID)), nil
}
