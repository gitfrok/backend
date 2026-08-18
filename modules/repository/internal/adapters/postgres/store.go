// Package postgres persists the Repository context's registry — the record of which repositories
// exist — making it a property of the platform rather than of a process (T-0053, SPEC-0052,
// ADR-0071).
//
// This is the adapter the context has been owed since T-0004. Until it landed, the registry was a
// map that emptied on restart while the repositories themselves were bare git repositories on
// block volumes that did not, and nothing reconciled the two. That was survivable only because no
// surface read the registry as a list: a list that omits a repository asserts it does not exist.
//
// Every path is tenant-scoped through platform/db.InTx — there is no unscoped path in this module.
// RLS is the backstop, not the mechanism: the transaction names the tenant it was asked about and
// the policy then admits exactly those rows.
package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/gitfrok/backend/modules/repository/internal/app"
	"github.com/gitfrok/backend/modules/repository/internal/domain"
	"github.com/gitfrok/backend/platform/db"
	"github.com/gitfrok/backend/platform/tenancy"
)

// Store implements the Repository persistence port — app.Store — over one db.Pool.
type Store struct {
	pool *db.Pool
}

// New wires the store. A nil pool is a composition bug, not a runtime shape.
func New(pool *db.Pool) *Store {
	if pool == nil {
		panic("repository postgres: pool is required")
	}
	return &Store{pool: pool}
}

// Compile-time proof that the durable adapter fills the same port the in-memory store does
// (ADR-0071 decision 1, following ADR-0062).
var _ app.Store = (*Store)(nil)

// Save registers a repository, or converges the row if it is already registered.
//
// An upsert rather than an insert: the aggregate's identity is (tenant, repo), and re-registering
// the same repository with the same name is the same fact stated twice. It is not a rename path —
// nothing in the product renames a repository yet (that is PR-30, Tier C) — but converging on
// name here means a replayed create cannot fail on a duplicate key and leave the caller unsure
// whether the repository exists.
func (s *Store) Save(ctx context.Context, r domain.Repository) error {
	ctx, err := scoped(ctx, string(r.Tenant))
	if err != nil {
		return err
	}
	return s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO repo.repositories (tenant_id, repo_id, name)
			 VALUES ($1, $2, $3)
			 ON CONFLICT (tenant_id, repo_id) DO UPDATE SET name = EXCLUDED.name`,
			string(r.Tenant), string(r.ID), r.Name,
		)
		if err != nil {
			return fmt.Errorf("repository postgres: save %s: %w", r.ID, err)
		}
		return nil
	})
}

// Load reads one repository within one tenant.
//
// A repository belonging to another tenant is reported as ABSENT, not as forbidden — the caller
// must not learn that it exists (invariant 1, SPEC-0001). RLS makes that true at the database
// rather than by a check here that could be forgotten.
func (s *Store) Load(ctx context.Context, tenant domain.TenantID, id domain.RepoID) (domain.Repository, error) {
	ctx, err := scoped(ctx, string(tenant))
	if err != nil {
		return domain.Repository{}, err
	}
	var r domain.Repository
	err = s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var tenantID, repoID, name string
		if err := tx.QueryRow(ctx,
			`SELECT tenant_id, repo_id, name FROM repo.repositories WHERE repo_id = $1`, string(id),
		).Scan(&tenantID, &repoID, &name); err != nil {
			return err
		}
		r = domain.Repository{Tenant: domain.TenantID(tenantID), ID: domain.RepoID(repoID), Name: name}
		return nil
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Repository{}, fmt.Errorf("repository postgres: repository %s not found", id)
	}
	if err != nil {
		return domain.Repository{}, fmt.Errorf("repository postgres: load %s: %w", id, err)
	}
	return r, nil
}

// Candidates returns up to limit of one tenant's repositories whose ID sorts after afterID.
//
// It answers nothing about authorization. Which candidates the caller may see is asked above this
// port, so the adapter cannot become a decision point by accident (invariant 2) — and because the
// query is RLS-scoped, another tenant's repositories are not filtered out here, they are never
// visible to the statement at all.
func (s *Store) Candidates(ctx context.Context, tenant domain.TenantID, afterID domain.RepoID, limit int) ([]domain.Repository, error) {
	ctx, err := scoped(ctx, string(tenant))
	if err != nil {
		return nil, err
	}
	if limit <= 0 {
		return nil, nil
	}
	var out []domain.Repository
	err = s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT tenant_id, repo_id, name
			   FROM repo.repositories
			  WHERE repo_id > $1
			  ORDER BY repo_id ASC
			  LIMIT $2`, string(afterID), limit,
		)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var tenantID, repoID, name string
			if err := rows.Scan(&tenantID, &repoID, &name); err != nil {
				return err
			}
			out = append(out, domain.Repository{
				Tenant: domain.TenantID(tenantID), ID: domain.RepoID(repoID), Name: name,
			})
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("repository postgres: candidates after %q: %w", afterID, err)
	}
	return out, nil
}

// scoped returns ctx carrying tenantID — and REFUSES when the context already names a different
// tenant.
//
// The refusal is here because RLS cannot make it: the adapter scopes the transaction from its own
// argument, so `SET LOCAL app.tenant_id` names the tenant that was asked for and the policy then
// admits exactly the rows that call requested. RLS protects one tenant's rows from a transaction
// scoped to another; it has nothing to say about a transaction scoped to the tenant in the
// request. That mismatch is what a caller must never be able to express, so it is refused before
// any database work — the same posture the residency adapter takes (SPEC-0042 AC5).
func scoped(ctx context.Context, tenantID string) (context.Context, error) {
	if tenantID == "" {
		return nil, errors.New("repository postgres: tenant required")
	}
	if current, ok := tenancy.FromContext(ctx); ok && string(current) != tenantID {
		return nil, fmt.Errorf("repository postgres: refusing a call for tenant %q under a context scoped to %q",
			tenantID, current)
	}
	return tenancy.WithTenant(ctx, tenancy.ID(tenantID)), nil
}
