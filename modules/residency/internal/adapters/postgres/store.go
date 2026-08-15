// Package postgres persists the Residency context's declarations and
// observed placements in Postgres, making declaration state a property of
// the platform rather than of a process (T-0037, SPEC-0042, ADR-0062). A
// declaration recorded before a kill -9 is exactly what the restarted plane
// cites, and the declaration-history read answers "in force at t" from
// retained effective-dated rows.
//
// Every path is tenant-scoped through platform/db.InTx — there is NO
// un-scoped path in this module and no InTxUnscoped call anywhere in it
// (SPEC-0042 AC5). The platform's single pre-tenancy exemption lives in the
// agent module's token lookups; residency never resolves a tenant, it only
// ever acts within one.
//
// declarations is append-only: a declare or replace INSERTs a new row and
// retains the history — the grant set in the migration (SELECT+INSERT only)
// makes that a property of the database, not of this adapter.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/gitfrok/backend/modules/residency/api"
	"github.com/gitfrok/backend/modules/residency/internal/app"
	"github.com/gitfrok/backend/platform/db"
	"github.com/gitfrok/backend/platform/tenancy"
)

// Store implements the residency persistence port — app.Store — over one
// db.Pool, with one effective-dated addition the port cannot express: the
// declaration in force at any instant (DeclarationAt), which is how the
// retained history stays answerable over a range (SPEC-0042 AC3).
type Store struct {
	pool *db.Pool
}

// New wires the store. A nil pool is a composition bug, not a runtime shape.
func New(pool *db.Pool) *Store {
	if pool == nil {
		panic("residency postgres: pool is required")
	}
	return &Store{pool: pool}
}

// Compile-time proof that the durable adapter fills the same port the
// in-memory store does (ADR-0062 decision 1).
var _ app.Store = (*Store)(nil)

// PutDeclaration appends one declaration row. INSERT only, never an upsert:
// a replace retains the row it supersedes, and the migration's grant set
// denies the UPDATE and DELETE that would do otherwise (SPEC-0042 AC3).
func (s *Store) PutDeclaration(ctx context.Context, d api.Declaration) error {
	ctx = scoped(ctx, d.TenantID)
	return s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO residency.declarations
			   (tenant_id, cloud, region, effective_at, actor_id, chain_seq, record_hash)
			 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			d.TenantID, d.Cloud, d.Region, d.EffectiveAt, d.ActorID, d.ChainSeq, d.RecordHash,
		)
		if err != nil {
			return fmt.Errorf("residency postgres: put declaration: %w", err)
		}
		return nil
	})
}

// Declaration returns the tenant's declaration in force NOW: the row with
// the maximum effective_at <= the current instant. A declaration whose
// effective instant is still in the future is not yet in force. ok is false
// when the tenant has declared nothing (yet).
func (s *Store) Declaration(ctx context.Context, tenantID string) (api.Declaration, bool, error) {
	return s.DeclarationAt(ctx, tenantID, time.Now())
}

// DeclarationAt returns the declaration in force at one instant — the row
// with the maximum effective_at <= at (SPEC-0042 AC3). The served index is
// (tenant_id, effective_at); the history the read walks is retained because
// nothing on this table ever updates or deletes a row.
func (s *Store) DeclarationAt(ctx context.Context, tenantID string, at time.Time) (api.Declaration, bool, error) {
	ctx = scoped(ctx, tenantID)
	var d api.Declaration
	err := s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return scanDeclaration(tx.QueryRow(ctx,
			`SELECT tenant_id, cloud, region, effective_at, actor_id, chain_seq, record_hash
			   FROM residency.declarations
			  WHERE effective_at <= $1
			  ORDER BY effective_at DESC
			  LIMIT 1`, at,
		), &d)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return api.Declaration{}, false, nil
	}
	if err != nil {
		return api.Declaration{}, false, fmt.Errorf("residency postgres: declaration at %s: %w", at, err)
	}
	return d, true, nil
}

// PutObservation records the latest observed placement for one data plane.
// Upsert, not insert: the port's shape is the LATEST placement per data
// plane, so a re-observation converges the row rather than appending one.
func (s *Store) PutObservation(ctx context.Context, tenantID, dataPlaneID, cloud, region string) error {
	ctx = scoped(ctx, tenantID)
	return s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO residency.observations
			   (tenant_id, data_plane_id, cloud, region, observed_at)
			 VALUES ($1, $2, $3, $4, now())
			 ON CONFLICT (tenant_id, data_plane_id) DO UPDATE SET
			   cloud = EXCLUDED.cloud, region = EXCLUDED.region,
			   observed_at = EXCLUDED.observed_at`,
			tenantID, dataPlaneID, cloud, region,
		)
		if err != nil {
			return fmt.Errorf("residency postgres: put observation: %w", err)
		}
		return nil
	})
}

// ObservedPlacements returns every data plane's latest observed placement
// for the tenant, in stable data-plane order — the same shape and order the
// in-memory store yields, so the declaration-time contradiction check walks
// exactly the same set on either store.
func (s *Store) ObservedPlacements(ctx context.Context, tenantID string) ([]api.ObservedPlacement, error) {
	ctx = scoped(ctx, tenantID)
	var out []api.ObservedPlacement
	err := s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT data_plane_id, cloud, region
			   FROM residency.observations
			  ORDER BY data_plane_id ASC`,
		)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var p api.ObservedPlacement
			if err := rows.Scan(&p.DataPlaneID, &p.Cloud, &p.Region); err != nil {
				return err
			}
			out = append(out, p)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("residency postgres: observed placements: %w", err)
	}
	return out, nil
}

// --- scanning --------------------------------------------------------------------

func scanDeclaration(r interface{ Scan(dest ...any) error }, d *api.Declaration) error {
	return r.Scan(&d.TenantID, &d.Cloud, &d.Region, &d.EffectiveAt, &d.ActorID, &d.ChainSeq, &d.RecordHash)
}

// scoped returns ctx carrying tenantID. The adapter scopes from its own
// parameter rather than trusting the caller: the tenant argument is the
// record's own tenancy, and WithTenant on an already-scoped ctx is harmless.
func scoped(ctx context.Context, tenantID string) context.Context {
	return tenancy.WithTenant(ctx, tenancy.ID(tenantID))
}
