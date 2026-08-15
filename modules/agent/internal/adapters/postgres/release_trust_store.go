package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/gitfrok/backend/modules/agent/api"
)

// The durable RELEASE trust distribution registry (T-0041, SPEC-0045 AC2):
// the release trust bundle revision each data plane has applied, keyed by
// data_plane_id (ADR-0065). Every path is tenant-scoped — the plane's
// applied revision is only ever read or written under the tenant the plane
// belongs to — so this half of the store takes NO unscoped exemption
// (unlike the enrolment token lookup of SPEC-0042 AC5). The table is the
// 0002 migration's agent.release_trust_plane_state, RLS-enforced; a
// different artifact from every CA-trust-bundle surface (SPEC-0045's
// two-bundles note).

// Compile-time proof that the durable adapter fills the same port the
// in-memory harness registry does.
var _ api.ReleaseTrustAppliedRegistry = (*Store)(nil)

// RecordReleaseTrustApplied upserts the plane's newest applied release
// trust bundle revision. The revision only moves FORWARD — a late or
// replayed ack for an older revision never regresses a plane's recorded
// convergence (the reconcile channel delivers the newest state; the ledger
// reflects it).
func (s *Store) RecordReleaseTrustApplied(ctx context.Context, tenantID, dataPlaneID string, revision int64) error {
	if tenantID == "" || dataPlaneID == "" {
		return errors.New("agent postgres: tenant and data plane are required")
	}
	ctx = scoped(ctx, tenantID)
	return s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO agent.release_trust_plane_state
			   (tenant_id, data_plane_id, applied_revision, applied_at)
			 VALUES ($1, $2, $3, $4)
			 ON CONFLICT (tenant_id, data_plane_id)
			 DO UPDATE SET applied_revision = GREATEST(agent.release_trust_plane_state.applied_revision, EXCLUDED.applied_revision),
			               applied_at       = EXCLUDED.applied_at`,
			tenantID, dataPlaneID, revision, time.Now(),
		)
		if err != nil {
			return fmt.Errorf("agent postgres: record release trust applied: %w", err)
		}
		return nil
	})
}

// ReleaseTrustApplied reads the revision one plane has applied. ok is false
// when the plane has never acknowledged a release trust bundle — a joiner
// that has not converged yet, rendered as "not applied", never as zero.
func (s *Store) ReleaseTrustApplied(ctx context.Context, tenantID, dataPlaneID string) (int64, bool, error) {
	ctx = scoped(ctx, tenantID)
	var rev int64
	err := s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT applied_revision FROM agent.release_trust_plane_state
			  WHERE tenant_id = $1 AND data_plane_id = $2`,
			tenantID, dataPlaneID,
		).Scan(&rev)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("agent postgres: read release trust applied: %w", err)
	}
	return rev, true, nil
}
