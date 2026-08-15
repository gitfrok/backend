// Package postgres persists the Agent context's enrolment tokens and data-plane
// registry in Postgres, making enrolment state a property of the platform rather
// than of a process (T-0036, SPEC-0042, ADR-0062). A spent token stays spent
// across a kill -9 and restart; the staleness machine reads durable liveness,
// never process uptime.
//
// Every path is tenant-scoped through platform/db.InTx except ONE enumerated
// exemption (SPEC-0042 AC5): enrolment resolves the tenant FROM the token, so
// the hash-keyed lookup and claim run through the migration's SECURITY DEFINER
// functions inside a single InTxUnscoped call before any tenant is known. The
// tenant for everything after is bound from the returned row.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/gitfrok/backend/modules/agent/internal/app"
	"github.com/gitfrok/backend/modules/agent/internal/domain"
	"github.com/gitfrok/backend/platform/db"
	"github.com/gitfrok/backend/platform/tenancy"
)

// unscopedTokenReason is the ONE stated escape from tenant scoping this
// adapter makes (SPEC-0042 AC5). It covers both exempt function calls: they
// are the two halves of the same act — resolving and claiming a credential
// whose owner tenant is only known once the row is read.
const unscopedTokenReason = "agent: resolve enrolment token by hash before tenant is known (SPEC-0042 AC5)"

// Store implements both agent persistence ports — app.TokenStore and
// app.RegistryStore — over one db.Pool. One type rather than two because both
// halves live in one migration, one schema and one isolation story.
type Store struct {
	pool *db.Pool
}

// New wires the store. A nil pool is a composition bug, not a runtime shape.
func New(pool *db.Pool) *Store {
	if pool == nil {
		panic("agent postgres: pool is required")
	}
	return &Store{pool: pool}
}

// Compile-time proof that the durable adapter fills the same ports the
// in-memory store does (ADR-0062 decision 1).
var (
	_ app.TokenStore    = (*Store)(nil)
	_ app.RegistryStore = (*Store)(nil)
)

// --- TokenStore ------------------------------------------------------------------

// PutToken persists one issued token — its hash, never the secret.
func (s *Store) PutToken(ctx context.Context, t domain.Token) error {
	ctx = scoped(ctx, t.TenantID)
	return s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO agent.enrolment_tokens
			   (id, tenant_id, issued_by, token_hash, issued_at, expires_at, spent_at, data_plane_id, revoked_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			t.ID, t.TenantID, t.IssuedBy, t.TokenHash[:], t.IssuedAt, t.ExpiresAt,
			nullTime(t.SpentAt), t.DataPlaneID, nullTime(t.RevokedAt),
		)
		if err != nil {
			return fmt.Errorf("agent postgres: put token: %w", err)
		}
		return nil
	})
}

// TokenByHash resolves a presented secret's hash to its record. This is the
// exempt path: the tenant is unknown until the row exists, so the lookup runs
// through agent.lookup_enrolment_token — UNIQUE hash column, at most one row —
// inside the one InTxUnscoped call this adapter is allowed.
func (s *Store) TokenByHash(ctx context.Context, hash [32]byte) (domain.Token, bool, error) {
	var tok domain.Token
	err := s.pool.InTxUnscoped(ctx, unscopedTokenReason, func(ctx context.Context, tx pgx.Tx) error {
		return scanToken(tx.QueryRow(ctx,
			`SELECT id, tenant_id, issued_by, token_hash,
			        issued_at, expires_at, spent_at, data_plane_id, revoked_at
			   FROM agent.lookup_enrolment_token($1)`, hash[:],
		), &tok)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Token{}, false, nil
	}
	if err != nil {
		return domain.Token{}, false, fmt.Errorf("agent postgres: token by hash: %w", err)
	}
	return tok, true, nil
}

// TokenByID resolves one token within its tenant; another tenant's ID is a
// miss — RLS and the WHERE clause agree, one coarse shape (SPEC-0038 AC9).
func (s *Store) TokenByID(ctx context.Context, tenantID, tokenID string) (domain.Token, bool, error) {
	ctx = scoped(ctx, tenantID)
	var tok domain.Token
	err := s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return scanToken(tx.QueryRow(ctx,
			`SELECT id, tenant_id, issued_by, token_hash,
			        issued_at, expires_at, spent_at, data_plane_id, revoked_at
			   FROM agent.enrolment_tokens
			  WHERE id = $1`, tokenID,
		), &tok)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Token{}, false, nil
	}
	if err != nil {
		return domain.Token{}, false, fmt.Errorf("agent postgres: token by id: %w", err)
	}
	return tok, true, nil
}

// TokensByTenant lists the tenant's tokens, oldest first.
func (s *Store) TokensByTenant(ctx context.Context, tenantID string) ([]domain.Token, error) {
	ctx = scoped(ctx, tenantID)
	var out []domain.Token
	err := s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, tenant_id, issued_by, token_hash,
			        issued_at, expires_at, spent_at, data_plane_id, revoked_at
			   FROM agent.enrolment_tokens
			  ORDER BY issued_at ASC`,
		)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var tok domain.Token
			if err := scanRow(rows, &tok); err != nil {
				return err
			}
			out = append(out, tok)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("agent postgres: tokens by tenant: %w", err)
	}
	return out, nil
}

// ClaimToken is the single-use gate (SPEC-0038 AC1) made atomic: ONE
// conditional UPDATE inside agent.claim_enrolment_token — never a
// select-then-update — so concurrent presenters cannot both spend the token.
// claimed is false for anything the guards refuse: spent, revoked, expired
// or unknown. The function never overwrites a recorded data_plane_id, so a
// released claim re-binds its retry to the SAME identity (ADR-0060).
//
// The expiry guard and the spend instant are SERVER-SIDE now() — the
// identity module's resolve_active_credential precedent (ADR-0043) — so the
// clock parameter is interface compatibility with the memory store only;
// the database never trusts a caller-supplied time here.
func (s *Store) ClaimToken(ctx context.Context, hash [32]byte, dataPlaneID string, _ time.Time) (domain.Token, bool, error) {
	var tok domain.Token
	err := s.pool.InTxUnscoped(ctx, unscopedTokenReason, func(ctx context.Context, tx pgx.Tx) error {
		return scanToken(tx.QueryRow(ctx,
			`SELECT id, tenant_id, issued_by, token_hash,
			        issued_at, expires_at, spent_at, data_plane_id, revoked_at
			   FROM agent.claim_enrolment_token($1, $2)`, hash[:], dataPlaneID,
		), &tok)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Token{}, false, nil
	}
	if err != nil {
		return domain.Token{}, false, fmt.Errorf("agent postgres: claim token: %w", err)
	}
	return tok, true, nil
}

// RevokeToken revokes an unspent token. Unknown tokens and spent tokens are
// errors with the shared sentinels: a spent token's enrolment already
// happened, and revoking it would change nothing about the plane it minted.
func (s *Store) RevokeToken(ctx context.Context, tenantID, tokenID string, now time.Time) error {
	if err := s.tokenTransition(ctx, tenantID, tokenID, "revoke token", func(tx pgx.Tx) error {
		var spent *time.Time
		if err := tx.QueryRow(ctx,
			`SELECT spent_at FROM agent.enrolment_tokens WHERE id = $1`, tokenID,
		).Scan(&spent); err != nil {
			return err
		}
		if spent != nil {
			return domain.ErrTokenSpent
		}
		n, err := tx.Exec(ctx,
			`UPDATE agent.enrolment_tokens SET revoked_at = $1 WHERE id = $2 AND revoked_at IS NULL`,
			now, tokenID,
		)
		if err != nil {
			return err
		}
		if n.RowsAffected() != 1 {
			return domain.ErrStoreNotFound
		}
		return nil
	}); err != nil {
		return err
	}
	return nil
}

// ReleaseClaim is the AC6 transition (SPEC-0042): an issuance failure un-spends
// the token so the presenter can retry, but keeps the recorded data_plane_id so
// the retry re-binds to the SAME identity — one token never mints two data
// planes (ADR-0060). Runs tenant-scoped: the tenant is known from the token by
// the time anything calls this, so it is NOT a third exempt path.
func (s *Store) ReleaseClaim(ctx context.Context, tenantID, tokenID string) error {
	return s.tokenTransition(ctx, tenantID, tokenID, "release claim", func(tx pgx.Tx) error {
		n, err := tx.Exec(ctx,
			`UPDATE agent.enrolment_tokens SET spent_at = NULL WHERE id = $1 AND spent_at IS NOT NULL`,
			tokenID,
		)
		if err != nil {
			return err
		}
		if n.RowsAffected() != 1 {
			return domain.ErrStoreNotFound
		}
		return nil
	})
}

// tokenTransition runs one token mutation tenant-scoped, mapping a miss under
// RLS to the shared not-found sentinel.
func (s *Store) tokenTransition(ctx context.Context, tenantID, tokenID, op string, fn func(pgx.Tx) error) error {
	ctx = scoped(ctx, tenantID)
	err := s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return fn(tx)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrStoreNotFound
	}
	if err != nil && !errors.Is(err, domain.ErrTokenSpent) && !errors.Is(err, domain.ErrStoreNotFound) {
		return fmt.Errorf("agent postgres: %s: %w", op, err)
	}
	return err
}

// --- RegistryStore ---------------------------------------------------------------

// PutDataPlane stores or updates one registry record. Upsert, not insert: a
// released claim's retry writes the SAME plane identity again (AC6), and the
// record must converge rather than collide.
func (s *Store) PutDataPlane(ctx context.Context, d domain.DataPlane) error {
	ctx = scoped(ctx, d.TenantID)
	return s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO agent.data_planes
			   (tenant_id, id, cloud, region, agent_version, k8s_version, capabilities,
			    enrolled_at, last_seen_at, current_certificate_id, certificate_expires_at, revoked_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
			 ON CONFLICT (tenant_id, id) DO UPDATE SET
			   cloud = EXCLUDED.cloud, region = EXCLUDED.region,
			   agent_version = EXCLUDED.agent_version, k8s_version = EXCLUDED.k8s_version,
			   capabilities = EXCLUDED.capabilities, enrolled_at = EXCLUDED.enrolled_at,
			   last_seen_at = EXCLUDED.last_seen_at,
			   current_certificate_id = EXCLUDED.current_certificate_id,
			   certificate_expires_at = EXCLUDED.certificate_expires_at,
			   revoked_at = EXCLUDED.revoked_at`,
			d.TenantID, d.ID, d.Cloud, d.Region, d.AgentVersion, d.K8sVersion, capsOf(d),
			d.EnrolledAt, d.LastSeenAt, d.CurrentCertificateID, nullTime(d.CertificateExpiresAt), nullTime(d.RevokedAt),
		)
		if err != nil {
			return fmt.Errorf("agent postgres: put data plane: %w", err)
		}
		return nil
	})
}

// DataPlane resolves one record within its tenant.
func (s *Store) DataPlane(ctx context.Context, tenantID, id string) (domain.DataPlane, bool, error) {
	ctx = scoped(ctx, tenantID)
	var d domain.DataPlane
	err := s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return scanPlane(tx.QueryRow(ctx,
			`SELECT tenant_id, id, cloud, region, agent_version, k8s_version, capabilities,
			        enrolled_at, last_seen_at, current_certificate_id, certificate_expires_at, revoked_at
			   FROM agent.data_planes
			  WHERE id = $1`, id,
		), &d)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.DataPlane{}, false, nil
	}
	if err != nil {
		return domain.DataPlane{}, false, fmt.Errorf("agent postgres: data plane: %w", err)
	}
	return d, true, nil
}

// DataPlanesByTenant lists the tenant's registry records, oldest first.
func (s *Store) DataPlanesByTenant(ctx context.Context, tenantID string) ([]domain.DataPlane, error) {
	ctx = scoped(ctx, tenantID)
	var out []domain.DataPlane
	err := s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT tenant_id, id, cloud, region, agent_version, k8s_version, capabilities,
			        enrolled_at, last_seen_at, current_certificate_id, certificate_expires_at, revoked_at
			   FROM agent.data_planes
			  ORDER BY enrolled_at ASC`,
		)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var d domain.DataPlane
			if err := scanPlaneRow(rows, &d); err != nil {
				return err
			}
			out = append(out, d)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("agent postgres: data planes by tenant: %w", err)
	}
	return out, nil
}

// MarkSeen records contact for the staleness window (SPEC-0038 AC8). This
// column is the durable liveness the machine recomputes from after a restart.
func (s *Store) MarkSeen(ctx context.Context, tenantID, id string, now time.Time) error {
	return s.planeTransition(ctx, tenantID, id, "mark seen",
		`UPDATE agent.data_planes SET last_seen_at = $1 WHERE id = $2`, now, id)
}

// SetCertificate records the certificate the data plane currently holds.
func (s *Store) SetCertificate(ctx context.Context, tenantID, id, certID string, expiresAt time.Time) error {
	return s.planeTransition(ctx, tenantID, id, "set certificate",
		`UPDATE agent.data_planes SET current_certificate_id = $1, certificate_expires_at = $2 WHERE id = $3`,
		certID, expiresAt, id)
}

// RevokeDataPlane marks one record revoked; admission reads it on the next
// connection — durably, so a restart changes nothing about the refusal.
func (s *Store) RevokeDataPlane(ctx context.Context, tenantID, id string, now time.Time) error {
	return s.planeTransition(ctx, tenantID, id, "revoke data plane",
		`UPDATE agent.data_planes SET revoked_at = $1 WHERE id = $2`, now, id)
}

// planeTransition runs one registry mutation tenant-scoped; a miss — unknown
// or another tenant's — is the shared not-found sentinel.
func (s *Store) planeTransition(ctx context.Context, tenantID, id, op, query string, args ...any) error {
	ctx = scoped(ctx, tenantID)
	return s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		n, err := tx.Exec(ctx, query, args...)
		if err != nil {
			return fmt.Errorf("agent postgres: %s: %w", op, err)
		}
		if n.RowsAffected() != 1 {
			return domain.ErrStoreNotFound
		}
		return nil
	})
}

// --- scanning --------------------------------------------------------------------

type rowScanner interface {
	Scan(dest ...any) error
}

func scanToken(r rowScanner, tok *domain.Token) error {
	var hash []byte
	var spent, revoked *time.Time
	if err := r.Scan(&tok.ID, &tok.TenantID, &tok.IssuedBy, &hash,
		&tok.IssuedAt, &tok.ExpiresAt, &spent, &tok.DataPlaneID, &revoked); err != nil {
		return err
	}
	copy(tok.TokenHash[:], hash)
	tok.SpentAt = timeOrZero(spent)
	tok.RevokedAt = timeOrZero(revoked)
	return nil
}

func scanPlane(r rowScanner, d *domain.DataPlane) error {
	var expires, revoked *time.Time
	if err := r.Scan(&d.TenantID, &d.ID, &d.Cloud, &d.Region, &d.AgentVersion, &d.K8sVersion, &d.Capabilities,
		&d.EnrolledAt, &d.LastSeenAt, &d.CurrentCertificateID, &expires, &revoked); err != nil {
		return err
	}
	d.CertificateExpiresAt = timeOrZero(expires)
	d.RevokedAt = timeOrZero(revoked)
	return nil
}

// scanRow and scanPlaneRow adapt the two pgx row shapes onto one scanner.
func scanRow(rows pgx.Rows, tok *domain.Token) error        { return scanToken(rows, tok) }
func scanPlaneRow(rows pgx.Rows, d *domain.DataPlane) error { return scanPlane(rows, d) }

// scoped returns ctx carrying tenantID. The adapter scopes from its own
// parameter rather than trusting the caller: the tenant argument is the
// record's own tenancy, and WithTenant on an already-scoped ctx is harmless.
func scoped(ctx context.Context, tenantID string) context.Context {
	return tenancy.WithTenant(ctx, tenancy.ID(tenantID))
}

func nullTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}

func timeOrZero(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}

func capsOf(d domain.DataPlane) []string {
	if d.Capabilities == nil {
		return []string{}
	}
	return d.Capabilities
}
