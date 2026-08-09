// Package postgres persists Identity&Access credential verifiers.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/gitfrok/backend/modules/identity/api"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
	"github.com/gitfrok/backend/platform/db"
	"github.com/gitfrok/backend/platform/tenancy"
)

// Store keeps tenant-scoped lifecycle operations on db.Pool and uses the
// migration-owned SECURITY DEFINER resolver as its only pre-authentication
// database access (ADR-0043).
type Store struct {
	pool *db.Pool
	pdp  policyapi.DecisionPoint
	keys verifierKeyRing
	now  func() time.Time
}

func New(pool *db.Pool, activeKeyID string, keys map[string][]byte, pdp policyapi.DecisionPoint) *Store {
	if pool == nil {
		panic("identity postgres: pool is required")
	}
	if pdp == nil {
		panic("identity postgres: PDP is required")
	}
	return &Store{pool: pool, pdp: pdp, keys: newVerifierKeyRing(activeKeyID, keys), now: time.Now}
}

func (s *Store) AuthenticatePAT(ctx context.Context, token string) (api.Principal, bool) {
	keyID, verifier, ok := s.keys.patVerifier(token)
	if !ok {
		return api.Principal{}, false
	}
	return s.resolve(ctx, "PAT", keyID, verifier)
}

func (s *Store) AuthenticateSSHKey(ctx context.Context, publicKey, verifierKeyID string) (api.Principal, bool) {
	verifier, ok := s.keys.sshVerifier(publicKey, verifierKeyID)
	if !ok {
		return api.Principal{}, false
	}
	return s.resolve(ctx, "SSH", verifierKeyID, verifier)
}

func (s *Store) resolve(ctx context.Context, kind, keyID, verifier string) (api.Principal, bool) {
	var principal api.Principal
	err := s.pool.InTxUnscoped(ctx, "identity: resolve opaque credential through SECURITY DEFINER", func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT tenant_id, actor_id, roles
			   FROM identity.resolve_active_credential($1, $2, $3)`, kind, keyID, verifier,
		).Scan(&principal.TenantID, &principal.ActorID, &principal.Roles)
	})
	if err != nil {
		return api.Principal{}, false
	}
	principal.Roles = append([]string(nil), principal.Roles...)
	return principal, true
}

func (s *Store) IssuePAT(ctx context.Context, tenantID, actorID, label string, scopes []string, expiresAt *time.Time) (api.PAT, string, error) {
	if err := s.authorizeLifecycle(ctx, tenantID, "identity.pat.issue", actorID); err != nil {
		return api.PAT{}, "", err
	}
	if expiresAt != nil && !expiresAt.After(s.now()) {
		return api.PAT{}, "", errors.New("identity postgres: expiry must be in the future")
	}
	id, token, verifier, err := s.keys.issuePAT()
	if err != nil {
		return api.PAT{}, "", err
	}
	createdAt := s.now().UTC()
	var expiry *time.Time
	if expiresAt != nil {
		value := expiresAt.UTC()
		expiry = &value
	}
	pat := api.PAT{ID: id, TenantID: tenantID, ActorID: actorID, Label: label, Scopes: append([]string(nil), scopes...), CreatedAt: createdAt, ExpiresAt: expiry}
	err = s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO identity.credentials
			   (id, tenant_id, actor_id, credential_kind, key_id, verifier, label, scope_labels, created_at, expires_at)
			 VALUES ($1, $2, $3, 'PAT', $4, $5, $6, $7, $8, $9)`,
			pat.ID, pat.TenantID, pat.ActorID, s.keys.activeKeyID, verifier, pat.Label, pat.Scopes, pat.CreatedAt, pat.ExpiresAt,
		)
		return err
	})
	if err != nil {
		return api.PAT{}, "", fmt.Errorf("identity postgres: issue PAT: %w", err)
	}
	return clonePAT(pat), token, nil
}

func (s *Store) RevokePAT(ctx context.Context, tenantID, actorID, patID string) (api.PAT, error) {
	if err := s.authorizeLifecycle(ctx, tenantID, "identity.pat.revoke", patID); err != nil {
		return api.PAT{}, err
	}
	var pat api.PAT
	err := s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`UPDATE identity.credentials
			    SET revoked_at = $1
			  WHERE id = $2 AND tenant_id = $3 AND actor_id = $4 AND credential_kind = 'PAT' AND revoked_at IS NULL
			  RETURNING id, tenant_id, actor_id, label, scope_labels, created_at, expires_at, revoked_at`,
			s.now().UTC(), patID, tenantID, actorID,
		).Scan(&pat.ID, &pat.TenantID, &pat.ActorID, &pat.Label, &pat.Scopes, &pat.CreatedAt, &pat.ExpiresAt, &pat.RevokedAt)
	})
	if err != nil {
		return api.PAT{}, fmt.Errorf("identity postgres: revoke PAT: %w", err)
	}
	return clonePAT(pat), nil
}

func (s *Store) ListPATs(ctx context.Context, tenantID, actorID string) ([]api.PAT, error) {
	if err := s.authorizeLifecycle(ctx, tenantID, "identity.pat.list", actorID); err != nil {
		return nil, err
	}
	var pats []api.PAT
	err := s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, tenant_id, actor_id, label, scope_labels, created_at, expires_at, revoked_at
			   FROM identity.credentials
			  WHERE tenant_id = $1 AND actor_id = $2 AND credential_kind = 'PAT'
			  ORDER BY created_at ASC`, tenantID, actorID,
		)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var pat api.PAT
			if err := rows.Scan(&pat.ID, &pat.TenantID, &pat.ActorID, &pat.Label, &pat.Scopes, &pat.CreatedAt, &pat.ExpiresAt, &pat.RevokedAt); err != nil {
				return err
			}
			pats = append(pats, clonePAT(pat))
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("identity postgres: list PATs: %w", err)
	}
	return pats, nil
}

func (s *Store) authorizeLifecycle(ctx context.Context, requestedTenant, action, resourceID string) error {
	tenant, err := tenancy.Require(ctx)
	if err != nil {
		return err
	}
	principal, err := api.RequirePrincipal(ctx)
	if err != nil {
		return err
	}
	if string(tenant) != requestedTenant || principal.TenantID != requestedTenant {
		return api.ErrTenantMismatch
	}
	decision, err := s.pdp.Decide(ctx, policyapi.Request{
		TenantID: requestedTenant,
		Subject:  policyapi.Subject{ID: principal.ActorID, TenantID: principal.TenantID, Roles: append([]string(nil), principal.Roles...)},
		Action:   action,
		Resource: policyapi.Resource{Type: "personal_access_token", ID: resourceID},
	})
	if err != nil || !decision.Allowed {
		return api.ErrAuthorizationDenied
	}
	return nil
}

func clonePAT(pat api.PAT) api.PAT {
	pat.Scopes = append([]string(nil), pat.Scopes...)
	if pat.ExpiresAt != nil {
		value := *pat.ExpiresAt
		pat.ExpiresAt = &value
	}
	if pat.RevokedAt != nil {
		value := *pat.RevokedAt
		pat.RevokedAt = &value
	}
	return pat
}

var _ api.Authenticator = (*Store)(nil)
