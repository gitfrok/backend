// Package memory is the Agent context's in-process store: the composition a dev plane and
// every test run on. Swapping to a durable adapter is a change to the module's composition
// root and nothing else (ADR-0025).
//
// Tenant isolation here is by construction of the keys: every lookup takes the tenant as a
// parameter and never scans across tenants, so a cross-tenant read is structurally a
// not-found — the same coarse shape the api surface promises (SPEC-0038 AC9).
package memory

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/gitfrok/backend/modules/agent/internal/domain"
)

// Store holds enrolment tokens and the data-plane registry in process.
type Store struct {
	mu           sync.Mutex
	tokensByHash map[[32]byte]domain.Token
	tokensByID   map[string]domain.Token
	planes       map[string]domain.DataPlane // key: tenant + "/" + data-plane ID
}

// New builds an empty store.
func New() *Store {
	return &Store{
		tokensByHash: make(map[[32]byte]domain.Token),
		tokensByID:   make(map[string]domain.Token),
		planes:       make(map[string]domain.DataPlane),
	}
}

func planeKey(tenantID, id string) string { return tenantID + "/" + id }

// PutToken stores one issued token.
func (s *Store) PutToken(_ context.Context, t domain.Token) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokensByHash[t.TokenHash] = t
	s.tokensByID[t.ID] = t
	return nil
}

// TokenByHash resolves a presented secret's hash to its record.
func (s *Store) TokenByHash(_ context.Context, hash [32]byte) (domain.Token, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokensByHash[hash]
	return t, ok, nil
}

// TokenByID resolves one token within its tenant.
func (s *Store) TokenByID(_ context.Context, tenantID, tokenID string) (domain.Token, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokensByID[tokenID]
	if !ok || t.TenantID != tenantID {
		return domain.Token{}, false, nil
	}
	return t, true, nil
}

// TokensByTenant lists the tenant's tokens, oldest first.
func (s *Store) TokensByTenant(_ context.Context, tenantID string) ([]domain.Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []domain.Token
	for _, t := range s.tokensByID {
		if t.TenantID == tenantID {
			out = append(out, t)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IssuedAt.Before(out[j].IssuedAt) })
	return out, nil
}

// ClaimToken is the single-use gate (SPEC-0038 AC1): under the store lock it transitions an
// unspent, unexpired, unrevoked token to spent and names the data plane it minted. claimed
// is false — with the record's current state — for any token that cannot be spent, so a
// concurrent presenter or a retry after a partial enrolment loses here, deterministically.
func (s *Store) ClaimToken(_ context.Context, hash [32]byte, dataPlaneID string, now time.Time) (domain.Token, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokensByHash[hash]
	if !ok {
		return domain.Token{}, false, nil
	}
	if reason := t.PresentOutcome(now); reason != "" {
		return t, false, nil
	}
	t.SpentAt = now
	t.DataPlaneID = dataPlaneID
	s.tokensByHash[hash] = t
	s.tokensByID[t.ID] = t
	return t, true, nil
}

// RevokeToken revokes an unspent token. Unknown tokens and spent tokens are errors: a spent
// token's enrolment already happened, and revoking it would change nothing about the data
// plane it minted.
func (s *Store) RevokeToken(_ context.Context, tenantID, tokenID string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokensByID[tokenID]
	if !ok || t.TenantID != tenantID {
		return errNotFound
	}
	if t.Spent() {
		return errSpent
	}
	t.RevokedAt = now
	s.tokensByID[t.ID] = t
	s.tokensByHash[t.TokenHash] = t
	return nil
}

// PutDataPlane stores or updates one registry record.
func (s *Store) PutDataPlane(_ context.Context, d domain.DataPlane) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.planes[planeKey(d.TenantID, d.ID)] = d
	return nil
}

// DataPlane resolves one record within its tenant.
func (s *Store) DataPlane(_ context.Context, tenantID, id string) (domain.DataPlane, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.planes[planeKey(tenantID, id)]
	return d, ok, nil
}

// DataPlanesByTenant lists the tenant's registry records, oldest first.
func (s *Store) DataPlanesByTenant(_ context.Context, tenantID string) ([]domain.DataPlane, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []domain.DataPlane
	for _, d := range s.planes {
		if d.TenantID == tenantID {
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].EnrolledAt.Before(out[j].EnrolledAt) })
	return out, nil
}

// MarkSeen records contact for the staleness window (SPEC-0038 AC8).
func (s *Store) MarkSeen(_ context.Context, tenantID, id string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.planes[planeKey(tenantID, id)]
	if !ok {
		return errNotFound
	}
	d.LastSeenAt = now
	s.planes[planeKey(tenantID, id)] = d
	return nil
}

// SetCertificate records the certificate the data plane currently holds.
func (s *Store) SetCertificate(_ context.Context, tenantID, id, certID string, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.planes[planeKey(tenantID, id)]
	if !ok {
		return errNotFound
	}
	d.CurrentCertificateID = certID
	d.CertificateExpiresAt = expiresAt
	s.planes[planeKey(tenantID, id)] = d
	return nil
}

// RevokeDataPlane marks one record revoked; admission reads it on the next connection.
func (s *Store) RevokeDataPlane(_ context.Context, tenantID, id string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.planes[planeKey(tenantID, id)]
	if !ok {
		return errNotFound
	}
	d.RevokedAt = now
	s.planes[planeKey(tenantID, id)] = d
	return nil
}
