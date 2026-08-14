// Package memory is the in-memory auditor grant store for dev planes and
// tests (T-0027). It is not durable, exactly like every other in-memory
// adapter; a configured plane composes the Postgres store instead.
package memory

import (
	"cmp"
	"context"
	"slices"
	"sync"
	"time"

	"github.com/gitfrok/backend/modules/identity/api"
)

// GrantStore keeps grant records and their witnessed transitions in
// process. Tenant scoping is a key dimension of every map, mirroring the
// row-level boundary the Postgres store enforces with RLS.
type GrantStore struct {
	mu          sync.Mutex
	grants      map[string]storedGrant // keyed by grant ID
	byRequest   map[string]string      // "tenant|requestID" -> grant ID
	transitions []api.GrantTransition  // in witness order
	transitionK map[string]struct{}    // "tenant|grant|kind" seen
}

type storedGrant struct {
	grant     api.AuditorGrant
	requestID string
}

// NewGrantStore builds an empty store.
func NewGrantStore() *GrantStore {
	return &GrantStore{
		grants:      map[string]storedGrant{},
		byRequest:   map[string]string{},
		transitions: nil,
		transitionK: map[string]struct{}{},
	}
}

func requestKey(tenant, requestID string) string { return tenant + "|" + requestID }

func transitionKey(tenant, grantID string, kind api.GrantTransitionKind) string {
	return tenant + "|" + grantID + "|" + string(kind)
}

// FindByRequest implements app.GrantStore.
func (s *GrantStore) FindByRequest(_ context.Context, tenantID, requestID string) (api.AuditorGrant, bool, error) {
	if requestID == "" {
		return api.AuditorGrant{}, false, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.byRequest[requestKey(tenantID, requestID)]
	if !ok {
		return api.AuditorGrant{}, false, nil
	}
	return clone(s.grants[id].grant), true, nil
}

// Insert implements app.GrantStore.
func (s *GrantStore) Insert(_ context.Context, g api.AuditorGrant, requestID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.grants[g.GrantID]; exists {
		return errDuplicateGrant
	}
	if requestID != "" {
		if _, exists := s.byRequest[requestKey(g.TenantID, requestID)]; exists {
			return errDuplicateGrant
		}
		s.byRequest[requestKey(g.TenantID, requestID)] = g.GrantID
	}
	s.grants[g.GrantID] = storedGrant{grant: clone(g), requestID: requestID}
	return nil
}

// Revoke implements app.GrantStore: only a grant that is still authorizing
// — never revoked and strictly before its expiry — can be revoked.
func (s *GrantStore) Revoke(_ context.Context, tenantID, grantID string, at time.Time) (api.AuditorGrant, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, ok := s.grants[grantID]
	if !ok || stored.grant.TenantID != tenantID {
		return api.AuditorGrant{}, false, nil // not found and cross-tenant are the same answer
	}
	if !stored.grant.RevokedAt.IsZero() || !at.Before(stored.grant.ExpiresAt) {
		return api.AuditorGrant{}, false, nil // already-revoked and expired are the same answer
	}
	stored.grant.RevokedAt = at
	s.grants[grantID] = stored
	return clone(stored.grant), true, nil
}

// List implements app.GrantStore.
func (s *GrantStore) List(_ context.Context, tenantID, auditorPrincipalID string) ([]api.AuditorGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []api.AuditorGrant
	for _, stored := range s.grants {
		g := stored.grant
		if g.TenantID != tenantID {
			continue
		}
		if auditorPrincipalID != "" && g.AuditorPrincipalID != auditorPrincipalID {
			continue
		}
		out = append(out, clone(g))
	}
	slices.SortFunc(out, func(a, b api.AuditorGrant) int {
		if c := a.IssuedAt.Compare(b.IssuedAt); c != 0 {
			return c
		}
		return cmp.Compare(a.GrantID, b.GrantID)
	})
	return out, nil
}

// FindForRead implements app.GrantStore.
func (s *GrantStore) FindForRead(_ context.Context, tenantID, auditorPrincipalID, packID string) ([]api.AuditorGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []api.AuditorGrant
	for _, stored := range s.grants {
		g := stored.grant
		if g.TenantID != tenantID || g.AuditorPrincipalID != auditorPrincipalID {
			continue
		}
		if !namesPack(g.PackIDs, packID) {
			continue
		}
		out = append(out, clone(g))
	}
	slices.SortFunc(out, func(a, b api.AuditorGrant) int {
		if c := a.IssuedAt.Compare(b.IssuedAt); c != 0 {
			return c
		}
		return cmp.Compare(a.GrantID, b.GrantID)
	})
	return out, nil
}

// Transitions implements app.GrantStore.
func (s *GrantStore) Transitions(_ context.Context, tenantID string, from, to time.Time, repositoryID string) ([]api.GrantTransition, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []api.GrantTransition
	for _, t := range s.transitions {
		grant, ok := s.grants[t.GrantID]
		if !ok || grant.grant.TenantID != tenantID {
			continue
		}
		if !from.IsZero() && t.OccurredAt.Before(from) {
			continue
		}
		if !to.IsZero() && t.OccurredAt.After(to) {
			continue
		}
		if repositoryID != "" && t.RepositoryID != "" && t.RepositoryID != repositoryID {
			continue
		}
		out = append(out, cloneTransition(t))
	}
	return out, nil
}

// TransitionRecorded implements app.GrantStore.
func (s *GrantStore) TransitionRecorded(_ context.Context, tenantID, grantID string, kind api.GrantTransitionKind) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.transitionK[transitionKey(tenantID, grantID, kind)]
	return ok, nil
}

// AppendTransition implements app.GrantStore.
func (s *GrantStore) AppendTransition(_ context.Context, t api.GrantTransition) (bool, error) {
	tenant := ""
	s.mu.Lock()
	defer s.mu.Unlock()
	if stored, ok := s.grants[t.GrantID]; ok {
		tenant = stored.grant.TenantID
	}
	key := transitionKey(tenant, t.GrantID, t.Kind)
	if _, exists := s.transitionK[key]; exists {
		return false, nil
	}
	s.transitionK[key] = struct{}{}
	s.transitions = append(s.transitions, cloneTransition(t))
	return true, nil
}

func namesPack(packs []string, packID string) bool {
	for _, p := range packs {
		if p == packID {
			return true
		}
	}
	return false
}

func clone(g api.AuditorGrant) api.AuditorGrant {
	g.PackIDs = append([]string(nil), g.PackIDs...)
	return g
}

func cloneTransition(t api.GrantTransition) api.GrantTransition { return t }

// errDuplicateGrant is the store's refusal of a second grant under one
// request ID; the service maps it onto the replay path.
var errDuplicateGrant = errDup{}

type errDup struct{}

func (errDup) Error() string { return "identity grants: duplicate issue under request ID" }
