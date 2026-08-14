// Package memory is the Rollout context's in-process store: the composition every dev plane
// and test runs on. Swapping to a durable adapter is a change to the module's composition root
// and nothing else (ADR-0025).
//
// Tenant isolation is by construction of the keys: every lookup takes the tenant as a
// parameter and never scans across tenants, so a cross-tenant read is structurally a
// not-found — the same coarse shape the api surface promises.
package memory

import (
	"context"
	"sync"

	"github.com/gitfrok/backend/modules/rollout/api"
)

// Store holds rollout records and version windows in process, keyed tenant + data plane.
type Store struct {
	mu      sync.Mutex
	rollout map[string]api.Rollout       // key: tenant + "/" + data-plane ID
	windows map[string]api.VersionWindow // key: tenant + "/" + data-plane ID
}

// New builds an empty store.
func New() *Store {
	return &Store{
		rollout: make(map[string]api.Rollout),
		windows: make(map[string]api.VersionWindow),
	}
}

func key(tenantID, dataPlaneID string) string { return tenantID + "/" + dataPlaneID }

// PutRollout stores or replaces the data plane's current rollout record.
func (s *Store) PutRollout(_ context.Context, r api.Rollout) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rollout[key(r.TenantID, r.DataPlaneID)] = r
	return nil
}

// Rollout resolves the data plane's current rollout within its tenant.
func (s *Store) Rollout(_ context.Context, tenantID, dataPlaneID string) (api.Rollout, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.rollout[key(tenantID, dataPlaneID)]
	return r, ok, nil
}

// PutWindow stores the data plane's AC7 pin/defer window.
func (s *Store) PutWindow(_ context.Context, tenantID, dataPlaneID string, w api.VersionWindow) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.windows[key(tenantID, dataPlaneID)] = w
	return nil
}

// Window resolves the data plane's AC7 window within its tenant.
func (s *Store) Window(_ context.Context, tenantID, dataPlaneID string) (api.VersionWindow, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	w, ok := s.windows[key(tenantID, dataPlaneID)]
	return w, ok, nil
}
