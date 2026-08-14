// Package memory is the in-memory residency store: the same tenant-scoped shape a durable
// adapter will hold, for dev planes and tests (T-0033). Swapping stores is a composition-line
// change (invariant 13).
package memory

import (
	"cmp"
	"context"
	"slices"
	"sync"

	"github.com/gitfrok/backend/modules/residency/api"
	"github.com/gitfrok/backend/platform/tenancy"
)

// Store is the tenant-keyed residency state: one declaration in force per tenant and the
// latest observed placement per data plane. Every read and write is tenant-scoped
// (SPEC-0001): a lookup under one tenant's scope can never return another tenant's record,
// which is the store-side half of AC8.
type Store struct {
	mu           sync.RWMutex
	declarations map[string]api.Declaration
	observations map[string]map[string]observation
}

type observation struct {
	dataPlaneID string
	cloud       string
	region      string
}

// New builds an empty store.
func New() *Store {
	return &Store{
		declarations: map[string]api.Declaration{},
		observations: map[string]map[string]observation{},
	}
}

// scoped enforces the tenant scope the context carries against the requested tenant: a
// mismatch — or a missing scope — is refused before any state is touched (SPEC-0001,
// invariant 1).
func scoped(ctx context.Context, tenantID string) bool {
	t, ok := tenancy.FromContext(ctx)
	return ok && string(t) == tenantID && tenantID != ""
}

// PutDeclaration stores the tenant's declaration in force.
func (s *Store) PutDeclaration(ctx context.Context, d api.Declaration) error {
	if !scoped(ctx, d.TenantID) {
		return api.ErrResidencyUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.declarations[d.TenantID] = d
	return nil
}

// Declaration returns the tenant's declaration in force; ok is false when none exists.
func (s *Store) Declaration(ctx context.Context, tenantID string) (api.Declaration, bool, error) {
	if !scoped(ctx, tenantID) {
		return api.Declaration{}, false, api.ErrResidencyUnavailable
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.declarations[tenantID]
	return d, ok, nil
}

// PutObservation records the latest observed placement for one data plane.
func (s *Store) PutObservation(ctx context.Context, tenantID, dataPlaneID, cloud, region string) error {
	if !scoped(ctx, tenantID) {
		return api.ErrResidencyUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	planes, ok := s.observations[tenantID]
	if !ok {
		planes = map[string]observation{}
		s.observations[tenantID] = planes
	}
	planes[dataPlaneID] = observation{dataPlaneID: dataPlaneID, cloud: cloud, region: region}
	return nil
}

// ObservedPlacements returns every data plane's latest observed placement for the tenant,
// in stable order. The declaration-time contradiction check walks exactly this set (AC3).
func (s *Store) ObservedPlacements(ctx context.Context, tenantID string) ([]api.ObservedPlacement, error) {
	if !scoped(ctx, tenantID) {
		return nil, api.ErrResidencyUnavailable
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	planes := s.observations[tenantID]
	out := make([]api.ObservedPlacement, 0, len(planes))
	for _, o := range planes {
		out = append(out, api.ObservedPlacement{DataPlaneID: o.dataPlaneID, Cloud: o.cloud, Region: o.region})
	}
	slices.SortFunc(out, func(a, b api.ObservedPlacement) int { return cmp.Compare(a.DataPlaneID, b.DataPlaneID) })
	return out, nil
}
