package memory

import (
	"context"
	"slices"
	"sync"

	"github.com/gitfrok/backend/modules/identity/api"
)

// Directory is the in-memory tenant membership view for dev planes and tests.
// It holds the same shape the Postgres one reads: principals with their
// current roles, scoped to one tenant.
type Directory struct {
	mu     sync.Mutex
	member map[string]map[string][]string // tenant -> actor -> roles
}

// NewDirectory builds an empty in-memory directory.
func NewDirectory() *Directory {
	return &Directory{member: map[string]map[string][]string{}}
}

// Put records one actor's memberships, replacing any previous roles — the
// dev/test twin of what provisioning writes to identity.memberships.
func (d *Directory) Put(tenantID, actorID string, roles ...string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	tenant, ok := d.member[tenantID]
	if !ok {
		tenant = map[string][]string{}
		d.member[tenantID] = tenant
	}
	tenant[actorID] = slices.Clone(roles)
}

func (d *Directory) TenantActors(_ context.Context, tenantID string) ([]api.Principal, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var actors []api.Principal
	for actorID, roles := range d.member[tenantID] {
		actors = append(actors, api.Principal{
			TenantID: tenantID, ActorID: actorID,
			Roles: slices.Clone(roles),
		})
	}
	slices.SortFunc(actors, func(a, b api.Principal) int { return slices.Compare([]string{a.ActorID}, []string{b.ActorID}) })
	return actors, nil
}
