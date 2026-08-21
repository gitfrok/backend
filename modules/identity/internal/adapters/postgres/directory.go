package postgres

import (
	"context"
	"slices"

	"github.com/jackc/pgx/v5"

	"github.com/gitfrok/backend/modules/identity/api"
	"github.com/gitfrok/backend/platform/db"
)

// directory is the read-only tenant membership view (SPEC-0063 recipient
// derivation). It reads the same memberships table credential resolution
// trusts, inside the platform's tenant-scoped transaction so RLS holds like
// everywhere else.
type directory struct {
	pool *db.Pool
}

// NewDirectory builds the identity Directory on one pool.
func NewDirectory(pool *db.Pool) directory {
	if pool == nil {
		panic("identity postgres: pool is required")
	}
	return directory{pool: pool}
}

func (d directory) TenantActors(ctx context.Context, tenantID string) ([]api.Principal, error) {
	var actors []api.Principal
	err := d.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT actor_id, role FROM identity.memberships
			  WHERE tenant_id = $1 AND active`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		index := map[string]int{}
		for rows.Next() {
			var actorID, role string
			if err := rows.Scan(&actorID, &role); err != nil {
				return err
			}
			i, ok := index[actorID]
			if !ok {
				i = len(actors)
				index[actorID] = i
				actors = append(actors, api.Principal{TenantID: tenantID, ActorID: actorID})
			}
			actors[i].Roles = append(actors[i].Roles, role)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	for i := range actors {
		slices.Sort(actors[i].Roles)
	}
	slices.SortFunc(actors, func(a, b api.Principal) int { return slices.Compare([]string{a.ActorID}, []string{b.ActorID}) })
	return actors, nil
}
