// Package notifications is the Notifications context's composition root
// (T-0080, SPEC-0063, ADR-0086). cmd/ builds the context here and never names
// a package under internal/ (ADR-0025).
package notifications

import (
	"context"
	"slices"

	notificationsv1 "github.com/gitfrok/backend/gen/proto/notifications/v1"
	identityapi "github.com/gitfrok/backend/modules/identity/api"
	notificationsgrpc "github.com/gitfrok/backend/modules/notifications/internal/adapters/grpc"
	notificationsmemory "github.com/gitfrok/backend/modules/notifications/internal/adapters/memory"
	notificationspg "github.com/gitfrok/backend/modules/notifications/internal/adapters/postgres"
	notificationsapp "github.com/gitfrok/backend/modules/notifications/internal/app"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
	"github.com/gitfrok/backend/platform/bus"
	"github.com/gitfrok/backend/platform/db"
)

// Service is the composed service, aliased so cmd/ can hold it without naming
// a package under this module's internal/ tree (ADR-0025).
type Service = notificationsapp.Service

// Store and CreatorStore are the persistence ports, aliased for the same
// reason: cmd/ wires stores without naming internal packages.
type (
	Store        = notificationsapp.Store
	CreatorStore = notificationsapp.CreatorStore
)

// NewMemoryStore wires the in-memory store — the dev/test default. Rows do
// not survive a restart; AC1's durability proof runs against Postgres.
func NewMemoryStore() (Store, CreatorStore) {
	m := notificationsmemory.New()
	return m, m
}

// NewPostgresStore wires the durable store over one pool: rows survive a
// kill-and-restart (SPEC-0063 AC1), RLS-forced like every store.
func NewPostgresStore(pool *db.Pool) (Store, CreatorStore) {
	p := notificationspg.New(pool)
	return p, p
}

// New assembles the context on the supplied ports.
func New(store Store, creators CreatorStore, directory notificationsapp.Directory) *Service {
	return notificationsapp.New(store, creators, directory)
}

// Subscribe wires the bus handlers: opened / ready / reviewed / merged /
// findings-attributed, each with its coverage-table recipient rule.
func Subscribe(b bus.Bus, s *Service) { notificationsapp.Subscribe(b, s) }

// GRPCServer is the read surface's server type, aliased so cmd/ can register
// it without naming an internal package.
func GRPCServer(s *Service, pdp policyapi.DecisionPoint) notificationsv1.NotificationServiceServer {
	return notificationsgrpc.NewServer(s, pdp)
}

// reviewCapableDirectory adapts Identity&Access's membership view onto the
// derivation port. A protection rule carries a required-approval count, not
// holder identities, so reviewers-to-be (SPEC-0063 AC1) resolves to principals
// whose roles grant merge_request.review in governance/policies/gitsaas/authz
// (owner, member). Role names are policy vocabulary; this filter mirrors one
// grant and cites it.
type reviewCapableDirectory struct{ members identityapi.Directory }

// NewDirectory adapts the identity Directory for recipient derivation. It
// names no permission outcome — only who holds a review-capable role today;
// every actual action is still decided by the PDP where it is attempted.
func NewDirectory(members identityapi.Directory) notificationsapp.Directory {
	return reviewCapableDirectory{members: members}
}

func (d reviewCapableDirectory) ReviewCapableActors(ctx context.Context, tenantID string) ([]string, error) {
	principals, err := d.members.TenantActors(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, p := range principals {
		if slices.Contains(p.Roles, "owner") || slices.Contains(p.Roles, "member") {
			out = append(out, p.ActorID)
		}
	}
	slices.Sort(out)
	return out, nil
}
