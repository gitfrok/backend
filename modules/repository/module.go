// Package repository is the Repository context's composition root.
//
// It exists because Go's internal/ rule is stricter than the architecture rule: cmd/ is told to
// inject concrete implementations (ADR-0025), but it cannot name a type under
// modules/repository/internal to do so. This package sits inside the module, so it may assemble
// the internals, and is importable from cmd/, so the plane binary still chooses what gets built.
//
// The constructors return the module's api/ interfaces and never the concrete services, so a
// caller cannot accidentally depend on an implementation. One constructor per adapter choice: cmd/
// picks by calling the one it wants, and passes in the infrastructure that adapter needs.
package repository

import (
	"github.com/gitfrok/backend/modules/repository/api"
	repogrpc "github.com/gitfrok/backend/modules/repository/internal/adapters/grpc"
	"github.com/gitfrok/backend/modules/repository/internal/adapters/memstore"
	repopg "github.com/gitfrok/backend/modules/repository/internal/adapters/postgres"
	"github.com/gitfrok/backend/modules/repository/internal/app"
	"github.com/gitfrok/backend/modules/repository/internal/replica"
	"github.com/gitfrok/backend/platform/bus"
	"github.com/gitfrok/backend/platform/db"
)

// NewInMemory assembles the Repository context on the in-memory store adapter, publishing its
// events to b.
//
// This is the adapter for tests and for a run with no database. It is NOT the one a plane binary
// should hold: the registry it keeps empties when the process does, while the repositories
// themselves are bare git repositories on block volumes that do not (ADR-0071). A list served
// from it would omit repositories that exist, which asserts they do not.
//
// auth may be nil, in which case listing refuses rather than returning nothing
// (api.ErrNoDecisionPoint).
func NewInMemory(b bus.Bus, auth api.Authorizer) api.Repositories {
	return app.New(memstore.New(), b, app.WithAuthorizer(auth))
}

// NewInMemoryWithSettings is NewInMemory with the settings surface wired (SPEC-0057).
//
// It is a separate constructor rather than more parameters on NewInMemory because most callers of
// the in-memory store are testing listing or creation and have no opinion about settings. A Service
// built by NewInMemory refuses every settings WRITE — api.ErrNoAdministrationPoint or
// api.ErrNoWitness — which is the honest answer for a service nobody told how to authorize or audit
// one.

// NewPostgres assembles the Repository context on the durable registry (T-0053, SPEC-0052,
// ADR-0071). This is the constructor a plane binary calls.
//
// auth derives the listable set at request time. It is api.Authorizer rather than the Policy
// context's DecisionPoint because this module is a leaf and must stay one — the composition root
// adapts the PDP onto it. A nil one is accepted at construction and refused at List, so a
// misconfigured plane fails loudly on the surface that needs authorization rather than silently
// serving an empty list that reads as "you may see nothing".
func NewPostgres(pool *db.Pool, b bus.Bus, auth api.Authorizer) api.Repositories {
	return app.New(repopg.New(pool), b, app.WithAuthorizer(auth))
}

// AttachSettings wires the settings decision point and the audit witness after construction
// (T-0068, SPEC-0057).
//
// Post-construction because of the order the plane is built in: the Repository context is assembled
// early — Code Search resolves repository names through it — and the audit trail is assembled late,
// once the plane knows whether it has a database. Rather than reorder the composition root around
// one surface, the settings ports are attached when they exist, which is the same shape
// security.AttachAuditWitness uses for the ingest replay guard.
//
// It reports whether the wiring took. A false means the caller holds a Repositories that is not this
// module's service, which is a composition bug: settings writes will refuse with
// api.ErrNoAdministrationPoint rather than proceeding unauthorized.
// AsSettings exposes the composed service's settings port to a composition
// root that needs to READ it for another context's derivation (SPEC-0065:
// Code Review reads the landing policy at merge time). It hands over the same
// surface the wire serves; nil when r is not this module's service.
func AsSettings(r api.Repositories) api.Settings {
	if svc, ok := r.(*app.Service); ok {
		return svc
	}
	return nil
}

func AttachSettings(r api.Repositories, admin api.Administrator, witness api.Witness) bool {
	svc, ok := r.(*app.Service)
	if !ok {
		return false
	}
	app.WithAdministrator(admin)(svc)
	app.WithWitness(witness)(svc)
	return true
}

// NewInMemoryCoordinator assembles the single-process replica coordinator used by git-storaged and
// by tests. localNodeID is this storage node's identity; the coordinator auto-seeds an unknown shard
// as primary==sync==localNodeID so a standalone node can acknowledge its own writes (SPEC-0018,
// ADR-0042). b carries the replica.force_promote audit event on a successful force-promote.
func NewInMemoryCoordinator(localNodeID string, b bus.Bus) api.Coordinator {
	return replica.NewInMemoryCoordinator(localNodeID, b)
}

// NewGRPCServer adapts the listing port onto the RepositoryRegistry contract (T-0054).
//
// It is a second service rather than another method on RepositoryReader because they are served
// by different processes: RepositoryReader is git-storaged, which reads bare repositories off
// block volumes and holds no record of which repositories the product knows about, while the
// registry is this context in the data plane — and per ADR-0071 the registry, not the disk, is
// the product's truth for existence.
func NewGRPCServer(l api.Lister) *repogrpc.Server { return repogrpc.NewServer(l) }

// NewSettingsGRPCServer adapts the settings port onto the RepositorySettings contract (T-0068).
//
// A third service in the package for the reason the registry is a second one: a service is the
// surface one process serves, and the registry's whole property is that a caller cannot steer it. A
// write verb there would put a mutation behind exactly that surface (SPEC-0057).
func NewSettingsGRPCServer(s api.Settings) *repogrpc.SettingsServer {
	return repogrpc.NewSettingsServer(s)
}
