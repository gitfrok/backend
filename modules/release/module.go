// Package release is the Release context's composition root (ADR-0025).
package release

import (
	policyapi "github.com/gitfrok/backend/modules/policy/api"
	"github.com/gitfrok/backend/modules/release/api"
	releasegrpc "github.com/gitfrok/backend/modules/release/internal/adapters/grpc"
	releasepg "github.com/gitfrok/backend/modules/release/internal/adapters/postgres"
	"github.com/gitfrok/backend/modules/release/internal/app"
	"github.com/gitfrok/backend/platform/db"
)

// TagResolver is re-exported so the plane binary can satisfy it without naming an internal package.
type TagResolver = releasegrpc.TagResolver

// NewPostgres assembles the Release context on its durable store (T-0064, SPEC-0056).
//
// There is no in-memory constructor. Unlike the repository registry, releases have never had one,
// and adding a memory adapter now would create the exact gap ADR-0071 was written to close: a
// record of what was announced that empties when a process does.
func NewPostgres(pool *db.Pool, pdp policyapi.DecisionPoint) api.Releases {
	return app.New(releasepg.New(pool), pdp)
}

// NewGRPCServer adapts the context onto its contract. tags resolves a tag to a commit at publish
// time; the Release context never does that itself, because it may not depend on Repository/Git.
func NewGRPCServer(releases api.Releases, tags TagResolver) *releasegrpc.Server {
	return releasegrpc.NewServer(releases, tags)
}
