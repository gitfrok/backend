// Package codesearch is the Code Search context's composition root. See the note in
// modules/repository/module.go for why a module needs one: cmd/ injects, but Go's internal/ rule
// keeps it from naming what it injects into.
package codesearch

import (
	repositoryv1 "github.com/gitfrok/backend/gen/proto/repository/v1"
	"github.com/gitfrok/backend/modules/codesearch/api"
	codesearchgrpc "github.com/gitfrok/backend/modules/codesearch/internal/adapters/grpc"
	"github.com/gitfrok/backend/modules/codesearch/internal/adapters/repocontent"
	"github.com/gitfrok/backend/modules/codesearch/internal/app"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
	repoapi "github.com/gitfrok/backend/modules/repository/api"
	"github.com/gitfrok/backend/platform/bus"
)

// GRPCServer is the module's gRPC door, aliased so cmd/ can hold one without naming a package
// under this module's internal/ tree.
type GRPCServer = codesearchgrpc.Server

// New assembles the Code Search context and subscribes it to b. Every dependency comes from
// cmd/: the bus it listens on and publishes to, the Repository read port it resolves names
// against, the PDP every result path asks (invariant 2), and — when the plane already has one —
// the route to repository content. Because the last three are ports and not services, this
// context does not change when Repository is extracted and they become gRPC clients (ADR-0026).
// A nil content source is a plane without a route to Git storage yet: the context tracks
// admission and freshness and absorbs nothing until AttachContentSource wires one.
func New(b bus.Bus, repos repoapi.Reader, pdp policyapi.DecisionPoint, content api.ContentSource) api.Service {
	svc := app.NewService(repos, pdp, b, content, app.Config{})
	svc.Register(b)
	return svc
}

// NewGRPCServer adapts the Service port to its gRPC contract (SPEC-0035).
func NewGRPCServer(svc api.Service) *GRPCServer {
	return codesearchgrpc.NewServer(svc)
}

// NewGRPCContentSource adapts the RepositoryReader gRPC client — the Repository/Git contract
// surface (GetTree/GetFile) — to the ContentSource port. It is the only route this context ever
// takes to repository content: never Git storage directly, never another context's tables
// (ADR-0022, SPEC-0035 AC7).
func NewGRPCContentSource(client repositoryv1.RepositoryReaderClient) api.ContentSource {
	return repocontent.NewGRPC(client)
}
