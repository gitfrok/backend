// Package codesearch is the Code Search context's composition root. See the note in
// modules/repository/module.go for why a module needs one: cmd/ injects, but Go's internal/ rule
// keeps it from naming what it injects into.
package codesearch

import (
	"github.com/gitfrok/backend/modules/codesearch/api"
	"github.com/gitfrok/backend/modules/codesearch/internal/app"
	repoapi "github.com/gitfrok/backend/modules/repository/api"
	"github.com/gitfrok/backend/platform/bus"
)

// New assembles the Code Search context and subscribes its projection to b. Both dependencies come
// from cmd/: the bus it listens on, and the Repository read port it resolves against. Because the
// second is a port and not a service, this context does not change when Repository is extracted
// and that argument becomes a gRPC client (ADR-0026).
func New(b bus.Bus, repos repoapi.Reader) api.Index {
	projection := app.NewProjection(repos)
	projection.Register(b)
	return projection
}
