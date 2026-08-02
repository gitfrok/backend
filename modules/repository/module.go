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
	"github.com/gitfrok/backend/modules/repository/internal/adapters/memstore"
	"github.com/gitfrok/backend/modules/repository/internal/app"
	"github.com/gitfrok/backend/platform/bus"
)

// NewInMemory assembles the Repository context on the in-memory store adapter, publishing its
// events to b. This is the adapter for local runs and tests; the Postgres one arrives with the
// tenancy baseline (T-0004) as a second constructor taking the pool from cmd/.
func NewInMemory(b bus.Bus) api.Repositories {
	return app.New(memstore.New(), b)
}
