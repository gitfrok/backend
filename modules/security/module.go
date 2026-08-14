// Package security is the Security/Findings context (SPEC-0024, SPEC-0025):
// the normalized finding model, scanner ingestion, and tenant-scoped reads.
//
// It wires the ingest service — the one place an ingest meets the PDP,
// computes identities, and emits events and the audit record — over an
// explicit store port. The in-memory store serves dev and tests; the
// Postgres adapter serves a configured plane. Swapping stores is a change
// to the composition line and nothing else.
package security

import (
	"github.com/gitfrok/backend/modules/security/api"
	securitygrpc "github.com/gitfrok/backend/modules/security/internal/adapters/grpc"
	secpg "github.com/gitfrok/backend/modules/security/internal/adapters/postgres"
	"github.com/gitfrok/backend/modules/security/internal/app"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
	"github.com/gitfrok/backend/platform/bus"
	"github.com/gitfrok/backend/platform/db"
)

// GRPCServer is the module's gRPC door, aliased so cmd/ can hold one
// without naming a package under this module's internal/ tree.
type GRPCServer = securitygrpc.Server

// New builds the context on the in-memory store: dev and tests, and any
// plane without a database URL.
func New(pdp policyapi.DecisionPoint, events bus.Bus) api.Findings {
	return app.New(app.NewMemoryStore(), pdp, events)
}

// NewWithPostgres builds the context on the Postgres adapter: the schema's
// UNIQUE identity dedup, the scan state machine, and RLS tenant isolation
// back the same contract the memory store implements.
func NewWithPostgres(pool *db.Pool, pdp policyapi.DecisionPoint, events bus.Bus) api.Findings {
	return app.New(secpg.New(pool), pdp, events)
}

// NewGRPCServer adapts the Findings port to its gRPC contract.
func NewGRPCServer(findings api.Findings) *GRPCServer {
	return securitygrpc.NewServer(findings)
}
