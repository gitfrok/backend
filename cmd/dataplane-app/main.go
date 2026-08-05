// Command dataplane-app is the single data-plane binary (invariant 19). Modules are packages
// composed here; they are not separate services (ADR-0025).
//
// This file is the only place that knows which modules exist and which concrete adapters they run
// on. A module never constructs another module, and never reaches for an adapter itself — so
// promoting one to its own service (ADR-0026) is a change here, not in the modules.
package main

import (
	"fmt"

	agentv1 "github.com/gitfrok/backend/gen/proto/agent/v1"
	"github.com/gitfrok/backend/modules/codesearch"
	csapi "github.com/gitfrok/backend/modules/codesearch/api"
	"github.com/gitfrok/backend/modules/repository"
	repoapi "github.com/gitfrok/backend/modules/repository/api"
	"github.com/gitfrok/backend/platform/bus"
)

// dataplane is the composed plane: every context, held by its api/ port.
type dataplane struct {
	bus          *bus.InProcess
	repositories repoapi.Repositories
	searchIndex  csapi.Index
}

// newDataplane wires the plane. Concrete implementations are chosen here and injected; the fields
// are the api/ interfaces, so nothing downstream can depend on which implementation it got.
func newDataplane() *dataplane {
	b := bus.NewInProcess()

	// Repository context, on the in-memory adapter until the Postgres one lands with the tenancy
	// baseline (T-0004). Swapping adapters is a change to this line and nothing else.
	repositories := repository.NewInMemory(b)

	// Code Search context, handed the bus it listens on and the Repository read port it resolves
	// against — the only two in-process routes a module may take (invariant 14).
	searchIndex := codesearch.New(b, repositories)

	return &dataplane{bus: b, repositories: repositories, searchIndex: searchIndex}
}

func main() {
	dp := newDataplane()
	// Compile-time proof that the generated contracts compose into this plane alongside the
	// modules; the agent gateway itself is wired in Phase 3.
	_ = agentv1.HealthState_HEALTH_STATE_HEALTHY
	_ = dp
	fmt.Println("gitfrok dataplane-app: repository + codesearch wired on the in-process bus (T-0008)")
}
