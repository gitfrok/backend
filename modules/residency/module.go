// Package residency is the Residency context's composition root (T-0033, SPEC-0040):
// declared residency, enforced on placement, with the witnessed facts the evidence pack's
// residency section cites.
//
// cmd/ builds the context here and never names a package under internal/ (ADR-0025). The
// witness is a port the composition root adapts onto the tenant's audit trail — the same
// seam Identity & Access uses for its grant lifecycle — keeping the module graph acyclic
// (invariant 14). Swapping the store is a change to a composition line, not to the context.
package residency

import (
	policyapi "github.com/gitfrok/backend/modules/policy/api"
	"github.com/gitfrok/backend/modules/residency/api"
	"github.com/gitfrok/backend/modules/residency/internal/adapters/memory"
	"github.com/gitfrok/backend/modules/residency/internal/app"
)

// Service is the composed service, aliased so cmd/ can hold it without naming a package
// under this module's internal/ tree.
type Service = app.Service

// Witness is the append-only port the composition root adapts the tenant's audit trail onto.
type Witness = api.Witness

// WitnessEntry is one record the lifecycle asks to be witnessed, aliased for the adapter's
// convenience.
type WitnessEntry = api.WitnessEntry

// WitnessRecord is the witnessed record's chain position, aliased for the same reason.
type WitnessRecord = api.WitnessRecord

// New builds the context on the in-memory store with a supplied witness. A durable store is
// future work; the store is a port, so that is a composition-line change (invariant 13).
func New(pdp policyapi.DecisionPoint, witness api.Witness, cfg api.Config, logf func(format string, args ...any)) *Service {
	return app.New(pdp, witness, memory.New(), cfg, logf)
}
