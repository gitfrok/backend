// Package codereview is the Code Review context's composition root (SPEC-0019).
//
// It assembles the merge-request service from its ports and returns the api/
// surface. The ref move at the end of a merge is a port to Repository/Git, which
// is what keeps this context out of Git storage.
package codereview

import (
	"github.com/gitfrok/backend/modules/codereview/api"
	"github.com/gitfrok/backend/modules/codereview/internal/app"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
	"github.com/gitfrok/backend/platform/bus"
)

// RefMover is Repository/Git's boundary for moving a ref on behalf of an
// authorized merge, aliased so cmd/ can supply one without naming a package
// under this module's internal/ tree.
type RefMover = app.RefMover

// New builds the Code Review context on the dev/in-memory store.
func New(refs RefMover, pdp policyapi.DecisionPoint, events bus.Bus) api.MergeRequests {
	return app.New(app.NewMemoryStore(), refs, pdp, events)
}
