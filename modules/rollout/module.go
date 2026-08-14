// Package rollout is the Rollout context's composition root (T-0032, SPEC-0039 AC3–AC7,
// ADR-0013/0017/0044): signed-release verification, reconcile-based rollout with rollback,
// per-data-plane rollout observability, and the customer version window.
//
// cmd/ builds the context here and never names a package under internal/ (ADR-0025). Swapping
// the store is a change to a composition line, not to the context.
package rollout

import (
	"github.com/gitfrok/backend/modules/rollout/api"
	"github.com/gitfrok/backend/modules/rollout/internal/adapters/memory"
	"github.com/gitfrok/backend/modules/rollout/internal/app"
	"github.com/gitfrok/backend/modules/rollout/internal/domain"
	"github.com/gitfrok/backend/platform/bus"
)

// Service is the composed engine, aliased so cmd/ can hold it without naming a package under
// this module's internal/ tree.
type Service = app.Service

// TrustBundle is the release-verification root, aliased for the same reason.
type TrustBundle = domain.TrustBundle

// NewTrustBundleFromPEM parses the versioned public verification keys (ADR-0044) into the
// bundle the engine verifies against. The public key is a non-secret operator artifact; the
// private key never reaches this process.
func NewTrustBundleFromPEM(pemBytes []byte) (*TrustBundle, error) {
	return domain.NewTrustBundleFromPEM(pemBytes)
}

// New builds the context on the in-memory store with a supplied verifier. A durable store is
// future work; the store is a port, so that is a composition-line change (invariant 13).
func New(verifier api.ReleaseVerifier, events bus.Bus, cfg api.Config, logf func(format string, args ...any)) *Service {
	return app.New(verifier, memory.New(), events, cfg, logf)
}
