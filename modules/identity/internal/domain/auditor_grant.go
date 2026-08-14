// Auditor grant lifecycle — the pure rules Identity&Access applies to a
// scoped, read-only, time-boxed grant (SPEC-0033, T-0027).
//
// No infrastructure here: validation and state derivation must be testable
// without a database, because they are the half of the lifecycle that is
// never allowed to depend on how a grant is stored.
package domain

import (
	"errors"
	"time"

	"github.com/gitfrok/backend/modules/identity/api"
)

// ErrInvalidGrantIssue reports an issue request that cannot become a grant:
// an empty auditor principal, an open or inverted range, no named packs, or
// a missing/past expiry. Rejected at issue time, never partially honoured —
// a grant is scoped, named and time-boxed by construction (SPEC-0033 AC3).
var ErrInvalidGrantIssue = errors.New("identity: invalid auditor grant issue")

// ValidateIssue checks the scope an admin requested against the shape a
// grant must have. Every rejection is the same error: a malformed request
// must not be distinguishable from any other failed operation on this
// surface (SPEC-0001).
func ValidateIssue(req api.GrantIssue, now time.Time) error {
	if req.AuditorPrincipalID == "" {
		return ErrInvalidGrantIssue
	}
	// The range is closed, never half-open: both bounds required, from not
	// after to.
	if req.RangeFrom.IsZero() || req.RangeTo.IsZero() || req.RangeFrom.After(req.RangeTo) {
		return ErrInvalidGrantIssue
	}
	if len(req.PackIDs) == 0 {
		return ErrInvalidGrantIssue
	}
	for _, pack := range req.PackIDs {
		if pack == "" {
			return ErrInvalidGrantIssue
		}
	}
	// A grant is time-boxed by construction: a missing expiry is rejected,
	// and an expiry already in the past could never authorize a read
	// (SPEC-0033 AC3).
	if req.ExpiresAt.IsZero() || !req.ExpiresAt.After(now) {
		return ErrInvalidGrantIssue
	}
	return nil
}

// DeriveState renders a stored grant's lifecycle at an instant on the
// server's clock. It is the server's own rendering — never a caller claim —
// and it is what makes expiry take effect without an operator action
// (SPEC-0033 AC3): revocation is a stored fact, expiry is a clock
// comparison, and both are read fresh on every decision (SPEC-0033 AC7).
func DeriveState(g api.AuditorGrant, now time.Time) api.GrantState {
	if !g.RevokedAt.IsZero() {
		return api.GrantRevoked
	}
	// Reads authorize strictly before the expiry the server recognizes — the
	// instant of expiry itself already denies (SPEC-0033 AC3).
	if !now.Before(g.ExpiresAt) {
		return api.GrantExpired
	}
	return api.GrantActive
}
