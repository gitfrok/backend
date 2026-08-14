package memory

import "github.com/gitfrok/backend/modules/agent/internal/domain"

// The memory store reports the shared store sentinels: a miss is domain.ErrStoreNotFound
// (one coarse shape across unknown and cross-tenant, SPEC-0038 AC9) and a spent-token
// revoke is domain.ErrTokenSpent. The adapter adds no error vocabulary of its own.
var (
	errNotFound = domain.ErrStoreNotFound
	errSpent    = domain.ErrTokenSpent
)
