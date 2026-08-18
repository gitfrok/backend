package app

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/gitfrok/backend/modules/repository/api"
	"github.com/gitfrok/backend/modules/repository/internal/domain"
)

// defaultPageSize and maxPageSize bound one page. They are limits on work, not on truth: neither
// is reported to the caller and neither implies anything about how many repositories exist.
const (
	defaultPageSize = 50
	maxPageSize     = 200
	// candidateBatch is how many rows are fetched per round while filling a page. A page can
	// need many rounds when most candidates are refused, which is the normal case for a
	// narrowly-scoped caller in a large tenant.
	candidateBatch = 200
	// maxRounds bounds the walk so a tenant with a very large number of repositories the caller
	// may not see cannot hold a request open indefinitely. Hitting it ends the page early with a
	// cursor, which is a short page rather than a wrong one.
	maxRounds = 50
)

// List answers which repositories the caller may see.
//
// The set is derived here, at request time, by asking the PDP about each candidate — never from a
// cached permission set and never from anything the caller sent, because ListQuery has no field
// with which to send one (SPEC-0052 AC4, mirroring SPEC-0035 AC2).
//
// Three refusals are deliberately different from each other:
//
//   - No tenant is an error: a list without a tenant would be a global question, and there is no
//     such thing here (invariant 1).
//   - No PDP is an error: an unauthorized list is not an empty list. Returning nothing would read
//     as "you may see nothing", which is a decision this service did not make.
//   - A caller the PDP allows nothing is an EMPTY LIST, not an error. "You may see none" and
//     "there are none" have to be the same answer, or the difference between them is a disclosure.
func (s *Service) List(ctx context.Context, q api.ListQuery) (api.ListPage, error) {
	if q.TenantID == "" {
		return api.ListPage{}, errors.New("app: tenant required")
	}
	if s.auth == nil {
		return api.ListPage{}, api.ErrNoDecisionPoint
	}

	limit := int(q.PageSize)
	if limit <= 0 {
		limit = defaultPageSize
	}
	if limit > maxPageSize {
		limit = maxPageSize
	}

	after, err := decodeCursor(q.PageToken, q.TenantID)
	if err != nil {
		return api.ListPage{}, err
	}

	tenant := domain.TenantID(q.TenantID)
	page := make([]api.RepositoryView, 0, limit)
	var lastSeen domain.RepoID
	exhausted := false

	// filled records that the walk stopped because the PAGE was full rather than because the
	// store ran out. The two need telling apart: a full page may have more behind it and must
	// offer a cursor, while a short batch means there is nothing further to walk.
	filled := false

	for round := 0; round < maxRounds && !filled; round++ {
		candidates, err := s.store.Candidates(ctx, tenant, after, candidateBatch)
		if err != nil {
			return api.ListPage{}, fmt.Errorf("app: listing repositories: %w", err)
		}
		if len(candidates) == 0 {
			exhausted = true
			break
		}
		for _, repo := range candidates {
			after = repo.ID
			lastSeen = repo.ID
			// Deny-by-default: an error and a not-allowed decision are the same refusal, and
			// neither fails the whole list — one unavailable decision must not make every
			// repository disappear (ADR-0006).
			allowed, err := s.auth.MayRead(ctx, q.TenantID, q.ActorID, q.ActorRoles, string(repo.ID))
			if err != nil || !allowed {
				continue
			}
			page = append(page, viewOf(repo))
			if len(page) == limit {
				filled = true
				break
			}
		}
		if !filled && len(candidates) < candidateBatch {
			exhausted = true
			break
		}
	}

	// A next cursor is offered only when there may be more to walk. An exhausted store ends the
	// page without one, so a caller is never invited to ask for a page that cannot exist.
	next := ""
	if !exhausted && lastSeen != "" {
		next = encodeCursor(q.TenantID, lastSeen)
	}
	return api.ListPage{Repositories: page, NextPageToken: next}, nil
}

// The cursor is the last repository ID walked, bound to the tenant that minted it.
//
// It encodes a position in the store's ordering, not a position in the ANSWER: it says nothing
// about how many repositories were refused along the way, so replaying one reveals nothing about
// what the caller could not see. Binding the tenant means a cursor cannot be carried across
// tenants — refused rather than silently reinterpreted, because reinterpreting it would let a
// caller in tenant B resume a walk over tenant A's ordering.
const cursorVersion = "v1"

func encodeCursor(tenantID string, last domain.RepoID) string {
	return base64.RawURLEncoding.EncodeToString([]byte(cursorVersion + "\x00" + tenantID + "\x00" + string(last)))
}

func decodeCursor(token, tenantID string) (domain.RepoID, error) {
	if token == "" {
		return "", nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return "", errors.New("app: malformed page token")
	}
	parts := strings.SplitN(string(raw), "\x00", 3)
	if len(parts) != 3 || parts[0] != cursorVersion {
		return "", errors.New("app: malformed page token")
	}
	if parts[1] != tenantID {
		// Not "not found": a cursor minted for another tenant is a request this caller must not
		// be able to express at all.
		return "", errors.New("app: page token does not belong to this tenant")
	}
	return domain.RepoID(parts[2]), nil
}

var _ api.Lister = (*Service)(nil)
