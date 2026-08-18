package app

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gitfrok/backend/modules/ci/api"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
)

// List answers which runs the caller may see (T-0059, SPEC-0054 AC4, AC5).
//
// The set is derived here, at request time, by asking the PDP about each
// candidate's repository — never a cached permission set and never anything
// the caller sent, because ListQuery has no field with which to send one.
//
// The three refusals are the same three the repository list draws, for the
// same reasons: no tenant is an error because a global list is not a thing;
// a store failure is an error; and a caller the PDP allows nothing gets an
// EMPTY page, never an error, because "you may see none" and "there are none"
// have to be the same answer.
//
// Note what is not here: nothing about job output. api.Job withholds it, and
// ADR-0072 defers retaining it to its own decision.

const (
	defaultListPageSize = 50
	maxListPageSize     = 200
	candidateBatch      = 200
	maxRounds           = 50
)

// Lister is the store's contribution to listing: candidates in a total order,
// tenant-scoped. Which of them the caller may see is asked above this port, so
// an adapter cannot become a decision point by accident (invariant 2).
type Lister interface {
	Candidates(ctx context.Context, tenantID, repositoryID string, after ListCursor, limit int) ([]api.Job, error)
}

// ListCursor is a position in the (queued_at DESC, job_id DESC) ordering.
type ListCursor struct {
	QueuedAt time.Time
	JobID    string
}

func (s *Service) List(ctx context.Context, q api.ListQuery) (api.ListPage, error) {
	if q.TenantID == "" {
		return api.ListPage{}, errors.New("ci: tenant required")
	}
	lister, ok := s.store.(Lister)
	if !ok {
		// A store that cannot enumerate is a composition problem, not an empty
		// history: returning nothing would read as "no runs", which is a claim
		// this service has no basis for.
		return api.ListPage{}, errors.New("ci: this store cannot list runs")
	}
	if s.pdp == nil {
		return api.ListPage{}, errors.New("ci: no decision point; listing cannot be authorized")
	}

	limit := int(q.PageSize)
	if limit <= 0 {
		limit = defaultListPageSize
	}
	if limit > maxListPageSize {
		limit = maxListPageSize
	}

	after, err := decodeListCursor(q.PageToken, q.TenantID)
	if err != nil {
		return api.ListPage{}, err
	}

	page := make([]api.Job, 0, limit)
	filled := false
	exhausted := false
	var last ListCursor

	for round := 0; round < maxRounds && !filled; round++ {
		candidates, err := lister.Candidates(ctx, q.TenantID, q.RepositoryID, after, candidateBatch)
		if err != nil {
			return api.ListPage{}, fmt.Errorf("ci: listing runs: %w", err)
		}
		if len(candidates) == 0 {
			exhausted = true
			break
		}
		for _, job := range candidates {
			after = ListCursor{QueuedAt: job.QueuedAt, JobID: job.ID}
			last = after
			// Deny-by-default: an error and a not-allowed decision are the same
			// refusal, and neither fails the whole page — one unavailable
			// decision must not make every run disappear (ADR-0006).
			allowed, err := s.mayReadRepository(ctx, q, job.RepositoryID)
			if err != nil || !allowed {
				continue
			}
			page = append(page, job)
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

	next := ""
	if !exhausted && last.JobID != "" {
		next = encodeListCursor(q.TenantID, last)
	}
	return api.ListPage{Jobs: page, NextPageToken: next}, nil
}

// mayReadRepository asks the PDP whether the caller may read the repository a
// run belongs to. Seeing that a run happened is reading something about the
// repository, so it asks the question the repository itself is guarded by.
func (s *Service) mayReadRepository(ctx context.Context, q api.ListQuery, repositoryID string) (bool, error) {
	d, err := s.pdp.Decide(ctx, policyapi.Request{
		TenantID: q.TenantID,
		Subject: policyapi.Subject{
			ID:       q.ActorID,
			TenantID: q.TenantID,
			Roles:    q.ActorRoles,
		},
		Action:   "repo.read",
		Resource: policyapi.Resource{Type: "repository", ID: repositoryID},
	})
	if err != nil {
		return false, err
	}
	return d.Allowed, nil
}

// The cursor encodes a position in the store's ordering, not in the answer: it
// says nothing about how many runs were refused along the way. It is bound to
// the tenant that minted it and refused rather than reinterpreted elsewhere.
func encodeListCursor(tenantID string, c ListCursor) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strings.Join([]string{
		"v1", tenantID, c.QueuedAt.UTC().Format(time.RFC3339Nano), c.JobID,
	}, "\x00")))
}

func decodeListCursor(token, tenantID string) (ListCursor, error) {
	if token == "" {
		return ListCursor{}, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return ListCursor{}, errors.New("ci: malformed page token")
	}
	parts := strings.Split(string(raw), "\x00")
	if len(parts) != 4 || parts[0] != "v1" {
		return ListCursor{}, errors.New("ci: malformed page token")
	}
	if parts[1] != tenantID {
		return ListCursor{}, errors.New("ci: page token does not belong to this tenant")
	}
	at, err := time.Parse(time.RFC3339Nano, parts[2])
	if err != nil {
		return ListCursor{}, errors.New("ci: malformed page token")
	}
	return ListCursor{QueuedAt: at, JobID: parts[3]}, nil
}
