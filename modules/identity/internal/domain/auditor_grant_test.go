package domain

import (
	"errors"
	"testing"
	"time"

	"github.com/gitfrok/backend/modules/identity/api"
)

// SPEC-0033 AC3/AC8: a grant is scoped, named and time-boxed by construction.
// Every malformed issue is the same rejection — a malformed request must not
// be distinguishable from any other failed operation on the surface.

var now = time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)

func validIssue() api.GrantIssue {
	return api.GrantIssue{
		AuditorPrincipalID: "auditor-1",
		RangeFrom:          now.Add(-72 * time.Hour),
		RangeTo:            now.Add(-time.Hour),
		RepositoryID:       "repo-1",
		PackIDs:            []string{"pack-1"},
		ExpiresAt:          now.Add(time.Hour),
	}
}

func TestValidateIssueAcceptsACompleteScope(t *testing.T) {
	if err := ValidateIssue(validIssue(), now); err != nil {
		t.Fatalf("valid issue rejected: %v", err)
	}
}

func TestValidateIssueRejectsMalformedShapes(t *testing.T) {
	for name, mutate := range map[string]func(*api.GrantIssue){
		"empty auditor principal": func(r *api.GrantIssue) { r.AuditorPrincipalID = "" },
		"zero range from":         func(r *api.GrantIssue) { r.RangeFrom = time.Time{} },
		"zero range to":           func(r *api.GrantIssue) { r.RangeTo = time.Time{} },
		"inverted range": func(r *api.GrantIssue) {
			r.RangeFrom, r.RangeTo = r.RangeTo, r.RangeFrom.Add(time.Hour)
		},
		"no packs":      func(r *api.GrantIssue) { r.PackIDs = nil },
		"empty pack":    func(r *api.GrantIssue) { r.PackIDs = []string{"pack-1", ""} },
		"zero expiry":   func(r *api.GrantIssue) { r.ExpiresAt = time.Time{} },
		"past expiry":   func(r *api.GrantIssue) { r.ExpiresAt = now.Add(-time.Second) },
		"expiry at now": func(r *api.GrantIssue) { r.ExpiresAt = now },
	} {
		t.Run(name, func(t *testing.T) {
			req := validIssue()
			mutate(&req)
			if err := ValidateIssue(req, now); !errors.Is(err, ErrInvalidGrantIssue) {
				t.Fatalf("error = %v, want %v", err, ErrInvalidGrantIssue)
			}
		})
	}
}

// SPEC-0033 AC3/AC7: revocation is a stored fact, expiry is a clock
// comparison; both are read fresh. The instant of expiry itself already
// denies.
func TestDeriveStateRendersTheLifecycleAtAnInstant(t *testing.T) {
	base := api.AuditorGrant{ExpiresAt: now.Add(time.Hour)}

	if got := DeriveState(base, now.Add(30*time.Minute)); got != api.GrantActive {
		t.Fatalf("state before expiry = %s, want ACTIVE", got)
	}
	if got := DeriveState(base, base.ExpiresAt); got != api.GrantExpired {
		t.Fatalf("state at expiry = %s, want EXPIRED — the expiry instant itself denies", got)
	}
	if got := DeriveState(base, base.ExpiresAt.Add(time.Second)); got != api.GrantExpired {
		t.Fatalf("state past expiry = %s, want EXPIRED", got)
	}

	revoked := base
	revoked.RevokedAt = now
	if got := DeriveState(revoked, now.Add(30*time.Minute)); got != api.GrantRevoked {
		t.Fatalf("state of revoked grant = %s, want REVOKED", got)
	}
	// Revocation wins over expiry: a revoked grant stays REVOKED past its
	// expiry, because the admin's act terminated it first.
	if got := DeriveState(revoked, base.ExpiresAt.Add(time.Hour)); got != api.GrantRevoked {
		t.Fatalf("state of revoked grant past expiry = %s, want REVOKED", got)
	}
}
