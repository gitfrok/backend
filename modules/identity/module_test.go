package identity_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/gitfrok/backend/modules/identity"
	"github.com/gitfrok/backend/modules/identity/api"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
	"github.com/gitfrok/backend/platform/db"
	"github.com/gitfrok/backend/platform/tenancy"
)

type recorderPDP struct {
	decision policyapi.Decision
	requests []policyapi.Request
}

func (p *recorderPDP) Decide(_ context.Context, req policyapi.Request) (policyapi.Decision, error) {
	p.requests = append(p.requests, req)
	return p.decision, nil
}

// SPEC-0006 AC2: lifecycle operations never trust a tenant supplied in a
// request. The already-authenticated request context is the source of scope.
func TestPATLifecycleRequiresMatchingTenantContext(t *testing.T) {
	pdp := &recorderPDP{decision: policyapi.Decision{Allowed: true}}
	auth := identity.NewInMemory([]byte("test-key"), pdp)
	ctx := api.WithPrincipal(tenancy.WithTenant(context.Background(), "tenant-a"), api.Principal{TenantID: "tenant-a", ActorID: "actor-a", Roles: []string{"owner"}})
	expiresAt := time.Now().Add(time.Hour)
	pat, _, err := auth.IssuePAT(ctx, "tenant-a", "actor-a", "ci", nil, &expiresAt)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := auth.IssuePAT(context.Background(), "tenant-a", "actor-a", "ci", nil, &expiresAt); !errors.Is(err, tenancy.ErrNoTenant) {
		t.Fatalf("missing tenant error = %v, want %v", err, tenancy.ErrNoTenant)
	}
	if _, err := auth.ListPATs(ctx, "tenant-b", "actor-a"); !errors.Is(err, api.ErrTenantMismatch) {
		t.Fatalf("mismatched tenant error = %v, want %v", err, api.ErrTenantMismatch)
	}
	if _, err := auth.RevokePAT(ctx, "tenant-b", "actor-a", pat.ID); !errors.Is(err, api.ErrTenantMismatch) {
		t.Fatalf("cross-tenant revoke error = %v, want %v", err, api.ErrTenantMismatch)
	}
	if len(pdp.requests) != 1 || pdp.requests[0].Action != "identity.pat.issue" || pdp.requests[0].Resource.Type != "personal_access_token" {
		t.Fatalf("PDP requests = %+v", pdp.requests)
	}
}

// SPEC-0006 AC3: issuing a PAT is a protected action. A missing or refusing
// PDP never falls back to an in-process role check.
func TestPATLifecycleDeniesWithoutPDPGrant(t *testing.T) {
	pdp := &recorderPDP{decision: policyapi.Decision{Allowed: false}}
	auth := identity.NewInMemory([]byte("test-key"), pdp)
	ctx := api.WithPrincipal(tenancy.WithTenant(context.Background(), "tenant-a"), api.Principal{TenantID: "tenant-a", ActorID: "actor-a"})
	expiresAt := time.Now().Add(time.Hour)
	if _, _, err := auth.IssuePAT(ctx, "tenant-a", "actor-a", "ci", nil, &expiresAt); !errors.Is(err, api.ErrAuthorizationDenied) {
		t.Fatalf("denied issue error = %v, want %v", err, api.ErrAuthorizationDenied)
	}
}

func TestNewPostgresRefusesMissingSecurityDependencies(t *testing.T) {
	pdp := &recorderPDP{decision: policyapi.Decision{Allowed: true}}
	for _, test := range []struct {
		name string
		pool bool
		pdp  policyapi.DecisionPoint
	}{
		{name: "pool", pool: false, pdp: pdp},
		{name: "PDP", pool: true, pdp: nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("NewPostgres did not reject missing security dependency")
				}
			}()
			var poolArg *db.Pool
			if test.pool {
				poolArg = new(db.Pool)
			}
			_ = identity.NewPostgres(poolArg, "default", map[string][]byte{"default": []byte("test-key")}, test.pdp)
		})
	}
}
