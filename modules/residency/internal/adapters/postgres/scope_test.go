// These tests are INTERNAL to the adapter and need no database: the scope
// check they exercise must refuse before any pool is touched, which is the
// property under test — a mismatched call must not reach Postgres even to be
// denied there (SPEC-0001 AC2, the posture platform/db.InTx already takes for
// an unscoped context).
package postgres

import (
	"testing"
	"time"

	"github.com/gitfrok/backend/modules/residency/api"
	"github.com/gitfrok/backend/platform/tenancy"
)

// TestScopeRefusesATenantOtherThanTheContextsOwn: the adapter scopes the
// transaction from its tenant ARGUMENT, so RLS is evaluated against the
// tenant that was asked for — it can never refuse a caller who asks about
// someone else. The refusal has to happen here instead: a call whose context
// already names a tenant may only act within THAT tenant.
func TestScopeRefusesATenantOtherThanTheContextsOwn(t *testing.T) {
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID("tenant-a"))
	if _, err := scoped(ctx, "tenant-b"); err == nil {
		t.Fatal("a store call for tenant-b under a tenant-a context was accepted")
	}
	if _, err := scoped(ctx, "tenant-a"); err != nil {
		t.Fatalf("a store call matching its own context = %v, want accepted", err)
	}
	// An unscoped context is the composition-root shape: the record's own
	// tenancy is the scope, and platform/db still refuses a context that
	// ends up carrying none.
	if _, err := scoped(t.Context(), "tenant-a"); err != nil {
		t.Fatalf("an unscoped context = %v, want the argument to establish the scope", err)
	}
}

// TestMismatchedCallNeverReachesThePool: the store methods refuse a
// cross-tenant call before the pool is dereferenced. A Store with no pool at
// all proves it — anything that reached Postgres would panic here instead of
// returning the coarse refusal.
func TestMismatchedCallNeverReachesThePool(t *testing.T) {
	s := &Store{} // deliberately no pool
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID("tenant-a"))

	if err := s.PutDeclaration(ctx, api.Declaration{TenantID: "tenant-b", Cloud: "aws", Region: "eu-1"}); err == nil {
		t.Fatal("PutDeclaration accepted a cross-tenant record")
	}
	if _, _, err := s.DeclarationAt(ctx, "tenant-b", time.Now()); err == nil {
		t.Fatal("DeclarationAt accepted a cross-tenant read")
	}
	if err := s.PutObservation(ctx, "tenant-b", "plane-1", "aws", "eu-1"); err == nil {
		t.Fatal("PutObservation accepted a cross-tenant write")
	}
	if _, err := s.ObservedPlacements(ctx, "tenant-b"); err == nil {
		t.Fatal("ObservedPlacements accepted a cross-tenant read")
	}
}
