// Package memory tests pin the in-memory store to the same effective-dated contract the
// durable Postgres adapter encodes (T-0039, SPEC-0042 AC3): history is retained, the read
// answers "in force at this instant", and same-instant rows tie-break deterministically on
// the later chain position. Tenant scope is enforced on every path (SPEC-0001).
package memory

import (
	"context"
	"testing"
	"time"

	"github.com/gitfrok/backend/modules/residency/api"
	"github.com/gitfrok/backend/platform/tenancy"
)

var baseInstant = time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)

func tenantCtx(tenantID string) context.Context {
	return tenancy.WithTenant(context.Background(), tenancy.ID(tenantID))
}

func decl(cloud, region string, at time.Time, seq int64) api.Declaration {
	return api.Declaration{
		TenantID: "acme", Cloud: cloud, Region: region,
		EffectiveAt: at, ActorID: "owner-1", ChainSeq: seq, RecordHash: "hash",
	}
}

// TestDeclarationAtHonorsEffectiveTime is the effective-dated read: a row whose effective
// instant is after the asked instant is not yet in force, and the latest row before it
// is (SPEC-0042 AC3 — the same semantics the durable store serves).
func TestDeclarationAtHonorsEffectiveTime(t *testing.T) {
	s := New()
	ctx := tenantCtx("acme")
	if err := s.PutDeclaration(ctx, decl("gke", "europe-west1", baseInstant, 1)); err != nil {
		t.Fatalf("put first: %v", err)
	}
	if err := s.PutDeclaration(ctx, decl("aws", "us-east1", baseInstant.Add(2*time.Hour), 2)); err != nil {
		t.Fatalf("put replace: %v", err)
	}

	// Before the first declaration: nothing in force.
	if _, ok, err := s.DeclarationAt(ctx, "acme", baseInstant.Add(-time.Second)); err != nil || ok {
		t.Fatalf("before any declaration = ok %v err %v, want none", ok, err)
	}
	// Between the two: the first is in force — the replace did not rewrite history.
	got, ok, err := s.DeclarationAt(ctx, "acme", baseInstant.Add(time.Hour))
	if err != nil || !ok || got.Cloud != "gke" {
		t.Fatalf("in force before the replace = %+v (ok %v, err %v), want the gke pinning", got, ok, err)
	}
	// After the replace: the replacement is in force.
	got, ok, err = s.DeclarationAt(ctx, "acme", baseInstant.Add(3*time.Hour))
	if err != nil || !ok || got.Cloud != "aws" {
		t.Fatalf("in force after the replace = %+v (ok %v, err %v), want the aws pinning", got, ok, err)
	}
}

// TestDeclarationAtTieBreaksOnChainSeq is the deterministic same-instant rule: two rows
// effective at the same instant resolve to the LATER chain position — the in-process twin
// of the durable store's ORDER BY effective_at DESC, chain_seq DESC (T-0039, SPEC-0042
// AC3). Append order is deliberately reversed to prove the chain position, not the write
// order, decides.
func TestDeclarationAtTieBreaksOnChainSeq(t *testing.T) {
	s := New()
	ctx := tenantCtx("acme")
	// Later chain position appended FIRST: the tie-break must still prefer seq 7.
	if err := s.PutDeclaration(ctx, decl("aws", "us-east1", baseInstant, 7)); err != nil {
		t.Fatalf("put seq 7: %v", err)
	}
	if err := s.PutDeclaration(ctx, decl("gke", "europe-west1", baseInstant, 5)); err != nil {
		t.Fatalf("put seq 5: %v", err)
	}
	got, ok, err := s.DeclarationAt(ctx, "acme", baseInstant)
	if err != nil || !ok || got.Cloud != "aws" || got.ChainSeq != 7 {
		t.Fatalf("same-instant tie-break = %+v (ok %v, err %v), want the later chain position (seq 7)", got, ok, err)
	}
}

// TestDeclarationAtIsTenantScoped is the store-side half of AC8: a lookup under one
// tenant's scope never returns another tenant's declaration, and an unscoped or
// mismatched read is the coarse refusal (SPEC-0001).
func TestDeclarationAtIsTenantScoped(t *testing.T) {
	s := New()
	if err := s.PutDeclaration(tenantCtx("acme"), decl("gke", "europe-west1", baseInstant, 1)); err != nil {
		t.Fatalf("put: %v", err)
	}
	if _, ok, err := s.DeclarationAt(tenantCtx("globex"), "acme", baseInstant); err == nil || ok {
		t.Fatal("a cross-tenant read must be the coarse refusal, never another tenant's record")
	}
	if _, ok, err := s.DeclarationAt(context.Background(), "acme", baseInstant); err == nil || ok {
		t.Fatal("an unscoped read must be the coarse refusal")
	}
}
