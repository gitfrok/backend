package memory

import (
	"context"
	"testing"
	"time"

	"github.com/gitfrok/backend/modules/identity/api"
)

// The in-memory store must hold the same tenant-scoping and uniqueness
// invariants the Postgres store enforces with RLS and constraints, because
// dev planes and tests compose it in the service's place.

var base = time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)

func grant(id, tenant, auditor string) api.AuditorGrant {
	return api.AuditorGrant{
		GrantID:            id,
		TenantID:           tenant,
		AuditorPrincipalID: auditor,
		RangeFrom:          base.Add(-time.Hour),
		RangeTo:            base,
		PackIDs:            []string{"pack-1"},
		ExpiresAt:          base.Add(time.Hour),
		IssuedAt:           base,
	}
}

func TestStoreIsTenantScoped(t *testing.T) {
	s := NewGrantStore()
	ctx := context.Background()
	if err := s.Insert(ctx, grant("g-1", "tenant-a", "auditor-1"), "req-1"); err != nil {
		t.Fatal(err)
	}
	// A different tenant sees nothing on any read path.
	if _, ok, _ := s.FindByRequest(ctx, "tenant-b", "req-1"); ok {
		t.Fatal("cross-tenant replay lookup found the grant")
	}
	if got, _ := s.List(ctx, "tenant-b", ""); len(got) != 0 {
		t.Fatalf("cross-tenant list = %d grants, want 0", len(got))
	}
	if got, _ := s.FindForRead(ctx, "tenant-b", "auditor-1", "pack-1"); len(got) != 0 {
		t.Fatalf("cross-tenant read lookup = %d grants, want 0", len(got))
	}
	if _, ok, _ := s.Revoke(ctx, "tenant-b", "g-1", base); ok {
		t.Fatal("cross-tenant revoke succeeded")
	}
}

func TestInsertIsUniquePerRequestID(t *testing.T) {
	s := NewGrantStore()
	ctx := context.Background()
	if err := s.Insert(ctx, grant("g-1", "tenant-a", "auditor-1"), "req-1"); err != nil {
		t.Fatal(err)
	}
	// Same tenant and request ID: a second grant is impossible.
	if err := s.Insert(ctx, grant("g-2", "tenant-a", "auditor-1"), "req-1"); err == nil {
		t.Fatal("duplicate issue under one request ID was stored")
	}
	// The same request ID under another tenant is a distinct key.
	if err := s.Insert(ctx, grant("g-3", "tenant-b", "auditor-1"), "req-1"); err != nil {
		t.Fatalf("same request ID under another tenant rejected: %v", err)
	}
	// Empty request IDs never collide.
	if err := s.Insert(ctx, grant("g-4", "tenant-a", "auditor-2"), ""); err != nil {
		t.Fatal(err)
	}
	if err := s.Insert(ctx, grant("g-5", "tenant-a", "auditor-3"), ""); err != nil {
		t.Fatal(err)
	}
}

func TestRevokeOnlyAuthorizingGrants(t *testing.T) {
	s := NewGrantStore()
	ctx := context.Background()
	if err := s.Insert(ctx, grant("g-1", "tenant-a", "auditor-1"), ""); err != nil {
		t.Fatal(err)
	}
	expired := grant("g-2", "tenant-a", "auditor-1")
	expired.ExpiresAt = base
	if err := s.Insert(ctx, expired, ""); err != nil {
		t.Fatal(err)
	}

	if _, ok, _ := s.Revoke(ctx, "tenant-a", "missing", base); ok {
		t.Fatal("nonexistent grant revoked")
	}
	if _, ok, _ := s.Revoke(ctx, "tenant-a", "g-2", base); ok {
		t.Fatal("grant at its expiry instant revoked — the instant itself denies")
	}
	got, ok, err := s.Revoke(ctx, "tenant-a", "g-1", base)
	if err != nil || !ok {
		t.Fatalf("revoke: %v ok=%v", err, ok)
	}
	if got.RevokedAt != base {
		t.Fatalf("RevokedAt = %v, want the revocation instant", got.RevokedAt)
	}
	if _, ok, _ := s.Revoke(ctx, "tenant-a", "g-1", base.Add(time.Minute)); ok {
		t.Fatal("already-revoked grant revoked again")
	}
}

func TestTransitionsAreExactlyOnceAndFiltered(t *testing.T) {
	s := NewGrantStore()
	ctx := context.Background()
	if err := s.Insert(ctx, grant("g-1", "tenant-a", "auditor-1"), ""); err != nil {
		t.Fatal(err)
	}
	issued := api.GrantTransition{
		Kind: api.GrantIssued, GrantID: "g-1", ActorID: "admin-a",
		GrantedBy: "admin-a", AuditorPrincipalID: "auditor-1", RepositoryID: "repo-1",
		ChainSeq: 1, RecordHash: "h-1", OccurredAt: base,
	}
	if ok, _ := s.AppendTransition(ctx, issued); !ok {
		t.Fatal("first witness not recorded")
	}
	if ok, _ := s.AppendTransition(ctx, issued); ok {
		t.Fatal("the same transition was witnessed twice")
	}
	if recorded, _ := s.TransitionRecorded(ctx, "tenant-a", "g-1", api.GrantIssued); !recorded {
		t.Fatal("recorded transition not reported as recorded")
	}
	if recorded, _ := s.TransitionRecorded(ctx, "tenant-a", "g-1", api.GrantExpiration); recorded {
		t.Fatal("unrecorded transition reported as recorded")
	}

	// Range and repository filtering.
	all, _ := s.Transitions(ctx, "tenant-a", time.Time{}, time.Time{}, "")
	if len(all) != 1 {
		t.Fatalf("unfiltered transitions = %d, want 1", len(all))
	}
	none, _ := s.Transitions(ctx, "tenant-a", base.Add(time.Hour), time.Time{}, "")
	if len(none) != 0 {
		t.Fatalf("out-of-range transitions = %d, want 0", len(none))
	}
	otherRepo, _ := s.Transitions(ctx, "tenant-a", time.Time{}, time.Time{}, "repo-2")
	if len(otherRepo) != 0 {
		t.Fatalf("other-repository transitions = %d, want 0", len(otherRepo))
	}
	crossTenant, _ := s.Transitions(ctx, "tenant-b", time.Time{}, time.Time{}, "")
	if len(crossTenant) != 0 {
		t.Fatalf("cross-tenant transitions = %d, want 0", len(crossTenant))
	}
}

func TestFindForReadNamesOnlyMatchingPacks(t *testing.T) {
	s := NewGrantStore()
	ctx := context.Background()
	if err := s.Insert(ctx, grant("g-1", "tenant-a", "auditor-1"), ""); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.FindForRead(ctx, "tenant-a", "auditor-1", "pack-1"); len(got) != 1 {
		t.Fatalf("named pack lookup = %d, want 1", len(got))
	}
	if got, _ := s.FindForRead(ctx, "tenant-a", "auditor-1", "pack-2"); len(got) != 0 {
		t.Fatalf("unnamed pack lookup = %d, want 0", len(got))
	}
	if got, _ := s.FindForRead(ctx, "tenant-a", "auditor-2", "pack-1"); len(got) != 0 {
		t.Fatalf("other auditor lookup = %d, want 0", len(got))
	}
}

func TestListReturnsCopiesInIssueOrder(t *testing.T) {
	s := NewGrantStore()
	ctx := context.Background()
	first := grant("g-1", "tenant-a", "auditor-1")
	first.IssuedAt = base
	second := grant("g-2", "tenant-a", "auditor-1")
	second.IssuedAt = base.Add(time.Minute)
	if err := s.Insert(ctx, second, ""); err != nil {
		t.Fatal(err)
	}
	if err := s.Insert(ctx, first, ""); err != nil {
		t.Fatal(err)
	}
	got, err := s.List(ctx, "tenant-a", "")
	if err != nil || len(got) != 2 || got[0].GrantID != "g-1" || got[1].GrantID != "g-2" {
		t.Fatalf("list = %+v err=%v, want issue order", got, err)
	}
	// Mutating a returned grant must not reach into the store.
	got[0].PackIDs[0] = "tampered"
	fresh, _ := s.List(ctx, "tenant-a", "")
	if fresh[0].PackIDs[0] != "pack-1" {
		t.Fatal("store handed out its own slice")
	}
}
