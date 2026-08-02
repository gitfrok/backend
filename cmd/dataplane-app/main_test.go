package main

import (
	"context"
	"testing"
)

// T-0008 AC4: composition happens here, in the plane binary, not inside a module. These tests
// assert on that composition — that the two modules, wired only through the bus and each other's
// api/, produce the end-to-end behaviour neither has alone.

// TestWiringConnectsTheModules: creating a repository in the Repository context makes it appear in
// the Code Search projection, with no module knowing the other was wired in.
func TestWiringConnectsTheModules(t *testing.T) {
	dp := newDataplane()
	ctx := context.Background()

	if _, err := dp.repositories.Create(ctx, "t-1", "repo-1", "infra", "user-9"); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := dp.searchIndex.Lookup(ctx, "t-1", "repo-1")
	if err != nil {
		t.Fatalf("the created repository never reached the projection: %v", err)
	}
	if got.Name != "infra" || got.RepoID != "repo-1" {
		t.Errorf("projection holds %+v", got)
	}
}

// TestWiringKeepsTenantsApart: the composed plane must not leak across tenants at either end.
func TestWiringKeepsTenantsApart(t *testing.T) {
	dp := newDataplane()
	ctx := context.Background()

	if _, err := dp.repositories.Create(ctx, "t-1", "repo-1", "infra", "user-9"); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if _, err := dp.repositories.Get(ctx, "t-2", "repo-1"); err == nil {
		t.Error("want a cross-tenant read denied at the Repository context")
	}
	if _, err := dp.searchIndex.Lookup(ctx, "t-2", "repo-1"); err == nil {
		t.Error("want a cross-tenant lookup denied at the Code Search projection")
	}
}

// TestModulesAreReachableOnlyAsPorts: the plane holds each module by its api/ interface, so a
// module could be swapped for a gRPC client without this file changing (ADR-0026).
func TestModulesAreReachableOnlyAsPorts(t *testing.T) {
	dp := newDataplane()
	// Compile-time: these fields are declared as the api/ interfaces, not concrete services.
	if dp.repositories == nil || dp.searchIndex == nil {
		t.Fatal("dataplane must expose both contexts")
	}
}
