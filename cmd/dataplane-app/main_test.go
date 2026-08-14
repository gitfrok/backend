package main

import (
	"context"
	"testing"

	"github.com/gitfrok/backend/modules/ci"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
)

// denyAll is the PDP the composition tests run on. They are about module wiring, not about
// authorization, and a stub that denies is the honest thing to hand them: the real PDP needs a
// policy bundle, and a permissive stub would be the exact "answers without consulting policy"
// shortcut modules/policy deliberately offers no constructor for.
type denyAll struct{}

func (denyAll) Decide(context.Context, policyapi.Request) (policyapi.Decision, error) {
	return policyapi.Decision{Reason: "denied: test stub"}, nil
}

// T-0008 AC4: composition happens here, in the plane binary, not inside a module. These tests
// assert on that composition — that the two modules, wired only through the bus and each other's
// api/, produce the end-to-end behaviour neither has alone.

// TestWiringConnectsTheModules: creating a repository in the Repository context makes it appear in
// the Code Search projection, with no module knowing the other was wired in.
func TestWiringConnectsTheModules(t *testing.T) {
	dp := newDataplane(denyAll{}, ci.RunnerConfig{}, nil, nil)
	ctx := t.Context()

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
	dp := newDataplane(denyAll{}, ci.RunnerConfig{}, nil, nil)
	ctx := t.Context()

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
	dp := newDataplane(denyAll{}, ci.RunnerConfig{}, nil, nil)
	// Compile-time: these fields are declared as the api/ interfaces, not concrete services.
	if dp.repositories == nil || dp.searchIndex == nil {
		t.Fatal("dataplane must expose both contexts")
	}
}

// TestPlaneRefusesToBuildWithoutAPDP: a plane with no decision point would let every protected
// action through unchecked, or crash on the first one. Neither is discoverable at wiring time
// unless this is, so the omission is refused where it is made (invariant 2).
func TestPlaneRefusesToBuildWithoutAPDP(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("newDataplane(nil, ci.RunnerConfig{}, nil, nil) built a plane with no PDP")
		}
	}()
	newDataplane(nil, ci.RunnerConfig{}, nil, nil)
}

// TestPlaneHoldsThePDPAsAPort: held as api.DecisionPoint, so extracting Policy into its own
// service (ADR-0026) swaps the constructor here and changes no caller.
func TestPlaneHoldsThePDPAsAPort(t *testing.T) {
	dp := newDataplane(denyAll{}, ci.RunnerConfig{}, nil, nil)

	got, err := dp.policy.Decide(t.Context(), policyapi.Request{TenantID: "t-1", Action: "repo.read"})
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if got.Allowed {
		t.Error("the stub PDP allowed something")
	}
}
