package app_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/gitfrok/backend/modules/repository/api"
	"github.com/gitfrok/backend/modules/repository/internal/adapters/memstore"
	"github.com/gitfrok/backend/modules/repository/internal/app"
	"github.com/gitfrok/backend/platform/bus"
)

// SPEC-0052 AC4 and AC5: the listable set is the PDP's, derived at request
// time, and the page carries no total.
//
// The criterion that matters most is that "you may see none" and "there are
// none" are the SAME answer — an empty list, never an error. A list is the
// first Repository surface where an empty answer is a claim about the world,
// and the claim has to be one this context can support.

// allowPDP allows exactly the repository IDs in its set. It fills the Repository context's own
// Authorizer port — the module is a leaf and does not import the Policy context, so the real
// adapter lives in the composition root.
type allowPDP struct {
	allowed map[string]bool
	err     error
	asked   []string
}

func (p *allowPDP) MayRead(_ context.Context, _, _ string, _ []string, repoID string) (bool, error) {
	p.asked = append(p.asked, repoID)
	if p.err != nil {
		return false, p.err
	}
	return p.allowed[repoID], nil
}

func seed(t *testing.T, svc api.Repositories, tenant string, names ...string) {
	t.Helper()
	for _, n := range names {
		if _, err := svc.Create(context.Background(), tenant, n, n, "actor-1"); err != nil {
			t.Fatalf("seeding %s: %v", n, err)
		}
	}
}

func listService(auth api.Authorizer) api.Repositories {
	return app.New(memstore.New(), bus.NewInProcess(), app.WithAuthorizer(auth))
}

func query(tenant string) api.ListQuery {
	return api.ListQuery{TenantID: tenant, ActorID: "actor-1", ActorRoles: []string{"member"}, PageSize: 10}
}

func TestListReturnsOnlyWhatThePDPAllows(t *testing.T) {
	pdp := &allowPDP{allowed: map[string]bool{"alpha": true, "gamma": true}}
	svc := listService(pdp)
	seed(t, svc, "tenant-a", "alpha", "beta", "gamma")

	page, err := svc.List(context.Background(), query("tenant-a"))
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	got := idsOf(page)
	want := []string{"alpha", "gamma"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("listed %v, want %v", got, want)
	}
	// One decision per candidate, at request time — never a cached permission set.
	if len(pdp.asked) != 3 {
		t.Fatalf("asked the PDP about %d repositories, want 3 (one per candidate)", len(pdp.asked))
	}
}

func TestListOfACallerAllowedNothingIsAnEmptyListNotAnError(t *testing.T) {
	// "You may see none" and "there are none" must be the same answer: an
	// error here would tell a caller that something exists to be refused.
	svc := listService(&allowPDP{allowed: map[string]bool{}})
	seed(t, svc, "tenant-a", "alpha", "beta")

	page, err := svc.List(context.Background(), query("tenant-a"))
	if err != nil {
		t.Fatalf("a caller allowed nothing must get an empty list, got error: %v", err)
	}
	if len(page.Repositories) != 0 {
		t.Fatalf("listed %v, want nothing", idsOf(page))
	}
	if page.NextPageToken != "" {
		t.Fatal("an empty page must not offer a next page")
	}
}

func TestListTreatsAPDPErrorAsARefusalForThatRepository(t *testing.T) {
	// Deny-by-default: an error is not a third outcome to work around
	// (ADR-0006). It must not fail the whole list either, or one unavailable
	// decision would make every repository disappear.
	svc := listService(&allowPDP{err: errors.New("pdp down")})
	seed(t, svc, "tenant-a", "alpha")

	page, err := svc.List(context.Background(), query("tenant-a"))
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(page.Repositories) != 0 {
		t.Fatalf("a PDP error must refuse, listed %v", idsOf(page))
	}
}

func TestListRefusesWhenNoDecisionPointIsWired(t *testing.T) {
	// An unauthorized list is not an empty list. Returning nothing would read
	// as "you may see nothing", which is a decision this service did not make.
	svc := app.New(memstore.New(), bus.NewInProcess())
	if _, err := svc.List(context.Background(), query("tenant-a")); !errors.Is(err, api.ErrNoDecisionPoint) {
		t.Fatalf("want ErrNoDecisionPoint, got %v", err)
	}
}

func TestListIsTenantScoped(t *testing.T) {
	pdp := &allowPDP{allowed: map[string]bool{"alpha": true, "other": true}}
	svc := listService(pdp)
	seed(t, svc, "tenant-a", "alpha")
	seed(t, svc, "tenant-b", "other")

	page, err := svc.List(context.Background(), query("tenant-a"))
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if got := idsOf(page); fmt.Sprint(got) != fmt.Sprint([]string{"alpha"}) {
		t.Fatalf("listed %v across tenants, want only alpha", got)
	}
	// The other tenant's repository was never even a candidate, so the PDP was
	// never asked about it: tenant scope is a store property, not a filter.
	for _, id := range pdp.asked {
		if id == "other" {
			t.Fatal("asked the PDP about another tenant's repository")
		}
	}
}

func TestListRefusesAQueryWithoutATenant(t *testing.T) {
	svc := listService(&allowPDP{allowed: map[string]bool{}})
	if _, err := svc.List(context.Background(), api.ListQuery{ActorID: "actor-1"}); err == nil {
		t.Fatal("a list without a tenant must be refused, not evaluated globally")
	}
}

func TestListPagesByOpaqueTokenAndCarriesNoTotal(t *testing.T) {
	allowed := map[string]bool{}
	names := []string{"a1", "a2", "a3", "a4", "a5"}
	for _, n := range names {
		allowed[n] = true
	}
	svc := listService(&allowPDP{allowed: allowed})
	seed(t, svc, "tenant-a", names...)

	q := query("tenant-a")
	q.PageSize = 2

	var seen []string
	for round := 0; round < 10; round++ {
		page, err := svc.List(context.Background(), q)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		seen = append(seen, idsOf(page)...)
		if page.NextPageToken == "" {
			break
		}
		if page.NextPageToken == q.PageToken {
			t.Fatal("the cursor did not advance")
		}
		q.PageToken = page.NextPageToken
	}
	if fmt.Sprint(seen) != fmt.Sprint(names) {
		t.Fatalf("paged %v, want %v", seen, names)
	}
}

func TestListRefusesACursorMintedForAnotherTenant(t *testing.T) {
	allowed := map[string]bool{"a1": true, "a2": true, "a3": true}
	svc := listService(&allowPDP{allowed: allowed})
	seed(t, svc, "tenant-a", "a1", "a2", "a3")
	seed(t, svc, "tenant-b", "b1")

	q := query("tenant-a")
	q.PageSize = 1
	first, err := svc.List(context.Background(), q)
	if err != nil {
		t.Fatalf("list: %v", err)
	}

	// Replaying tenant A's cursor as tenant B must be refused rather than
	// silently reinterpreted: a cursor is bounded to the tenant that minted it.
	stolen := query("tenant-b")
	stolen.PageToken = first.NextPageToken
	if _, err := svc.List(context.Background(), stolen); err == nil {
		t.Fatal("a cursor from another tenant must be refused")
	}
}

func TestListRefusesAMalformedCursor(t *testing.T) {
	svc := listService(&allowPDP{allowed: map[string]bool{"a1": true}})
	seed(t, svc, "tenant-a", "a1")
	q := query("tenant-a")
	q.PageToken = "not-a-cursor"
	if _, err := svc.List(context.Background(), q); err == nil {
		t.Fatal("a malformed cursor must be refused, not treated as the beginning")
	}
}

func idsOf(p api.ListPage) []string {
	out := make([]string, 0, len(p.Repositories))
	for _, r := range p.Repositories {
		out = append(out, r.RepoID)
	}
	return out
}
