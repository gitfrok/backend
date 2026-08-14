// The dashboard read shape (SPEC-0026): the tenant-wide ListFindings derives
// the readable repository set server-side per request — never from a
// caller-asserted repository_id — and the dashboard filters (age bounds,
// owning team) actually narrow results end to end. Merge-request findings
// reads accept the same empty-repository context (SPEC-0026 AC6).
package app_test

import (
	"context"
	"errors"
	"testing"
	"time"

	policyapi "github.com/gitfrok/backend/modules/policy/api"
	"github.com/gitfrok/backend/modules/security/api"
	"github.com/gitfrok/backend/modules/security/internal/app"
	"github.com/gitfrok/backend/platform/bus"
)

// selectivePDP allows everything except findings.read decisions on the
// repositories it is told to deny.
type selectivePDP struct {
	denyRepos map[string]bool
	requests  []policyapi.Request
}

func (p *selectivePDP) Decide(_ context.Context, req policyapi.Request) (policyapi.Decision, error) {
	p.requests = append(p.requests, req)
	if req.Action == "findings.read" && req.Resource.Type == "repository" && p.denyRepos[req.Resource.ID] {
		return policyapi.Decision{Allowed: false, DecisionID: "dec-deny"}, nil
	}
	return policyapi.Decision{Allowed: true, DecisionID: "dec-allow"}, nil
}

func newSelectiveSvc(deny ...string) (*app.Service, *app.MemoryStore, *selectivePDP) {
	pdp := &selectivePDP{denyRepos: map[string]bool{}}
	for _, r := range deny {
		pdp.denyRepos[r] = true
	}
	store := app.NewMemoryStore()
	svc := app.New(store, pdp, bus.NewInProcess())
	return svc, store, pdp
}

func ingestFor(t *testing.T, svc *app.Service, repoID, reqID string, scan api.Scan, findings ...api.RawFinding) {
	t.Helper()
	chunk := api.IngestChunk{
		Context:    api.Context{TenantID: "t-1", RepositoryID: repoID, ActorID: "actor-1", RequestID: reqID},
		Revision:   "rev-1",
		Scan:       scan,
		Findings:   findings,
		ChunkIndex: 0, FinalChunk: true,
	}
	if _, err := svc.IngestScanResults(context.Background(), chunk); err != nil {
		t.Fatalf("ingest %s: %v", repoID, err)
	}
}

// tenantWideCtx is the BFF shape of a dashboard read (SPEC-0026 AC6): the
// repository scope is server-derived, so the context names none.
func tenantWideCtx() api.Context {
	return api.Context{TenantID: "t-1", RepositoryID: "", ActorID: "actor-1", RequestID: "req-read"}
}

// wallScan is a SAST scan started offset from the wall clock: the memory
// store measures finding age from the scan's start time against now.
func wallScan(offset time.Duration) api.Scan {
	start := time.Now().UTC().Add(offset)
	return api.Scan{
		ScannerClass: api.ScannerClassSAST, ToolName: "semgrep", ToolVersion: "1.99.0",
		StartedAt: start, EndedAt: start.Add(time.Minute),
	}
}

func ruleNames(rows []api.Finding) map[string]bool {
	out := map[string]bool{}
	for _, f := range rows {
		out[f.RuleID] = true
	}
	return out
}

// A tenant-wide listing (no repository in the context) derives the readable
// repository set server-side from per-repo PDP decisions and never leaks a
// repository the caller cannot read (SPEC-0026 AC6).
func TestTenantWideListDerivesReadableRepositories(t *testing.T) {
	svc, _, pdp := newSelectiveSvc("repo-2")
	ctx := context.Background()
	ingestFor(t, svc, "repo-1", "req-a", wallScan(0), rawFinding("rule-1", "a.py", "fn-a"))
	ingestFor(t, svc, "repo-2", "req-b", wallScan(0), rawFinding("rule-2", "b.py", "fn-b"))

	page, err := svc.ListFindings(ctx, api.ListRequest{Context: tenantWideCtx()})
	if err != nil {
		t.Fatalf("tenant-wide listing must succeed with an empty repository, got %v", err)
	}
	if len(page.Findings) != 1 || page.Findings[0].RuleID != "rule-1" || page.Findings[0].RepositoryID != "repo-1" {
		t.Fatalf("tenant-wide listing must serve only readable repositories, got %+v", page.Findings)
	}
	// The derivation asked the PDP about BOTH repositories holding findings.
	asked := map[string]bool{}
	for _, r := range pdp.requests {
		if r.Action == "findings.read" && r.Resource.Type == "repository" {
			asked[r.Resource.ID] = true
		}
	}
	if !asked["repo-1"] || !asked["repo-2"] {
		t.Fatalf("readable set must be derived per request over all candidates, asked=%v", asked)
	}

	// A repository filter inside the readable set narrows; outside it is the
	// coarse denial, whether the repository holds findings or not.
	page, err = svc.ListFindings(ctx, api.ListRequest{Context: tenantWideCtx(), RepositoryFilter: "repo-1"})
	if err != nil || len(page.Findings) != 1 {
		t.Fatalf("readable repository filter: %+v err=%v", page, err)
	}
	if _, err := svc.ListFindings(ctx, api.ListRequest{Context: tenantWideCtx(), RepositoryFilter: "repo-2"}); !errors.Is(err, api.ErrDenied) {
		t.Fatalf("an unreadable repository filter must deny, got %v", err)
	}
	if _, err := svc.ListFindings(ctx, api.ListRequest{Context: tenantWideCtx(), RepositoryFilter: "repo-9"}); !errors.Is(err, api.ErrDenied) {
		t.Fatalf("an unknown repository filter must deny like an unreadable one, got %v", err)
	}

	// The single-repository shape is unchanged: a context naming the
	// repository reads it, naming an unreadable one denies, and a mismatched
	// filter denies.
	single := api.Context{TenantID: "t-1", RepositoryID: "repo-1", ActorID: "actor-1", RequestID: "req-read"}
	if page, err := svc.ListFindings(ctx, api.ListRequest{Context: single}); err != nil || len(page.Findings) != 1 {
		t.Fatalf("single-repo listing: %+v err=%v", page, err)
	}
	denied := api.Context{TenantID: "t-1", RepositoryID: "repo-2", ActorID: "actor-1", RequestID: "req-read"}
	if _, err := svc.ListFindings(ctx, api.ListRequest{Context: denied}); !errors.Is(err, api.ErrDenied) {
		t.Fatalf("single-repo listing of an unreadable repository must deny, got %v", err)
	}
	if _, err := svc.ListFindings(ctx, api.ListRequest{Context: single, RepositoryFilter: "repo-2"}); !errors.Is(err, api.ErrDenied) {
		t.Fatalf("a foreign repository filter on a single-repo read must deny, got %v", err)
	}

	// Fail closed: when nothing is readable the listing is an honest empty
	// page, never a leak and never a distinguishable error.
	svc2, _, _ := newSelectiveSvc("repo-1", "repo-2")
	ingestFor(t, svc2, "repo-1", "req-c", wallScan(0), rawFinding("rule-3", "c.py", "fn-c"))
	page, err = svc2.ListFindings(ctx, api.ListRequest{Context: tenantWideCtx()})
	if err != nil || len(page.Findings) != 0 {
		t.Fatalf("an empty readable set must yield an empty page, got %+v err=%v", page, err)
	}
}

// The dashboard filters — min/max age and owning team — narrow the listing
// end to end on both read shapes (SPEC-0026 AC2).
func TestDashboardFiltersNarrowResults(t *testing.T) {
	svc, store, _ := newSelectiveSvc()
	ctx := context.Background()
	// One finding first seen ~10 days ago, one first seen now.
	ingestFor(t, svc, "repo-1", "req-old", wallScan(-10*24*time.Hour), rawFinding("rule-old", "old.py", "fn-old"))
	ingestFor(t, svc, "repo-1", "req-new", wallScan(0), rawFinding("rule-new", "new.py", "fn-new"))
	if err := store.SetRepositoryOwningTeam(ctx, "t-1", "repo-1", "team-a"); err != nil {
		t.Fatalf("ownership feed: %v", err)
	}

	cases := []struct {
		name string
		req  api.ListRequest
		want []string
	}{
		{"unfiltered", api.ListRequest{}, []string{"rule-old", "rule-new"}},
		{"max age keeps the young", api.ListRequest{MaxAgeDays: 5}, []string{"rule-new"}},
		{"min age keeps the old", api.ListRequest{MinAgeDays: 5}, []string{"rule-old"}},
		{"owning team match", api.ListRequest{OwningTeamFilter: "team-a"}, []string{"rule-old", "rule-new"}},
		{"owning team mismatch", api.ListRequest{OwningTeamFilter: "team-b"}, nil},
		{"age and team compose", api.ListRequest{MinAgeDays: 5, OwningTeamFilter: "team-a"}, []string{"rule-old"}},
	}
	for _, shape := range []struct {
		name string
		ctx  api.Context
	}{
		{"tenant-wide", tenantWideCtx()},
		{"single-repo", api.Context{TenantID: "t-1", RepositoryID: "repo-1", ActorID: "actor-1", RequestID: "req-read"}},
	} {
		for _, tc := range cases {
			t.Run(shape.name+"/"+tc.name, func(t *testing.T) {
				req := tc.req
				req.Context = shape.ctx
				page, err := svc.ListFindings(ctx, req)
				if err != nil {
					t.Fatalf("list: %v", err)
				}
				want := map[string]bool{}
				for _, r := range tc.want {
					want[r] = true
				}
				got := ruleNames(page.Findings)
				if len(got) != len(want) {
					t.Fatalf("filters did not narrow: got %v, want %v", got, want)
				}
				for r := range want {
					if !got[r] {
						t.Fatalf("filters did not narrow: got %v, want %v", got, want)
					}
				}
			})
		}
	}
}

// Merge-request findings reads accept the tenant-wide shape: an empty
// repository matches the projection's server-derived one, a named one must
// match it (SPEC-0026 AC6, SPEC-0028).
func TestMergeRequestFindingsAcceptsEmptyRepository(t *testing.T) {
	h := newHarness(true)
	ctx := context.Background()
	h.svc.SetMergeBaseResolver(&fakeResolver{base: "rev-base", found: true})
	if _, err := h.svc.IngestScanResults(ctx, chunkAt("rev-base", "req-b", 0,
		rawFinding("rule-old", "old.py", "fn-old"))); err != nil {
		t.Fatalf("base scan: %v", err)
	}
	if _, err := h.svc.IngestScanResults(ctx, chunkAt("rev-head", "req-h", time.Hour,
		rawFinding("rule-old", "old.py", "fn-old"), rawFinding("rule-new", "new.py", "fn-new"))); err != nil {
		t.Fatalf("head scan: %v", err)
	}
	announceMR(h, "rev-head")

	// Empty repository: the BFF shape succeeds and serves the comparison.
	req := mrRequest()
	req.RepositoryID = ""
	page, err := h.svc.ListMergeRequestFindings(ctx, req)
	if err != nil {
		t.Fatalf("an empty repository must be accepted, got %v", err)
	}
	if len(page.Views) != 2 || page.Summary.Status != api.AttributionAttributed {
		t.Fatalf("unexpected page: views=%d summary=%+v", len(page.Views), page.Summary)
	}

	// The projection's own repository still matches; a foreign one denies
	// like an unknown merge request.
	req = mrRequest()
	req.RepositoryID = "repo-1"
	if _, err := h.svc.ListMergeRequestFindings(ctx, req); err != nil {
		t.Fatalf("the projection's repository must match, got %v", err)
	}
	req = mrRequest()
	req.RepositoryID = "repo-9"
	if _, err := h.svc.ListMergeRequestFindings(ctx, req); !errors.Is(err, api.ErrDenied) {
		t.Fatalf("a foreign repository must deny, got %v", err)
	}

	// Tenant, actor and request ID remain mandatory on the MR path.
	req = mrRequest()
	req.RepositoryID = ""
	req.ActorID = ""
	if _, err := h.svc.ListMergeRequestFindings(ctx, req); !errors.Is(err, api.ErrDenied) {
		t.Fatalf("a context without an actor must deny, got %v", err)
	}
}
