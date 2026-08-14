package app_test

import (
	"context"
	"sync"
	"testing"
	"time"

	csapi "github.com/gitfrok/backend/modules/codesearch/api"
	"github.com/gitfrok/backend/modules/codesearch/internal/app"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
	repoapi "github.com/gitfrok/backend/modules/repository/api"
	"github.com/gitfrok/backend/platform/bus"
)

// These tests pin the security statements of SPEC-0034 and SPEC-0035: the searchable repository
// set is derived server-side at query time, a revocation binds on the next query (and on every
// page of an old cursor), counts and "more" exist only over authorized matches, and the one
// refusal shape never distinguishes unauthorized from no-match.

// rulePDP answers from mutable per-resource rules so a test can revoke between queries. The zero
// decision denies, exactly like the real PDP's fail-closed shape.
type rulePDP struct {
	mu         sync.Mutex
	repoAllow  map[string]bool
	tenantDeny bool
	errOnRead  bool
}

func (p *rulePDP) Decide(_ context.Context, req policyapi.Request) (policyapi.Decision, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	switch req.Action {
	case "search.query":
		if p.tenantDeny {
			return policyapi.Decision{}, nil
		}
		return policyapi.Decision{Allowed: true, DecisionID: "dec-q"}, nil
	case "search.read", "search.index.status.read":
		if p.errOnRead {
			return policyapi.Decision{}, context.DeadlineExceeded
		}
		if p.repoAllow[req.Resource.ID] {
			return policyapi.Decision{Allowed: true, DecisionID: "dec-r"}, nil
		}
	}
	return policyapi.Decision{}, nil
}

func (p *rulePDP) set(repo string, allow bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.repoAllow[repo] = allow
}

// fakeContent is the repository-content route for tests: the same port the gRPC adapter fills in
// the plane (ADR-0022, SPEC-0035 AC7).
type fakeContent struct {
	files map[string][]csapi.FileEntry
	blobs map[string][]byte
}

func (f *fakeContent) key(tenant, repo, revision string, path string) string {
	return tenant + "/" + repo + "/" + revision + "/" + path
}

func (f *fakeContent) ListFiles(_ context.Context, tenantID, repoID, revision string) ([]csapi.FileEntry, error) {
	return f.files[tenantID+"/"+repoID+"/"+revision], nil
}

func (f *fakeContent) ReadFile(_ context.Context, tenantID, repoID, revision, path string) ([]byte, error) {
	return f.blobs[f.key(tenantID, repoID, revision, path)], nil
}

func (f *fakeContent) put(tenant, repo, revision, path string, content string) {
	k := tenant + "/" + repo + "/" + revision
	f.files[k] = append(f.files[k], csapi.FileEntry{Path: path, SizeBytes: int64(len(content))})
	f.blobs[f.key(tenant, repo, revision, path)] = []byte(content)
}

// newSearchHarness wires the context the way cmd/ does: projection on the bus, content source
// attached, worker running. It returns once every admitted revision is absorbed.
func newSearchHarness(t *testing.T, pdp policyapi.DecisionPoint, content csapi.ContentSource) (*app.Service, bus.Bus) {
	t.Helper()
	b := bus.NewInProcess()
	reader := newReader(
		repoapi.RepositoryView{TenantID: "t-1", RepoID: "repo-a", Name: "alpha"},
		repoapi.RepositoryView{TenantID: "t-1", RepoID: "repo-b", Name: "beta"},
	)
	svc := app.NewService(reader, pdp, b, content, app.Config{})
	svc.Register(b)

	ctx := t.Context()
	for _, repo := range []string{"repo-a", "repo-b"} {
		if err := b.Publish(ctx, created("t-1", repo)); err != nil {
			t.Fatalf("publish created(%s): %v", repo, err)
		}
		err := b.Publish(ctx, repoapi.RefUpdated{
			EventID: "01ARYZ6S4100000000000000" + repo[len(repo)-1:], TenantID: "t-1", RepoID: repo,
			Ref: "refs/heads/main", NewSha: "rev-1", ActorID: "user-9", OccurredAt: time.Now().UTC(),
		})
		if err != nil {
			t.Fatalf("publish ref(%s): %v", repo, err)
		}
	}
	if err := svc.Drain(ctx); err != nil {
		t.Fatalf("Drain: %v", err)
	}
	return svc, b
}

func query(text string) csapi.Query {
	return csapi.Query{
		TenantID: "t-1", ActorID: "user-9", ActorRoles: []string{"member"},
		RequestID: "req-1", Text: text, Mode: csapi.QueryModeSubstring,
	}
}

// TestSearchFiltersByPermissionAtQueryTime: two repositories hold the same marker; only the
// authorized one appears. The scope is a server fact at query time — the Query type has no field
// a caller could widen it with (SPEC-0034 AC2, SPEC-0035 AC2).
func TestSearchFiltersByPermissionAtQueryTime(t *testing.T) {
	content := &fakeContent{files: map[string][]csapi.FileEntry{}, blobs: map[string][]byte{}}
	content.put("t-1", "repo-a", "rev-1", "a.go", "func needletoken() {}\n")
	content.put("t-1", "repo-b", "rev-1", "b.go", "func needletoken() {}\n")
	pdp := &rulePDP{repoAllow: map[string]bool{"repo-a": true}}
	svc, _ := newSearchHarness(t, pdp, content)

	page, err := svc.Search(t.Context(), query("needletoken"))
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(page.Matches) != 1 || page.Matches[0].RepositoryID != "repo-a" {
		t.Fatalf("want exactly the authorized repository's match, got %+v", page.Matches)
	}
	if page.Matches[0].Revision != "rev-1" {
		t.Errorf("want the indexed revision, got %q", page.Matches[0].Revision)
	}
}

// TestUnauthorizedOnlyIsTheZeroPage: a query whose only matches sit in repositories the caller
// may not read returns the zero Page — bit-for-bit the shape of a no-match query (SPEC-0034 AC3,
// SPEC-0035 AC4).
func TestUnauthorizedOnlyIsTheZeroPage(t *testing.T) {
	content := &fakeContent{files: map[string][]csapi.FileEntry{}, blobs: map[string][]byte{}}
	content.put("t-1", "repo-b", "rev-1", "b.go", "func needletoken() {}\n")
	pdp := &rulePDP{repoAllow: map[string]bool{}}
	svc, _ := newSearchHarness(t, pdp, content)

	unauthorizedOnly, err := svc.Search(t.Context(), query("needletoken"))
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	noMatch, err := svc.Search(t.Context(), query("zzzznothing"))
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(unauthorizedOnly.Matches) != 0 || unauthorizedOnly.NextPageToken != "" {
		t.Fatalf("unauthorized-only must be the zero Page, got %+v", unauthorizedOnly)
	}
	if len(noMatch.Matches) != 0 || noMatch.NextPageToken != "" {
		t.Fatalf("no-match must be the zero Page, got %+v", noMatch)
	}
}

// TestRevocationBindsOnNextQuery: scope is re-derived on every query, so a revocation takes
// effect immediately — no cache cycle, no reindex, no cursor reuse serves revoked content
// (SPEC-0034 AC6, SPEC-0035 AC5).
func TestRevocationBindsOnNextQuery(t *testing.T) {
	content := &fakeContent{files: map[string][]csapi.FileEntry{}, blobs: map[string][]byte{}}
	content.put("t-1", "repo-a", "rev-1", "a.go", "needletoken one\nneedletoken two\n")
	pdp := &rulePDP{repoAllow: map[string]bool{"repo-a": true}}
	svc, _ := newSearchHarness(t, pdp, content)

	q := query("needletoken")
	q.ResultLimit = 1
	before, err := svc.Search(t.Context(), q)
	if err != nil {
		t.Fatalf("Search before: %v", err)
	}
	if len(before.Matches) != 1 || before.NextPageToken == "" {
		t.Fatalf("want one match and a continuation cursor, got %+v", before)
	}

	pdp.set("repo-a", false)
	after, err := svc.Search(t.Context(), q)
	if err != nil {
		t.Fatalf("Search after revocation: %v", err)
	}
	if len(after.Matches) != 0 || after.NextPageToken != "" {
		t.Fatalf("revoked content must vanish on the next query, got %+v", after)
	}

	// Paging with the pre-revocation cursor re-runs enforcement: the token verifies, but the
	// re-derived scope is empty, so it yields no content.
	q.PageToken = before.NextPageToken
	resumed, err := svc.Search(t.Context(), q)
	if err != nil {
		t.Fatalf("Search with old cursor: %v", err)
	}
	if len(resumed.Matches) != 0 || resumed.NextPageToken != "" {
		t.Fatalf("an old cursor must not serve revoked content, got %+v", resumed)
	}
}

// TestForgedCursorYieldsNoContent: a tampered, malformed, or query-mismatched token returns the
// zero Page — never an error that distinguishes it from an empty result (SPEC-0035 AC1).
func TestForgedCursorYieldsNoContent(t *testing.T) {
	content := &fakeContent{files: map[string][]csapi.FileEntry{}, blobs: map[string][]byte{}}
	content.put("t-1", "repo-a", "rev-1", "a.go", "needletoken one\nneedletoken two\n")
	pdp := &rulePDP{repoAllow: map[string]bool{"repo-a": true}}
	svc, _ := newSearchHarness(t, pdp, content)

	q := query("needletoken")
	q.ResultLimit = 1
	first, err := svc.Search(t.Context(), q)
	if err != nil || first.NextPageToken == "" {
		t.Fatalf("want a continuation cursor, got %+v (err %v)", first, err)
	}

	cases := map[string]string{
		"tampered":    first.NextPageToken[:len(first.NextPageToken)-2] + "AA",
		"malformed":   "not-a-cursor",
		"other query": first.NextPageToken, // valid signature, but replayed under a different text below
	}
	for name, token := range cases {
		qq := q
		qq.PageToken = token
		if name == "other query" {
			qq.Text = "differentquerytext"
		}
		page, err := svc.Search(t.Context(), qq)
		if err != nil {
			t.Fatalf("%s: a bad cursor must not error, got %v", name, err)
		}
		if len(page.Matches) != 0 || page.NextPageToken != "" {
			t.Fatalf("%s: a bad cursor must yield the zero Page, got %+v", name, page)
		}
	}
}

// TestPaginationStaysAuthorized: a legitimate second page continues the same enforcement and
// terminates — the cursor binds to tenant and query and expires (SPEC-0035 AC1/AC5).
func TestPaginationStaysAuthorized(t *testing.T) {
	content := &fakeContent{files: map[string][]csapi.FileEntry{}, blobs: map[string][]byte{}}
	content.put("t-1", "repo-a", "rev-1", "a.go", "needletoken one\nneedletoken two\n")
	pdp := &rulePDP{repoAllow: map[string]bool{"repo-a": true}}
	svc, _ := newSearchHarness(t, pdp, content)

	q := query("needletoken")
	q.ResultLimit = 1
	first, err := svc.Search(t.Context(), q)
	if err != nil || len(first.Matches) != 1 {
		t.Fatalf("page 1: %+v (err %v)", first, err)
	}
	q.PageToken = first.NextPageToken
	second, err := svc.Search(t.Context(), q)
	if err != nil || len(second.Matches) != 1 {
		t.Fatalf("page 2: %+v (err %v)", second, err)
	}
	if second.Matches[0].LineStart == first.Matches[0].LineStart {
		t.Fatalf("page 2 must advance, got the same match %+v", second.Matches[0])
	}
	if second.NextPageToken != "" {
		t.Fatalf("want the last page to carry no cursor, got %q", second.NextPageToken)
	}
}

// TestTenantLevelDenialRefusesWhole: when the tenant-level search.query decision is denied, the
// query is refused with the coarse error regardless of per-repository permissions (SPEC-0035
// vocabulary). A PDP that cannot be reached denies just the same (ADR-0006).
func TestTenantLevelDenialRefusesWhole(t *testing.T) {
	content := &fakeContent{files: map[string][]csapi.FileEntry{}, blobs: map[string][]byte{}}
	content.put("t-1", "repo-a", "rev-1", "a.go", "func needletoken() {}\n")
	pdp := &rulePDP{repoAllow: map[string]bool{"repo-a": true}, tenantDeny: true}
	svc, _ := newSearchHarness(t, pdp, content)

	if _, err := svc.Search(t.Context(), query("needletoken")); err != csapi.ErrDenied {
		t.Fatalf("want the coarse denial, got %v", err)
	}

	pdp.mu.Lock()
	pdp.tenantDeny, pdp.errOnRead = false, true
	pdp.mu.Unlock()
	if _, err := svc.Search(t.Context(), query("needletoken")); err != nil {
		t.Fatalf("an unreachable per-repo PDP shrinks the scope, it does not fail the query: %v", err)
	}
}

// TestMalformedRequestsAreCoarse: every shape the contract cannot honour is the same ErrMalformed
// (SPEC-0035 non-functional).
func TestMalformedRequestsAreCoarse(t *testing.T) {
	pdp := &rulePDP{repoAllow: map[string]bool{"repo-a": true}}
	svc, _ := newSearchHarness(t, pdp, &fakeContent{files: map[string][]csapi.FileEntry{}, blobs: map[string][]byte{}})

	cases := map[string]csapi.Query{}
	base := query("text")
	cases["no tenant"] = func() csapi.Query { q := base; q.TenantID = ""; return q }()
	cases["no actor"] = func() csapi.Query { q := base; q.ActorID = ""; return q }()
	cases["no request"] = func() csapi.Query { q := base; q.RequestID = ""; return q }()
	cases["empty text"] = func() csapi.Query { q := base; q.Text = ""; return q }()
	cases["unknown mode"] = func() csapi.Query { q := base; q.Mode = csapi.QueryMode(9); return q }()
	cases["bad regex"] = func() csapi.Query {
		q := base
		q.Mode, q.Text = csapi.QueryModeRegex, "([unclosed"
		return q
	}()
	long := make([]byte, csapi.MaxRegexPatternLength+1)
	for i := range long {
		long[i] = 'a'
	}
	cases["oversized regex"] = func() csapi.Query {
		q := base
		q.Mode, q.Text = csapi.QueryModeRegex, string(long)
		return q
	}()
	for name, q := range cases {
		if _, err := svc.Search(t.Context(), q); err != csapi.ErrMalformed {
			t.Errorf("%s: want ErrMalformed, got %v", name, err)
		}
	}
}

// TestGetIndexStatusOnlyReadable: freshness is reported per repository the caller may read and
// nothing for others — not even existence (SPEC-0035 AC6).
func TestGetIndexStatusOnlyReadable(t *testing.T) {
	content := &fakeContent{files: map[string][]csapi.FileEntry{}, blobs: map[string][]byte{}}
	content.put("t-1", "repo-a", "rev-1", "a.go", "x := 1\n")
	content.put("t-1", "repo-b", "rev-1", "b.go", "y := 2\n")
	pdp := &rulePDP{repoAllow: map[string]bool{"repo-a": true}}
	svc, _ := newSearchHarness(t, pdp, content)

	entries, err := svc.GetIndexStatus(t.Context(), query(""))
	if err != nil {
		t.Fatalf("GetIndexStatus: %v", err)
	}
	if len(entries) != 1 || entries[0].RepositoryID != "repo-a" {
		t.Fatalf("want only the readable repository, got %+v", entries)
	}
	if entries[0].LastIndexedRevision != "rev-1" {
		t.Errorf("want the absorbed revision, got %q", entries[0].LastIndexedRevision)
	}

	// Status is malformed without its verified context.
	if _, err := svc.GetIndexStatus(t.Context(), csapi.Query{}); err != csapi.ErrMalformed {
		t.Errorf("want ErrMalformed without context, got %v", err)
	}
}

// TestRegexAndSymbolModesArePermissionFiltered: every mode travels the same scope derivation —
// there is no mode that bypasses the filter (SPEC-0034 AC2).
func TestRegexAndSymbolModesArePermissionFiltered(t *testing.T) {
	content := &fakeContent{files: map[string][]csapi.FileEntry{}, blobs: map[string][]byte{}}
	content.put("t-1", "repo-a", "rev-1", "a.go", "func getRefUpdated() {}\n")
	content.put("t-1", "repo-b", "rev-1", "b.go", "func getRefUpdated() {}\n")
	pdp := &rulePDP{repoAllow: map[string]bool{"repo-a": true}}
	svc, _ := newSearchHarness(t, pdp, content)

	re := query("get[A-Z][a-z]+Updated")
	re.Mode = csapi.QueryModeRegex
	page, err := svc.Search(t.Context(), re)
	if err != nil {
		t.Fatalf("regex Search: %v", err)
	}
	if len(page.Matches) != 1 || page.Matches[0].RepositoryID != "repo-a" {
		t.Fatalf("regex: want only the authorized match, got %+v", page.Matches)
	}

	sym := query("RefUpdated")
	sym.Mode = csapi.QueryModeSymbol
	page, err = svc.Search(t.Context(), sym)
	if err != nil {
		t.Fatalf("symbol Search: %v", err)
	}
	if len(page.Matches) != 1 || page.Matches[0].RepositoryID != "repo-a" {
		t.Fatalf("symbol: want only the authorized match, got %+v", page.Matches)
	}
}

// TestTenantIndexSizeMeasuresOnlyOwnTenant: the fair-use measure is tenant-scoped (SPEC-0034
// AC7, PRD §6).
func TestTenantIndexSizeMeasuresOnlyOwnTenant(t *testing.T) {
	content := &fakeContent{files: map[string][]csapi.FileEntry{}, blobs: map[string][]byte{}}
	content.put("t-1", "repo-a", "rev-1", "a.go", "func needletoken() {}\n")
	pdp := &rulePDP{repoAllow: map[string]bool{"repo-a": true}}
	svc, _ := newSearchHarness(t, pdp, content)

	size, err := svc.TenantIndexSize(t.Context(), "t-1")
	if err != nil || size <= 0 {
		t.Fatalf("want a positive footprint, got %d (err %v)", size, err)
	}
	other, err := svc.TenantIndexSize(t.Context(), "t-2")
	if err != nil || other != 0 {
		t.Fatalf("another tenant's footprint must be zero, got %d (err %v)", other, err)
	}
}

// TestLagAboveBoundIsReportedOnce: a revision admitted long before the index absorbs it leaves a
// measured lag above the stated freshness bound, which is published as IndexLagged — reported,
// not silent, and deduped so it is not an event storm (SPEC-0034 AC4).
func TestLagAboveBoundIsReportedOnce(t *testing.T) {
	b := bus.NewInProcess()
	reader := newReader(repoapi.RepositoryView{TenantID: "t-1", RepoID: "repo-a", Name: "alpha"})
	content := &fakeContent{files: map[string][]csapi.FileEntry{}, blobs: map[string][]byte{}}
	content.put("t-1", "repo-a", "rev-1", "a.go", "x := 1\n")
	pdp := &rulePDP{repoAllow: map[string]bool{"repo-a": true}}

	svc := app.NewService(reader, pdp, b, content, app.Config{FreshnessBound: time.Millisecond})
	svc.Register(b)

	var mu sync.Mutex
	var lagged []csapi.IndexLagged
	var indexed []csapi.RepositoryIndexed
	bus.SubscribeTyped(b, func(_ context.Context, e csapi.IndexLagged) error {
		mu.Lock()
		lagged = append(lagged, e)
		mu.Unlock()
		return nil
	})
	bus.SubscribeTyped(b, func(_ context.Context, e csapi.RepositoryIndexed) error {
		mu.Lock()
		indexed = append(indexed, e)
		mu.Unlock()
		return nil
	})

	ctx := t.Context()
	if err := b.Publish(ctx, created("t-1", "repo-a")); err != nil {
		t.Fatalf("publish created: %v", err)
	}
	// Admitted an hour ago: the absorb's measured lag will exceed the millisecond bound.
	err := b.Publish(ctx, repoapi.RefUpdated{
		EventID: "01ARYZ6S4100000000000000L1", TenantID: "t-1", RepoID: "repo-a",
		Ref: "refs/heads/main", NewSha: "rev-1", ActorID: "user-9",
		OccurredAt: time.Now().UTC().Add(-time.Hour),
	})
	if err != nil {
		t.Fatalf("publish ref: %v", err)
	}
	if err := svc.Drain(ctx); err != nil {
		t.Fatalf("Drain: %v", err)
	}
	// A second admission of the same revision re-runs the check without re-reporting it.
	if err := svc.Backfill(ctx); err != nil {
		t.Fatalf("Backfill: %v", err)
	}
	if err := svc.Drain(ctx); err != nil {
		t.Fatalf("Drain 2: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(indexed) == 0 {
		t.Fatal("want the revision absorbed (RepositoryIndexed published)")
	}
	if len(lagged) != 1 {
		t.Fatalf("want exactly one IndexLagged for the bound breach, got %d", len(lagged))
	}
	if lagged[0].Lag <= time.Millisecond || lagged[0].RepositoryID != "repo-a" {
		t.Fatalf("want the measured lag above the bound for repo-a, got %+v", lagged[0])
	}

	// The status surface reports the same measured lag to a reader of the repository.
	entries, err := svc.GetIndexStatus(ctx, query(""))
	if err != nil {
		t.Fatalf("GetIndexStatus: %v", err)
	}
	if len(entries) != 1 || entries[0].FreshnessLag <= time.Millisecond {
		t.Fatalf("want the measured lag in the status entry, got %+v", entries)
	}
}
