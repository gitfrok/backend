package github

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gitfrok/backend/modules/codereview/api"
	"github.com/gitfrok/backend/modules/codereview/internal/app"
)

// memoryRecords is a minimal record store for tests.
type memoryRecords struct {
	records map[string][]api.ImportedMergeRequest
	dead    map[string]bool
}

func newMemoryRecords() *memoryRecords {
	return &memoryRecords{records: map[string][]api.ImportedMergeRequest{}, dead: map[string]bool{}}
}

func (m *memoryRecords) PutImport(_ context.Context, importID string, records []api.ImportedMergeRequest) error {
	if m.dead[importID] {
		return http.ErrBodyNotAllowed
	}
	m.records[importID] = records
	return nil
}

func (m *memoryRecords) ListImport(_ context.Context, importID string) ([]api.ImportedMergeRequest, error) {
	if m.dead[importID] {
		return nil, nil
	}
	return m.records[importID], nil
}

func (m *memoryRecords) Tombstone(_ context.Context, importID string) error {
	m.dead[importID] = true
	return nil
}

// A github API stub serving PRs and reviews.
func newStubServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/repos/acme/widgets/pulls" && r.URL.Query().Get("state") == "open":
			_ = json.NewEncoder(w).Encode([]pullRequest{{
				Number: 1, Title: "Add feature", Body: "Closes #0", State: "open",
				User: ghUser{Login: "alice"}, CreatedAt: time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC),
				Head: ghRef{Ref: "feature/x"}, Base: ghRef{Ref: "main"},
			}})
		case r.URL.Path == "/repos/acme/widgets/pulls" && r.URL.Query().Get("state") == "closed":
			_ = json.NewEncoder(w).Encode([]pullRequest{})
		case r.URL.Path == "/repos/acme/widgets/pulls/1/reviews":
			_ = json.NewEncoder(w).Encode([]pullReview{{
				ID: 11, State: "approved", Body: "LGTM", User: ghUser{Login: "bob"},
				SubmittedAt: time.Date(2024, 1, 3, 0, 0, 0, 0, time.UTC),
			}})
		case r.URL.Path == "/repos/acme/widgets/pulls/1/comments":
			_ = json.NewEncoder(w).Encode([]reviewComment{{
				ID: 31, Body: "This line", Path: "widget.go", Line: 12,
				User: ghUser{Login: "bob"}, CreatedAt: time.Date(2024, 1, 3, 1, 0, 0, 0, time.UTC),
			}, {
				ID: 32, Body: "Outdated line", Path: "widget.go",
				User: ghUser{Login: "bob"}, CreatedAt: time.Date(2024, 1, 3, 2, 0, 0, 0, time.UTC),
			}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

// An import stores PR history with ATTESTED_IMPORT provenance and returns
// counts for the manifest digest (AC4/AC16).
func TestImportHistoryStoresAttestedRecords(t *testing.T) {
	server := newStubServer(t)
	defer server.Close()
	records := newMemoryRecords()
	client := New(records, server.Client())
	client.base = server.URL

	result, err := client.ImportHistory(context.Background(), app.ImportHistoryCommand{
		TenantID: "t", RepositoryID: "r", ImportID: "import-1",
		SourceURL: "https://github.com/acme/widgets.git", SourceSystem: "github", SourceInstance: "github.com",
	})
	if err != nil {
		t.Fatalf("ImportHistory: %v", err)
	}
	if result.Counts["merge_requests"] != 1 || result.Counts["approvals"] != 1 {
		t.Fatalf("counts = %v", result.Counts)
	}

	stored, err := records.ListImport(context.Background(), "import-1")
	if err != nil || len(stored) != 1 {
		t.Fatalf("stored = %v err = %v", stored, err)
	}
	pr := stored[0]
	if pr.Title != "Add feature" || pr.DeclaredCreator != "alice" || pr.State != "open" {
		t.Fatalf("pr = %+v", pr)
	}
	// The load-bearing ADR-0029 facts: provenance class is ATTESTED_IMPORT, the
	// actor is the opaque foreign handle, the digest is set, and declared_at is
	// the source's timestamp (display-only).
	if pr.Provenance.Class != api.AttestImported {
		t.Fatalf("class = %q, want ATTESTED_IMPORT", pr.Provenance.Class)
	}
	if pr.Provenance.DeclaredActor != "alice" || pr.Provenance.SourceRef != "1" {
		t.Fatalf("provenance = %+v", pr.Provenance)
	}
	if pr.Provenance.PayloadDigest == "" {
		t.Fatal("payload digest not set")
	}
	// The approval is display-only: its provenance is attested, so it can never
	// satisfy a merge policy (AC13).
	if len(pr.Approvals) != 1 || pr.Approvals[0].Provenance.Class != api.AttestImported {
		t.Fatalf("approvals = %+v", pr.Approvals)
	}
}

// Review summaries attach to the merge request, line comments keep their diff
// position, and a comment whose line no longer resolves degrades to the file.
// No comment is dropped (AC5).
func TestImportHistoryDegradesAnchors(t *testing.T) {
	server := newStubServer(t)
	defer server.Close()
	records := newMemoryRecords()
	client := New(records, server.Client())
	client.base = server.URL

	result, err := client.ImportHistory(context.Background(), app.ImportHistoryCommand{
		TenantID: "t", RepositoryID: "r", ImportID: "import-1",
		SourceURL: "https://github.com/acme/widgets.git", SourceSystem: "github", SourceInstance: "github.com",
	})
	if err != nil {
		t.Fatalf("ImportHistory: %v", err)
	}
	if result.Counts["comments"] != 3 {
		t.Fatalf("comments = %d, want 3 (one review summary + two line comments)", result.Counts["comments"])
	}
	stored, _ := records.ListImport(context.Background(), "import-1")
	threads := stored[0].Threads
	// Nothing claims a diff position: resolving a declared position against the
	// imported refs is not something this import does yet, so every imported
	// anchor is approximate and says so.
	want := []struct {
		anchor      string
		path        string
		approximate bool
	}{
		{api.AnchorMerge, "", true},
		{api.AnchorFile, "widget.go", true},
		{api.AnchorFile, "widget.go", true},
	}
	if len(threads) != len(want) {
		t.Fatalf("threads = %d, want %d", len(threads), len(want))
	}
	for i, w := range want {
		if threads[i].Anchor != w.anchor || threads[i].Path != w.path || threads[i].Approximate() != w.approximate {
			t.Errorf("thread %d = anchor %q path %q approximate %v; want %q %q %v",
				i, threads[i].Anchor, threads[i].Path, threads[i].Approximate(), w.anchor, w.path, w.approximate)
		}
	}
}

// A rate-limited source (403/429) is a stall, not a failure (AC8).
func TestImportHistoryRateLimitStalls(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()
	client := New(newMemoryRecords(), server.Client())
	client.base = server.URL

	_, err := client.ImportHistory(context.Background(), app.ImportHistoryCommand{
		TenantID: "t", RepositoryID: "r", ImportID: "import-1",
		SourceURL: "https://github.com/acme/widgets.git", SourceSystem: "github", SourceInstance: "github.com",
	})
	if err != app.ErrImportStalled {
		t.Fatalf("err = %v, want ErrImportStalled", err)
	}
}

// Source URL parsing accepts https and scp-like forms and refuses garbage.
func TestParseSource(t *testing.T) {
	cases := []struct {
		raw   string
		ok    bool
		owner string
		repo  string
	}{
		{"https://github.com/acme/widgets.git", true, "acme", "widgets"},
		{"https://github.com/acme/widgets", true, "acme", "widgets"},
		{"https://gitlab.example.com/group/proj", true, "group", "proj"},
		{"git@github.com:acme/widgets.git", true, "acme", "widgets"},
		{"", false, "", ""},
		{"https://github.com/onlyowner", false, "", ""},
		{"not a url", false, "", ""},
	}
	for _, tc := range cases {
		got, ok := parseSource(tc.raw)
		if ok != tc.ok || got.owner != tc.owner || got.repo != tc.repo {
			t.Errorf("parseSource(%q) = %+v, %v; want %s/%s, %v", tc.raw, got, ok, tc.owner, tc.repo, tc.ok)
		}
	}
}

// A revoked import refuses further writes (AC17).
func TestRevokedImportRefusesWrites(t *testing.T) {
	records := newMemoryRecords()
	if err := records.Tombstone(context.Background(), "import-1"); err != nil {
		t.Fatal(err)
	}
	if err := records.PutImport(context.Background(), "import-1", nil); err == nil {
		t.Fatal("a revoked import accepted a write")
	}
}

// A repository with more pull requests than one page holds imports whole.
func TestImportHistoryFollowsPages(t *testing.T) {
	firstPage := make([]pullRequest, pageSize)
	for i := range firstPage {
		firstPage[i] = pullRequest{
			Number: int64(i + 1), Title: "PR", State: "open", User: ghUser{Login: "alice"},
			Head: ghRef{Ref: "feature"}, Base: ghRef{Ref: "main"},
		}
	}
	secondPage := []pullRequest{{
		Number: 101, Title: "Last", State: "open", User: ghUser{Login: "alice"},
		Head: ghRef{Ref: "feature"}, Base: ghRef{Ref: "main"},
	}}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/repos/acme/widgets/pulls" && r.URL.Query().Get("state") == "open":
			switch r.URL.Query().Get("page") {
			case "1":
				_ = json.NewEncoder(w).Encode(firstPage)
			default:
				_ = json.NewEncoder(w).Encode(secondPage)
			}
		default:
			_ = json.NewEncoder(w).Encode([]any{})
		}
	}))
	defer server.Close()

	records := newMemoryRecords()
	client := New(records, server.Client())
	client.base = server.URL

	result, err := client.ImportHistory(context.Background(), app.ImportHistoryCommand{
		TenantID: "t", RepositoryID: "r", ImportID: "import-1",
		SourceURL: "https://github.com/acme/widgets.git", SourceSystem: "github", SourceInstance: "github.com",
	})
	if err != nil {
		t.Fatalf("ImportHistory: %v", err)
	}
	if result.Counts["merge_requests"] != int64(pageSize+1) {
		t.Fatalf("merge_requests = %d, want %d", result.Counts["merge_requests"], pageSize+1)
	}
}

// countingPacer counts how many source fetches asked to proceed.
type countingPacer struct{ waits int }

func (p *countingPacer) Wait(context.Context) error {
	p.waits++
	return nil
}

// Every source fetch waits its turn, and the bytes read are reported so the
// caller can charge them to the tenant (SPEC-0011 AC21).
func TestImportHistoryPacesFetchesAndReportsBytes(t *testing.T) {
	server := newStubServer(t)
	defer server.Close()
	pacer := &countingPacer{}
	client := New(newMemoryRecords(), server.Client()).WithPacer(pacer)
	client.base = server.URL

	result, err := client.ImportHistory(context.Background(), app.ImportHistoryCommand{
		TenantID: "t", RepositoryID: "r", ImportID: "import-1",
		SourceURL: "https://github.com/acme/widgets.git", SourceSystem: "github", SourceInstance: "github.com",
	})
	if err != nil {
		t.Fatalf("ImportHistory: %v", err)
	}
	// open PRs, closed PRs, and the one PR's reviews and line comments.
	if pacer.waits != 4 {
		t.Fatalf("pacer waits = %d, want one per source fetch (4)", pacer.waits)
	}
	if result.SourceBytesRead <= 0 {
		t.Fatalf("source bytes read = %d, want the bytes actually read", result.SourceBytesRead)
	}
}

// The mapping half of the store is not what these adapter tests are about: an
// importer never asserts an identity (SPEC-0011 AC22 — mapping is an admin's act,
// never an importer's inference), so these refuse rather than pretend.
func (m *memoryRecords) PutMapping(context.Context, api.DeclaredActorMapping) (api.DeclaredActorMapping, error) {
	return api.DeclaredActorMapping{}, http.ErrBodyNotAllowed
}

func (m *memoryRecords) ListMappings(context.Context, string) ([]api.DeclaredActorMapping, error) {
	return nil, nil
}
