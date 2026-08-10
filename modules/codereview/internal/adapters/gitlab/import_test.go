package gitlab

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gitfrok/backend/modules/codereview/api"
	"github.com/gitfrok/backend/modules/codereview/internal/app"
)

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

func newStubServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// url.PathEscape encodes the slash; net/http decodes it back on r.URL.Path.
		switch {
		case r.URL.Path == "/projects/group/widgets/merge_requests":
			_ = json.NewEncoder(w).Encode([]mergeRequest{{
				IID: 7, Title: "Add widget", Description: "Closes #3", State: "opened",
				Author: glUser{Username: "carol"}, CreatedAt: time.Date(2024, 2, 1, 0, 0, 0, 0, time.UTC),
				UpdatedAt:    time.Date(2024, 2, 2, 0, 0, 0, 0, time.UTC),
				SourceBranch: "feature/widget", TargetBranch: "main",
			}})
		case strings.Contains(r.URL.Path, "/merge_requests/7/approvals"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"approved_by": []map[string]any{{"user_id": 9, "user": map[string]any{"username": "dave"}}},
			})
		case strings.Contains(r.URL.Path, "/merge_requests/7/notes"):
			_ = json.NewEncoder(w).Encode([]note{{
				ID: 21, Body: "Looks good", Author: glUser{Username: "dave"},
				CreatedAt: time.Date(2024, 2, 2, 0, 0, 0, 0, time.UTC),
				Position:  position{NewPath: "widget.go", NewLine: 12},
			}, {
				ID: 22, Body: "File-level remark", Author: glUser{Username: "dave"},
				CreatedAt: time.Date(2024, 2, 2, 1, 0, 0, 0, time.UTC),
				Position:  position{NewPath: "widget.go"},
			}, {
				ID: 23, Body: "General remark", Author: glUser{Username: "erin"},
				CreatedAt: time.Date(2024, 2, 2, 2, 0, 0, 0, time.UTC),
			}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

// An import stores MR history with ATTESTED_IMPORT provenance (AC4/AC16).
func TestImportHistoryStoresAttestedRecords(t *testing.T) {
	server := newStubServer(t)
	defer server.Close()
	records := newMemoryRecords()
	client := New(records, server.Client())
	client.base = server.URL

	result, err := client.ImportHistory(context.Background(), app.ImportHistoryCommand{
		TenantID: "t", RepositoryID: "r", ImportID: "import-1",
		SourceURL: "https://gitlab.com/group/widgets.git", SourceSystem: "gitlab", SourceInstance: "gitlab.com",
	})
	if err != nil {
		t.Fatalf("ImportHistory: %v", err)
	}
	if result.Counts["merge_requests"] != 1 || result.Counts["approvals"] != 1 || result.Counts["comments"] != 3 {
		t.Fatalf("counts = %v", result.Counts)
	}

	stored, err := records.ListImport(context.Background(), "import-1")
	if err != nil || len(stored) != 1 {
		t.Fatalf("stored = %v err = %v", stored, err)
	}
	mr := stored[0]
	if mr.Title != "Add widget" || mr.DeclaredCreator != "carol" || mr.SourceRef != "feature/widget" {
		t.Fatalf("mr = %+v", mr)
	}
	if mr.Provenance.Class != api.AttestImported || mr.Provenance.SourceSystem != "gitlab" {
		t.Fatalf("provenance = %+v", mr.Provenance)
	}
	if mr.Provenance.DeclaredActor != "carol" || mr.Provenance.PayloadDigest == "" {
		t.Fatalf("provenance = %+v", mr.Provenance)
	}
	if len(mr.Approvals) != 1 || mr.Approvals[0].Provenance.Class != api.AttestImported {
		t.Fatalf("approvals = %+v", mr.Approvals)
	}
	// GitLab declares no per-approval timestamp, so none is recorded rather than
	// the merge request's own being passed off as one (ADR-0029).
	if !mr.Approvals[0].DeclaredAt.IsZero() || !mr.Approvals[0].Provenance.DeclaredAt.IsZero() {
		t.Fatalf("approval carries an undeclared timestamp: %+v", mr.Approvals[0])
	}
	// Each record's digest covers its own payload, not its parent's.
	if mr.Approvals[0].Provenance.PayloadDigest == mr.Provenance.PayloadDigest {
		t.Fatal("approval digest is the merge request's digest")
	}
	if mr.Threads[0].Provenance.PayloadDigest == mr.Provenance.PayloadDigest {
		t.Fatal("thread digest is the merge request's digest")
	}
	if len(mr.Threads) != 3 || mr.Threads[0].Comments[0].DeclaredActor != "dave" {
		t.Fatalf("threads = %+v", mr.Threads)
	}
}

// A note's anchor degrades with the position the source declared, and no note
// is dropped for want of one (AC5).
func TestImportHistoryDegradesAnchors(t *testing.T) {
	server := newStubServer(t)
	defer server.Close()
	records := newMemoryRecords()
	client := New(records, server.Client())
	client.base = server.URL

	if _, err := client.ImportHistory(context.Background(), app.ImportHistoryCommand{
		TenantID: "t", RepositoryID: "r", ImportID: "import-1",
		SourceURL: "https://gitlab.com/group/widgets.git", SourceSystem: "gitlab", SourceInstance: "gitlab.com",
	}); err != nil {
		t.Fatalf("ImportHistory: %v", err)
	}
	stored, _ := records.ListImport(context.Background(), "import-1")
	threads := stored[0].Threads
	// No imported anchor claims a diff position: this import never resolved the
	// declared positions against the refs it imported, and GitLab echoes a note's
	// original path even after the file is gone.
	want := []struct {
		anchor      string
		path        string
		approximate bool
	}{
		{api.AnchorFile, "widget.go", true},
		{api.AnchorFile, "widget.go", true},
		{api.AnchorMerge, "", true},
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

// A rate-limited source is a stall, not a failure (AC8).
func TestImportHistoryRateLimitStalls(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()
	client := New(newMemoryRecords(), server.Client())
	client.base = server.URL

	_, err := client.ImportHistory(context.Background(), app.ImportHistoryCommand{
		TenantID: "t", RepositoryID: "r", ImportID: "import-1",
		SourceURL: "https://gitlab.com/group/widgets.git", SourceSystem: "gitlab", SourceInstance: "gitlab.com",
	})
	if err != app.ErrImportStalled {
		t.Fatalf("err = %v, want ErrImportStalled", err)
	}
}

// Source URL parsing handles nested groups, https, and scp-like forms.
func TestParseSource(t *testing.T) {
	cases := []struct {
		raw       string
		ok        bool
		namespace string
		project   string
	}{
		{"https://gitlab.com/acme/widgets.git", true, "acme", "widgets"},
		{"https://gitlab.com/group/sub/proj", true, "group/sub", "proj"},
		{"git@gitlab.com:acme/widgets.git", true, "acme", "widgets"},
		{"", false, "", ""},
		{"https://gitlab.com/onlyone", false, "", ""},
	}
	for _, tc := range cases {
		got, ok := parseSource(tc.raw)
		if ok != tc.ok || got.namespace != tc.namespace || got.project != tc.project {
			t.Errorf("parseSource(%q) = %+v, %v; want %s/%s, %v", tc.raw, got, ok, tc.namespace, tc.project, tc.ok)
		}
	}
}

// A source with more history than one page holds imports whole: an import that
// stopped at the first page would report partial counts as the full backlog.
func TestImportHistoryFollowsPages(t *testing.T) {
	firstPage := make([]mergeRequest, pageSize)
	for i := range firstPage {
		firstPage[i] = mergeRequest{
			IID: int64(i + 1), Title: "MR", State: "opened", Author: glUser{Username: "carol"},
			SourceBranch: "feature", TargetBranch: "main",
		}
	}
	secondPage := []mergeRequest{{
		IID: 101, Title: "Last", State: "merged", Author: glUser{Username: "carol"},
		SourceBranch: "feature", TargetBranch: "main",
	}}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/merge_requests"):
			switch r.URL.Query().Get("page") {
			case "1":
				_ = json.NewEncoder(w).Encode(firstPage)
			default:
				_ = json.NewEncoder(w).Encode(secondPage)
			}
		case strings.Contains(r.URL.Path, "/approvals"):
			_ = json.NewEncoder(w).Encode(map[string]any{"approved_by": []any{}})
		default:
			_ = json.NewEncoder(w).Encode([]note{})
		}
	}))
	defer server.Close()

	records := newMemoryRecords()
	client := New(records, server.Client())
	client.base = server.URL

	result, err := client.ImportHistory(context.Background(), app.ImportHistoryCommand{
		TenantID: "t", RepositoryID: "r", ImportID: "import-1",
		SourceURL: "https://gitlab.com/group/widgets.git", SourceSystem: "gitlab", SourceInstance: "gitlab.com",
	})
	if err != nil {
		t.Fatalf("ImportHistory: %v", err)
	}
	if result.Counts["merge_requests"] != int64(pageSize+1) {
		t.Fatalf("merge_requests = %d, want %d", result.Counts["merge_requests"], pageSize+1)
	}
	stored, _ := records.ListImport(context.Background(), "import-1")
	if len(stored) != pageSize+1 {
		t.Fatalf("stored = %d records, want %d", len(stored), pageSize+1)
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
