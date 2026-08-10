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
				Position:  position{NewPath: "widget.go"},
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

	counts, err := client.ImportHistory(context.Background(), app.ImportHistoryCommand{
		TenantID: "t", RepositoryID: "r", ImportID: "import-1",
		SourceURL: "https://gitlab.com/group/widgets.git", SourceSystem: "gitlab", SourceInstance: "gitlab.com",
	})
	if err != nil {
		t.Fatalf("ImportHistory: %v", err)
	}
	if counts["merge_requests"] != 1 || counts["approvals"] != 1 || counts["comments"] != 1 {
		t.Fatalf("counts = %v", counts)
	}

	stored, err := records.ListImport(context.Background(), "import-1")
	if err != nil || len(stored) != 1 {
		t.Fatalf("stored = %v err = %v", stored, err)
	}
	mr := stored[0]
	if mr.Title != "Add widget" || mr.CreatorID != "carol" || mr.SourceRef != "feature/widget" {
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
	if len(mr.Threads) != 1 || mr.Threads[0].Comments[0].DeclaredActor != "dave" {
		t.Fatalf("threads = %+v", mr.Threads)
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
