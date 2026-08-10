package codereview_test

import (
	"context"
	"testing"

	"github.com/gitfrok/backend/modules/codereview"
	"github.com/gitfrok/backend/modules/codereview/api"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
	"github.com/gitfrok/backend/platform/bus"
)

// stubGitImporter stands in for Repository/Git's import boundary: the git phase
// is not what this test is about.
type stubGitImporter struct{}

func (stubGitImporter) ImportRefs(context.Context, codereview.ImportRefsCommand) (codereview.GitResult, error) {
	return codereview.GitResult{Refs: []codereview.RefUpdate{{Ref: "refs/heads/main", Revision: "a1"}}}, nil
}

// stubHistoryImporter writes one imported record into the store it is given,
// which is the store the composition root is supposed to share.
type stubHistoryImporter struct{ records api.ImportedRecordStore }

func (s stubHistoryImporter) ImportHistory(ctx context.Context, command codereview.ImportHistoryCommand) (codereview.HistoryResult, error) {
	err := s.records.PutImport(ctx, command.ImportID, []api.ImportedMergeRequest{{
		MergeRequestID: "1",
		Provenance:     api.Provenance{Class: api.AttestImported, ImportID: command.ImportID},
	}})
	return codereview.HistoryResult{Counts: map[string]int64{"merge_requests": 1}}, err
}

type allowAllPDP struct{}

func (allowAllPDP) Decide(context.Context, policyapi.Request) (policyapi.Decision, error) {
	return policyapi.Decision{Allowed: true, DecisionID: "d-1", PolicyRevision: "rev-1"}, nil
}

// Revoking an import must drop the records the history phase actually wrote.
// That only holds if the composition root hands one record store to both the
// history importer and the import service (SPEC-0011 AC17).
func TestImportRevokeTombstonesTheRecordsTheImporterWrote(t *testing.T) {
	ctx := t.Context()
	records := codereview.NewImportRecordStore()
	// Pacing is off in this test: it is about what a revoke leaves readable, and a
	// throttle would only make it slower.
	service := codereview.NewImportService(
		records, stubGitImporter{}, stubHistoryImporter{records: records}, allowAllPDP{}, bus.NewInProcess(),
		codereview.NewImportPacer(0),
	)

	principal := api.Context{TenantID: "tenant-a", RepositoryID: "repo-a", ActorID: "actor-a", RequestID: "req-1"}
	imp, err := service.Create(ctx, api.CreateImportRequest{
		Context: principal, SourceURL: "https://github.com/acme/widgets.git",
		SourceSystem: "github", SourceInstance: "github.com",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	stored, err := records.ListImport(ctx, imp.ID)
	if err != nil || len(stored) != 1 {
		t.Fatalf("stored = %v err = %v; want one imported record", stored, err)
	}

	if _, err := service.Revoke(ctx, api.RevokeImportRequest{Context: principal, ImportID: imp.ID}); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	remaining, err := records.ListImport(ctx, imp.ID)
	if err != nil {
		t.Fatalf("ListImport after revoke: %v", err)
	}
	if len(remaining) != 0 {
		t.Fatalf("revoked import still reads %d records", len(remaining))
	}
}

// The source selector refuses a system no adapter serves rather than handing
// the import to the wrong API client.
func TestSourceHistoryImporterRefusesUnknownSystem(t *testing.T) {
	importer := codereview.NewSourceHistoryImporter(codereview.NewImportRecordStore(), nil, codereview.NewImportPacer(0))
	if _, err := importer.ImportHistory(t.Context(), codereview.ImportHistoryCommand{
		TenantID: "tenant-a", RepositoryID: "repo-a", ImportID: "import-1",
		SourceURL: "https://example.com/acme/widgets.git", SourceSystem: "bitbucket",
	}); err == nil {
		t.Fatal("an unknown source system was accepted")
	}
}
