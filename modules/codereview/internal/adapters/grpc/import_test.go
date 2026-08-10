package grpc

import (
	"context"
	"errors"
	"testing"
	"time"

	codereviewv1 "github.com/gitfrok/backend/gen/proto/codereview/v1"
	contractsv1 "github.com/gitfrok/backend/gen/proto/contracts/v1"
	"github.com/gitfrok/backend/modules/codereview/api"
)

// stubImports records the request the adapter forwarded and returns a fixed page.
type stubImports struct {
	api.ImportService
	got  api.ListImportedHistoryRequest
	page api.ImportedHistoryPage
	err  error
}

func (s *stubImports) ListImportedHistory(_ context.Context, req api.ListImportedHistoryRequest) (api.ImportedHistoryPage, error) {
	s.got = req
	return s.page, s.err
}

func historyRequest() *codereviewv1.ListImportedHistoryRequest {
	return &codereviewv1.ListImportedHistoryRequest{
		Context: &codereviewv1.ReviewCommandContext{
			TenantId: "tenant-a", RepositoryId: "repo-a", ActorId: "actor-a", RequestId: "req-1",
		},
		ImportId: "import-1",
		PageSize: 25,
	}
}

// The adapter forwards only the verified context and the request's own fields,
// and returns every record with its provenance block — the thing a reader needs
// to tell imported history from first-party history (AC23 depends on AC20).
func TestListImportedHistoryCarriesProvenanceAndPaging(t *testing.T) {
	declared := time.Unix(1600000000, 0).UTC()
	imports := &stubImports{page: api.ImportedHistoryPage{
		NextPageToken: "mr-25",
		MergeRequests: []api.ImportedMergeRequest{{
			MergeRequestID:  "mr-01",
			Title:           "Add widget",
			State:           "merged",
			DeclaredCreator: "octocat",
			Provenance: api.Provenance{
				Class: api.AttestImported, ImportID: "import-1",
				SourceSystem: "github", SourceInstance: "github.com",
				DeclaredActor: "octocat", DeclaredAt: declared, PayloadDigest: "sha256:abc",
			},
			Threads: []api.ImportedThread{{
				ThreadID: "thread-1", MergeRequestID: "mr-01", Path: "widget.go",
				Anchor:     api.AnchorFile,
				Provenance: api.Provenance{Class: api.AttestImported, ImportID: "import-1"},
				Comments: []api.ImportedComment{{
					CommentID: "comment-1", DeclaredActor: "octocat", Body: "looks good",
					DeclaredAt: declared,
					Provenance: api.Provenance{Class: api.AttestImported, ImportID: "import-1"},
				}},
			}},
			Approvals: []api.ImportedApproval{{
				ApprovalID: "approval-1", MergeRequestID: "mr-01", DeclaredActor: "octocat",
				DeclaredAt: declared,
				Provenance: api.Provenance{Class: api.AttestImported, ImportID: "import-1"},
			}},
		}},
	}}
	server := NewImportServer(imports)

	response, err := server.ListImportedHistory(t.Context(), historyRequest())
	if err != nil {
		t.Fatalf("ListImportedHistory: %v", err)
	}
	if imports.got.TenantID != "tenant-a" || imports.got.ImportID != "import-1" || imports.got.PageSize != 25 {
		t.Fatalf("forwarded %+v", imports.got)
	}
	if response.GetNextPageToken() != "mr-25" {
		t.Fatalf("next page token = %q", response.GetNextPageToken())
	}
	if len(response.GetMergeRequests()) != 1 {
		t.Fatalf("records = %d, want 1", len(response.GetMergeRequests()))
	}

	record := response.GetMergeRequests()[0]
	if record.GetDeclaredCreator() != "octocat" {
		t.Fatalf("declared creator = %q", record.GetDeclaredCreator())
	}
	if record.GetState() != "merged" {
		t.Fatalf("state = %q, want the source's own string", record.GetState())
	}
	if record.GetProvenance().GetClass() != contractsv1.Provenance_CLASS_ATTESTED_IMPORT {
		t.Fatalf("class = %v", record.GetProvenance().GetClass())
	}
	if record.GetProvenance().GetPayloadDigest() != "sha256:abc" {
		t.Fatalf("payload digest = %q", record.GetProvenance().GetPayloadDigest())
	}
	if !record.GetProvenance().GetDeclaredAt().AsTime().Equal(declared) {
		t.Fatalf("declared at = %v", record.GetProvenance().GetDeclaredAt().AsTime())
	}
	if len(record.GetThreads()) != 1 || record.GetThreads()[0].GetAnchor() != codereviewv1.ImportedThread_ANCHOR_FILE {
		t.Fatalf("threads = %+v", record.GetThreads())
	}
	if len(record.GetThreads()[0].GetComments()) != 1 {
		t.Fatalf("comments = %+v", record.GetThreads()[0].GetComments())
	}
	if len(record.GetApprovals()) != 1 || record.GetApprovals()[0].GetDeclaredActor() != "octocat" {
		t.Fatalf("approvals = %+v", record.GetApprovals())
	}
	for _, provenance := range []*contractsv1.Provenance{
		record.GetThreads()[0].GetProvenance(),
		record.GetThreads()[0].GetComments()[0].GetProvenance(),
		record.GetApprovals()[0].GetProvenance(),
	} {
		if provenance.GetClass() != contractsv1.Provenance_CLASS_ATTESTED_IMPORT {
			t.Fatalf("a nested record travelled as %v", provenance.GetClass())
		}
	}
}

// An anchor precision this build cannot name travels as UNSPECIFIED. Mapping it
// to DIFF would turn an approximate anchor into a claim that the diff position
// still resolves (AC5).
func TestUnknownAnchorIsNotMappedToDiff(t *testing.T) {
	if got := anchorToProto("SOMETHING_NEW"); got != codereviewv1.ImportedThread_ANCHOR_UNSPECIFIED {
		t.Fatalf("anchor = %v, want UNSPECIFIED", got)
	}
	if got := anchorToProto(""); got != codereviewv1.ImportedThread_ANCHOR_UNSPECIFIED {
		t.Fatalf("empty anchor = %v, want UNSPECIFIED", got)
	}
}

// A provenance class this build cannot name never travels as FIRST_PARTY: a
// record whose class we cannot state must not be presentable as one this
// platform witnessed (ADR-0029 §1).
func TestUnknownProvenanceClassIsNotFirstParty(t *testing.T) {
	for _, class := range []string{"", "SOMETHING_NEW"} {
		got := provenanceToProto(api.Provenance{Class: class}).GetClass()
		if got != contractsv1.Provenance_CLASS_UNSPECIFIED {
			t.Fatalf("class %q travelled as %v", class, got)
		}
	}
}

// A source that declared no timestamp yields an absent one, not the Unix epoch:
// a reader must not render a date the source never declared.
func TestUndeclaredTimestampIsAbsent(t *testing.T) {
	if got := provenanceToProto(api.Provenance{Class: api.AttestImported}).GetDeclaredAt(); got != nil {
		t.Fatalf("declared at = %v, want absent", got)
	}
}

// The refusal is the one coarse denial this surface returns, and a malformed
// context never reaches the service.
func TestListImportedHistoryDenialIsCoarse(t *testing.T) {
	imports := &stubImports{err: errors.New("import unavailable")}
	server := NewImportServer(imports)

	withService, err := server.ListImportedHistory(t.Context(), historyRequest())
	if err == nil {
		t.Fatal("a failing read returned a response")
	}
	if withService != nil {
		t.Fatalf("response = %+v, want none", withService)
	}

	malformed := historyRequest()
	malformed.Context = nil
	unauthenticated := &stubImports{}
	if _, err := NewImportServer(unauthenticated).ListImportedHistory(t.Context(), malformed); err == nil {
		t.Fatal("a request with no verified context was served")
	}
	if unauthenticated.got.ImportID != "" {
		t.Fatalf("a malformed request reached the service as %+v", unauthenticated.got)
	}
	if err.Error() != denialImport().Error() {
		t.Fatalf("denials differ: %v vs %v", err, denialImport())
	}
}
