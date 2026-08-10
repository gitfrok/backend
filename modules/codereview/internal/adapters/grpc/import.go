package grpc

import (
	"context"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	codereviewv1 "github.com/gitfrok/backend/gen/proto/codereview/v1"
	contractsv1 "github.com/gitfrok/backend/gen/proto/contracts/v1"
	"github.com/gitfrok/backend/modules/codereview/api"
)

// ImportServer is the gRPC adapter for the import port (SPEC-0011). It carries
// only verified identity context and the source identity; no caller can assert a
// tenant, an actor, its roles, a state, a digest, or an authorization outcome.
type ImportServer struct {
	codereviewv1.UnimplementedImportServiceServer
	imports api.ImportService
}

// NewImportServer wires the import surface.
func NewImportServer(imports api.ImportService) *ImportServer {
	return &ImportServer{imports: imports}
}

// denialImport is the one refusal this surface returns. It does not distinguish
// a missing import from one in another tenant.
func denialImport() error {
	return denial()
}

func (s *ImportServer) CreateImport(ctx context.Context, req *codereviewv1.CreateImportRequest) (*codereviewv1.CreateImportResponse, error) {
	ctx, principal, err := intoContext(ctx, req.GetContext())
	if err != nil {
		return nil, denialImport()
	}
	imp, err := s.imports.Create(ctx, api.CreateImportRequest{
		Context:        principal,
		SourceURL:      req.GetSourceUrl(),
		SourceSystem:   req.GetSourceSystem(),
		SourceInstance: req.GetSourceInstance(),
		SourceToken:    req.GetSourceToken(),
	})
	if err != nil {
		return nil, denialImport()
	}
	return &codereviewv1.CreateImportResponse{Import: importToProto(imp)}, nil
}

func (s *ImportServer) GetImport(ctx context.Context, req *codereviewv1.GetImportRequest) (*codereviewv1.GetImportResponse, error) {
	ctx, principal, err := intoContext(ctx, req.GetContext())
	if err != nil {
		return nil, denialImport()
	}
	imp, err := s.imports.Get(ctx, principal, req.GetImportId())
	if err != nil {
		return nil, denialImport()
	}
	return &codereviewv1.GetImportResponse{Import: importToProto(imp)}, nil
}

func (s *ImportServer) ListImports(ctx context.Context, req *codereviewv1.ListImportsRequest) (*codereviewv1.ListImportsResponse, error) {
	ctx, principal, err := intoContext(ctx, req.GetContext())
	if err != nil {
		return nil, denialImport()
	}
	imports, err := s.imports.List(ctx, principal, req.GetRepositoryId())
	if err != nil {
		return nil, denialImport()
	}
	response := &codereviewv1.ListImportsResponse{}
	for _, imp := range imports {
		response.Imports = append(response.Imports, importToProto(imp))
	}
	return response, nil
}

func (s *ImportServer) RevokeImport(ctx context.Context, req *codereviewv1.RevokeImportRequest) (*codereviewv1.RevokeImportResponse, error) {
	ctx, principal, err := intoContext(ctx, req.GetContext())
	if err != nil {
		return nil, denialImport()
	}
	imp, err := s.imports.Revoke(ctx, api.RevokeImportRequest{
		Context:  principal,
		ImportID: req.GetImportId(),
	})
	if err != nil {
		return nil, denialImport()
	}
	return &codereviewv1.RevokeImportResponse{Import: importToProto(imp)}, nil
}

// ListImportedHistory returns one page of an import's imported merge requests.
// Every record carries its provenance block: without it a reader has no way to
// tell imported history from first-party history, which is what AC23's rendering
// depends on (ADR-0029 §4).
func (s *ImportServer) ListImportedHistory(ctx context.Context, req *codereviewv1.ListImportedHistoryRequest) (*codereviewv1.ListImportedHistoryResponse, error) {
	ctx, principal, err := intoContext(ctx, req.GetContext())
	if err != nil {
		return nil, denialImport()
	}
	page, err := s.imports.ListImportedHistory(ctx, api.ListImportedHistoryRequest{
		Context:   principal,
		ImportID:  req.GetImportId(),
		PageSize:  int(req.GetPageSize()),
		PageToken: req.GetPageToken(),
	})
	if err != nil {
		return nil, denialImport()
	}
	response := &codereviewv1.ListImportedHistoryResponse{NextPageToken: page.NextPageToken}
	for _, record := range page.MergeRequests {
		response.MergeRequests = append(response.MergeRequests, importedMergeRequestToProto(record))
	}
	return response, nil
}

func importedMergeRequestToProto(record api.ImportedMergeRequest) *codereviewv1.ImportedMergeRequest {
	out := &codereviewv1.ImportedMergeRequest{
		MergeRequestId: record.MergeRequestID,
		SourceRef:      record.SourceRef,
		TargetRef:      record.TargetRef,
		Title:          record.Title,
		Description:    record.Description,
		State:          record.State,
		// The source's declared author travels as an opaque handle. It is never
		// mapped onto creator_id, which names a resolvable platform actor
		// (ADR-0029 §4, SPEC-0011 AC14).
		DeclaredCreator: record.DeclaredCreator,
		Provenance:      provenanceToProto(record.Provenance),
	}
	for _, thread := range record.Threads {
		out.Threads = append(out.Threads, importedThreadToProto(thread))
	}
	for _, approval := range record.Approvals {
		out.Approvals = append(out.Approvals, &codereviewv1.ImportedApproval{
			ApprovalId:     approval.ApprovalID,
			MergeRequestId: approval.MergeRequestID,
			DeclaredActor:  approval.DeclaredActor,
			DeclaredAt:     declaredTimestamp(approval.DeclaredAt),
			Provenance:     provenanceToProto(approval.Provenance),
		})
	}
	return out
}

func importedThreadToProto(thread api.ImportedThread) *codereviewv1.ImportedThread {
	out := &codereviewv1.ImportedThread{
		ThreadId:       thread.ThreadID,
		MergeRequestId: thread.MergeRequestID,
		Path:           thread.Path,
		Anchor:         anchorToProto(thread.Anchor),
		Provenance:     provenanceToProto(thread.Provenance),
	}
	for _, comment := range thread.Comments {
		out.Comments = append(out.Comments, &codereviewv1.ImportedComment{
			CommentId:     comment.CommentID,
			DeclaredActor: comment.DeclaredActor,
			Body:          comment.Body,
			DeclaredAt:    declaredTimestamp(comment.DeclaredAt),
			Provenance:    provenanceToProto(comment.Provenance),
		})
	}
	return out
}

// anchorToProto maps the anchor precision. An unrecognized precision travels as
// UNSPECIFIED rather than as DIFF: DIFF asserts the diff position still
// resolves, and a mapping that guesses it would turn an approximate anchor into
// an exact claim (SPEC-0011 AC5).
func anchorToProto(anchor string) codereviewv1.ImportedThread_Anchor {
	switch anchor {
	case api.AnchorDiff:
		return codereviewv1.ImportedThread_ANCHOR_DIFF
	case api.AnchorFile:
		return codereviewv1.ImportedThread_ANCHOR_FILE
	case api.AnchorMerge:
		return codereviewv1.ImportedThread_ANCHOR_MERGE
	default:
		return codereviewv1.ImportedThread_ANCHOR_UNSPECIFIED
	}
}

// provenanceToProto maps the immutable provenance block. An unrecognized class
// travels as UNSPECIFIED, never as FIRST_PARTY: a record whose class this build
// cannot name must not be presentable as one this platform witnessed
// (ADR-0029 §1).
func provenanceToProto(provenance api.Provenance) *contractsv1.Provenance {
	class := contractsv1.Provenance_CLASS_UNSPECIFIED
	switch provenance.Class {
	case api.AttestFirstParty:
		class = contractsv1.Provenance_CLASS_FIRST_PARTY
	case api.AttestImported:
		class = contractsv1.Provenance_CLASS_ATTESTED_IMPORT
	}
	return &contractsv1.Provenance{
		Class:          class,
		ImportId:       provenance.ImportID,
		SourceSystem:   provenance.SourceSystem,
		SourceInstance: provenance.SourceInstance,
		SourceRef:      provenance.SourceRef,
		DeclaredActor:  provenance.DeclaredActor,
		DeclaredAt:     declaredTimestamp(provenance.DeclaredAt),
		PayloadDigest:  provenance.PayloadDigest,
	}
}

// declaredTimestamp carries a source-declared time. A zero time travels as an
// absent timestamp rather than as the Unix epoch, so a reader never renders a
// date the source never declared.
func declaredTimestamp(at time.Time) *timestamppb.Timestamp {
	if at.IsZero() {
		return nil
	}
	return timestamppb.New(at)
}

func importStateProto(state api.ImportState) codereviewv1.ImportState {
	switch state {
	case api.ImportPending:
		return codereviewv1.ImportState_IMPORT_STATE_PENDING
	case api.ImportRunning:
		return codereviewv1.ImportState_IMPORT_STATE_RUNNING
	case api.ImportComplete:
		return codereviewv1.ImportState_IMPORT_STATE_COMPLETE
	case api.ImportFailed:
		return codereviewv1.ImportState_IMPORT_STATE_FAILED
	case api.ImportStalled:
		return codereviewv1.ImportState_IMPORT_STATE_STALLED
	case api.ImportRevoked:
		return codereviewv1.ImportState_IMPORT_STATE_REVOKED
	default:
		return codereviewv1.ImportState_IMPORT_STATE_UNSPECIFIED
	}
}

func importToProto(imp api.Import) *codereviewv1.Import {
	return &codereviewv1.Import{
		ImportId:             imp.ID,
		TenantId:             imp.TenantID,
		RepositoryId:         imp.RepositoryID,
		SourceUrl:            imp.SourceURL,
		SourceSystem:         imp.SourceSystem,
		SourceInstance:       imp.SourceInstance,
		State:                importStateProto(imp.State),
		ManifestDigest:       imp.ManifestDigest,
		GitPhaseComplete:     imp.GitPhaseComplete,
		HistoryPhaseComplete: imp.HistoryPhaseComplete,
		RecordCounts:         imp.RecordCounts,
		FailureReason:        imp.FailureReason,
	}
}

// MapDeclaredActor records a tenant admin's assertion that a foreign handle is a
// platform identity (SPEC-0011 AC10/AC22).
//
// The asserting admin comes from the verified context, never from the request
// body: a caller able to name its own asserter could attribute its claim to
// somebody else. The request contributes only the handle, its source instance,
// and the identity being asserted.
func (s *ImportServer) MapDeclaredActor(ctx context.Context, req *codereviewv1.MapDeclaredActorRequest) (*codereviewv1.MapDeclaredActorResponse, error) {
	ctx, principal, err := intoContext(ctx, req.GetContext())
	if err != nil {
		return nil, denialImport()
	}
	mapping, err := s.imports.MapDeclaredActor(ctx, api.MapDeclaredActorRequest{
		Context:        principal,
		ImportID:       req.GetImportId(),
		DeclaredActor:  req.GetDeclaredActor(),
		SourceInstance: req.GetSourceInstance(),
		MappedActorID:  req.GetActorId(),
	})
	if err != nil {
		return nil, denialImport()
	}
	return &codereviewv1.MapDeclaredActorResponse{Mapping: mappingToProto(mapping)}, nil
}

// ListDeclaredActorMappings returns the mappings asserted for one import.
func (s *ImportServer) ListDeclaredActorMappings(ctx context.Context, req *codereviewv1.ListDeclaredActorMappingsRequest) (*codereviewv1.ListDeclaredActorMappingsResponse, error) {
	ctx, principal, err := intoContext(ctx, req.GetContext())
	if err != nil {
		return nil, denialImport()
	}
	mappings, err := s.imports.ListDeclaredActorMappings(ctx, principal, req.GetImportId())
	if err != nil {
		return nil, denialImport()
	}
	response := &codereviewv1.ListDeclaredActorMappingsResponse{}
	for _, mapping := range mappings {
		response.Mappings = append(response.Mappings, mappingToProto(mapping))
	}
	return response, nil
}

func mappingToProto(mapping api.DeclaredActorMapping) *codereviewv1.DeclaredActorMapping {
	return &codereviewv1.DeclaredActorMapping{
		MappingId:      mapping.MappingID,
		TenantId:       mapping.TenantID,
		ImportId:       mapping.ImportID,
		DeclaredActor:  mapping.DeclaredActor,
		SourceInstance: mapping.SourceInstance,
		ActorId:        mapping.ActorID,
		AssertedBy:     mapping.AssertedBy,
		AssertedAt:     declaredTimestamp(mapping.AssertedAt),
	}
}
