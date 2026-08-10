package grpc

import (
	"context"

	codereviewv1 "github.com/gitfrok/backend/gen/proto/codereview/v1"
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
