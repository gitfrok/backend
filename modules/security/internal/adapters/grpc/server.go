// Package grpc adapts the Security/Findings in-process surface to its gRPC
// contract (SPEC-0025). It carries only verified identity context; no caller
// can assert a finding identity, a lifecycle state, or an authorization
// result — those are server state and PDP answers, respectively.
package grpc

import (
	"context"
	"errors"

	securityv1 "github.com/gitfrok/backend/gen/proto/security/v1"
	"github.com/gitfrok/backend/modules/security/api"
	"github.com/gitfrok/backend/platform/tenancy"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Server is the gRPC adapter for the Findings port.
type Server struct {
	securityv1.UnimplementedFindingsServiceServer
	findings api.Findings
}

// NewServer builds the adapter over the module's port.
func NewServer(findings api.Findings) *Server { return &Server{findings: findings} }

// denial is the coarse refusal (SPEC-0025 AC2): not-found, cross-tenant, and
// unauthorized are indistinguishable.
func denial() error {
	return status.Error(codes.PermissionDenied, "security: finding unavailable")
}

var errMalformed = status.Error(codes.InvalidArgument, "malformed request")

// IngestScanResults ingests one chunk of a completed scan's batch.
func (s *Server) IngestScanResults(ctx context.Context, req *securityv1.IngestScanResultsRequest) (*securityv1.IngestScanResultsResponse, error) {
	chunk, err := intoIngestChunk(req)
	if err != nil {
		return nil, errMalformed
	}
	ctx = tenancy.WithTenant(ctx, tenancy.ID(chunk.TenantID))
	res, err := s.findings.IngestScanResults(ctx, chunk)
	if err != nil {
		if errors.Is(err, api.ErrMalformed) {
			return nil, errMalformed
		}
		return nil, denial()
	}
	return &securityv1.IngestScanResultsResponse{
		ScanId:           res.ScanID,
		FindingsRecorded: res.FindingsRecorded,
	}, nil
}

// GetFinding returns one finding.
func (s *Server) GetFinding(ctx context.Context, req *securityv1.GetFindingRequest) (*securityv1.GetFindingResponse, error) {
	ctx, c, err := intoContext(ctx, req.GetContext())
	if err != nil {
		return nil, err
	}
	f, err := s.findings.GetFinding(ctx, c, req.GetFindingId())
	if err != nil {
		return nil, denial()
	}
	return &securityv1.GetFindingResponse{Finding: toFindingProto(f)}, nil
}

// ListFindings pages a tenant-scoped, filtered listing.
func (s *Server) ListFindings(ctx context.Context, req *securityv1.ListFindingsRequest) (*securityv1.ListFindingsResponse, error) {
	ctx, c, err := intoContext(ctx, req.GetContext())
	if err != nil {
		return nil, err
	}
	page, err := s.findings.ListFindings(ctx, api.ListRequest{
		Context:            c,
		RepositoryFilter:   req.GetRepositoryFilter(),
		ScannerClassFilter: fromScannerClassProto(req.GetScannerClassFilter()),
		SeverityFilter:     fromSeverityProto(req.GetSeverityFilter()),
		LifecycleFilter:    fromLifecycleProto(req.GetLifecycleFilter()),
		PageSize:           int(req.GetPageSize()),
		PageToken:          req.GetPageToken(),
	})
	if err != nil {
		return nil, denial()
	}
	out := &securityv1.ListFindingsResponse{NextPageToken: page.NextPageToken}
	for _, f := range page.Findings {
		out.Findings = append(out.Findings, toFindingProto(f))
	}
	return out, nil
}

func intoContext(ctx context.Context, c *securityv1.FindingsContext) (context.Context, api.Context, error) {
	if c == nil || c.GetTenantId() == "" || c.GetRepositoryId() == "" ||
		c.GetActorId() == "" || c.GetRequestId() == "" {
		return ctx, api.Context{}, errMalformed
	}
	in := api.Context{
		TenantID: c.GetTenantId(), RepositoryID: c.GetRepositoryId(),
		ActorID: c.GetActorId(), ActorRoles: append([]string(nil), c.GetActorRoles()...),
		RequestID: c.GetRequestId(),
	}
	return tenancy.WithTenant(ctx, tenancy.ID(in.TenantID)), in, nil
}

// intoIngestChunk maps the request. It refuses anything that asserts what
// only the server may assert: the request type carries no identity,
// lifecycle, or first-seen field to even attempt it with (SPEC-0025 AC3).
func intoIngestChunk(req *securityv1.IngestScanResultsRequest) (api.IngestChunk, error) {
	if req == nil || req.GetContext() == nil || req.GetScan() == nil {
		return api.IngestChunk{}, errMalformed
	}
	c := req.GetContext()
	if c.GetTenantId() == "" || c.GetRepositoryId() == "" || c.GetActorId() == "" || c.GetRequestId() == "" {
		return api.IngestChunk{}, errMalformed
	}
	sd := req.GetScan()
	if sd.GetScanStartedAt() == nil || sd.GetScanEndedAt() == nil {
		return api.IngestChunk{}, errMalformed
	}
	chunk := api.IngestChunk{
		Context: api.Context{
			TenantID: c.GetTenantId(), RepositoryID: c.GetRepositoryId(),
			ActorID: c.GetActorId(), ActorRoles: append([]string(nil), c.GetActorRoles()...),
			RequestID: c.GetRequestId(),
		},
		Revision: req.GetRevision(),
		Scan: api.Scan{
			ScannerClass: fromScannerClassProto(sd.GetScannerClass()),
			ToolName:     sd.GetToolName(),
			ToolVersion:  sd.GetToolVersion(),
			StartedAt:    sd.GetScanStartedAt().AsTime(),
			EndedAt:      sd.GetScanEndedAt().AsTime(),
		},
		ChunkIndex: int(req.GetChunkIndex()),
		FinalChunk: req.GetFinalChunk(),
	}
	for _, rf := range req.GetFindings() {
		raw := api.RawFinding{
			RuleID:   rf.GetRuleId(),
			Severity: fromSeverityProto(rf.GetSeverity()),
			Location: api.Location{
				ArtifactPath:     rf.GetLocation().GetArtifactPath(),
				EnclosingContent: rf.GetLocation().GetEnclosingContent(),
				Component:        rf.GetLocation().GetComponent(),
				ComponentVersion: rf.GetLocation().GetComponentVersion(),
			},
			Provenance:          rf.GetProvenance(),
			ProvenanceMediaType: rf.GetProvenanceMediaType(),
		}
		chunk.Findings = append(chunk.Findings, raw)
	}
	return chunk, nil
}

func fromScannerClassProto(c securityv1.ScannerClass) api.ScannerClass {
	switch c {
	case securityv1.ScannerClass_SCANNER_CLASS_SAST:
		return api.ScannerClassSAST
	case securityv1.ScannerClass_SCANNER_CLASS_DEPENDENCY:
		return api.ScannerClassDependency
	case securityv1.ScannerClass_SCANNER_CLASS_SECRETS:
		return api.ScannerClassSecrets
	case securityv1.ScannerClass_SCANNER_CLASS_CONTAINER:
		return api.ScannerClassContainer
	case securityv1.ScannerClass_SCANNER_CLASS_DAST:
		return api.ScannerClassDAST
	default:
		return "" // unspecified is invalid; the service refuses it whole
	}
}

func toScannerClassProto(c api.ScannerClass) securityv1.ScannerClass {
	switch c {
	case api.ScannerClassSAST:
		return securityv1.ScannerClass_SCANNER_CLASS_SAST
	case api.ScannerClassDependency:
		return securityv1.ScannerClass_SCANNER_CLASS_DEPENDENCY
	case api.ScannerClassSecrets:
		return securityv1.ScannerClass_SCANNER_CLASS_SECRETS
	case api.ScannerClassContainer:
		return securityv1.ScannerClass_SCANNER_CLASS_CONTAINER
	case api.ScannerClassDAST:
		return securityv1.ScannerClass_SCANNER_CLASS_DAST
	default:
		return securityv1.ScannerClass_SCANNER_CLASS_UNSPECIFIED
	}
}

func fromSeverityProto(s securityv1.FindingSeverity) api.Severity {
	switch s {
	case securityv1.FindingSeverity_FINDING_SEVERITY_LOW:
		return api.SeverityLow
	case securityv1.FindingSeverity_FINDING_SEVERITY_MEDIUM:
		return api.SeverityMedium
	case securityv1.FindingSeverity_FINDING_SEVERITY_HIGH:
		return api.SeverityHigh
	case securityv1.FindingSeverity_FINDING_SEVERITY_CRITICAL:
		return api.SeverityCritical
	default:
		return "" // unspecified is invalid; the service refuses it whole
	}
}

func toSeverityProto(s api.Severity) securityv1.FindingSeverity {
	switch s {
	case api.SeverityLow:
		return securityv1.FindingSeverity_FINDING_SEVERITY_LOW
	case api.SeverityMedium:
		return securityv1.FindingSeverity_FINDING_SEVERITY_MEDIUM
	case api.SeverityHigh:
		return securityv1.FindingSeverity_FINDING_SEVERITY_HIGH
	case api.SeverityCritical:
		return securityv1.FindingSeverity_FINDING_SEVERITY_CRITICAL
	default:
		return securityv1.FindingSeverity_FINDING_SEVERITY_UNSPECIFIED
	}
}

func fromLifecycleProto(l securityv1.FindingLifecycle) api.Lifecycle {
	switch l {
	case securityv1.FindingLifecycle_FINDING_LIFECYCLE_OPEN:
		return api.LifecycleOpen
	case securityv1.FindingLifecycle_FINDING_LIFECYCLE_RESOLVED:
		return api.LifecycleResolved
	default:
		return "" // unspecified means "no filter"
	}
}

func toLifecycleProto(l api.Lifecycle) securityv1.FindingLifecycle {
	switch l {
	case api.LifecycleOpen:
		return securityv1.FindingLifecycle_FINDING_LIFECYCLE_OPEN
	case api.LifecycleResolved:
		return securityv1.FindingLifecycle_FINDING_LIFECYCLE_RESOLVED
	default:
		return securityv1.FindingLifecycle_FINDING_LIFECYCLE_UNSPECIFIED
	}
}

func toFindingProto(f api.Finding) *securityv1.Finding {
	return &securityv1.Finding{
		FindingId: f.ID, TenantId: f.TenantID, RepositoryId: f.RepositoryID,
		ScannerClass: toScannerClassProto(f.ScannerClass),
		ToolName:     f.ToolName, ToolVersion: f.ToolVersion,
		RuleId: f.RuleID, Severity: toSeverityProto(f.Severity),
		Location: &securityv1.FindingLocation{
			ArtifactPath:     f.Location.ArtifactPath,
			EnclosingContent: f.Location.EnclosingContent,
			Component:        f.Location.Component,
			ComponentVersion: f.Location.ComponentVersion,
		},
		Lifecycle: toLifecycleProto(f.Lifecycle),
		FirstSeenScanId: f.FirstSeenScanID, LastSeenScanId: f.LastSeenScanID,
		Provenance: f.Provenance, ProvenanceMediaType: f.ProvenanceMediaType,
	}
}
