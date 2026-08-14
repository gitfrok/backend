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
	"google.golang.org/protobuf/types/known/timestamppb"
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
	ctx, c, err := intoTenantContext(ctx, req.GetContext())
	if err != nil {
		return nil, err
	}
	page, err := s.findings.ListFindings(ctx, api.ListRequest{
		Context:            c,
		RepositoryFilter:   req.GetRepositoryFilter(),
		ScannerClassFilter: fromScannerClassProto(req.GetScannerClassFilter()),
		SeverityFilter:     fromSeverityProto(req.GetSeverityFilter()),
		LifecycleFilter:    fromLifecycleProto(req.GetLifecycleFilter()),
		MinAgeDays:         int(req.GetMinAgeDays()),
		MaxAgeDays:         int(req.GetMaxAgeDays()),
		OwningTeamFilter:   req.GetOwningTeamFilter(),
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

// intoContext validates a single-repository operation's context: every
// field, repository included, is mandatory (SPEC-0025).
func intoContext(ctx context.Context, c *securityv1.FindingsContext) (context.Context, api.Context, error) {
	if c == nil || c.GetTenantId() == "" || c.GetRepositoryId() == "" ||
		c.GetActorId() == "" || c.GetRequestId() == "" {
		return ctx, api.Context{}, errMalformed
	}
	return withAPIContext(ctx, c)
}

// intoTenantContext validates the tenant-wide read paths (SPEC-0026 AC6):
// the repository scope is SERVER-DERIVED for them — the BFF never sends
// repository_id on a dashboard or merge-request findings read — so it is
// optional here while tenant, actor, and request ID remain mandatory.
func intoTenantContext(ctx context.Context, c *securityv1.FindingsContext) (context.Context, api.Context, error) {
	if c == nil || c.GetTenantId() == "" || c.GetActorId() == "" || c.GetRequestId() == "" {
		return ctx, api.Context{}, errMalformed
	}
	return withAPIContext(ctx, c)
}

func withAPIContext(ctx context.Context, c *securityv1.FindingsContext) (context.Context, api.Context, error) {
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
		Lifecycle:       toLifecycleProto(f.Lifecycle),
		FirstSeenScanId: f.FirstSeenScanID, LastSeenScanId: f.LastSeenScanID,
		Provenance: f.Provenance, ProvenanceMediaType: f.ProvenanceMediaType,
	}
}

// ListMergeRequestFindings pages the findings attributable to one merge
// request (SPEC-0028). The summary is always present: an UNAVAILABLE
// summary with an empty list is still UNAVAILABLE, never "no findings".
func (s *Server) ListMergeRequestFindings(ctx context.Context, req *securityv1.ListMergeRequestFindingsRequest) (*securityv1.ListMergeRequestFindingsResponse, error) {
	ctx, c, err := intoTenantContext(ctx, req.GetContext())
	if err != nil {
		return nil, err
	}
	page, err := s.findings.ListMergeRequestFindings(ctx, api.MergeRequestFindingsRequest{
		Context:            c,
		MergeRequestID:     req.GetMergeRequestId(),
		ScannerClassFilter: fromScannerClassProto(req.GetScannerClassFilter()),
		SeverityFilter:     fromSeverityProto(req.GetSeverityFilter()),
		AttributionFilter:  fromAttributionProto(req.GetAttributionFilter()),
		PageSize:           int(req.GetPageSize()),
		PageToken:          req.GetPageToken(),
	})
	if err != nil {
		if errors.Is(err, api.ErrMalformed) {
			return nil, errMalformed
		}
		return nil, denial()
	}
	out := &securityv1.ListMergeRequestFindingsResponse{
		NextPageToken: page.NextPageToken,
		Summary:       toAttributionSummaryProto(page.Summary),
	}
	for _, v := range page.Views {
		out.Findings = append(out.Findings, toMergeRequestFindingViewProto(v))
	}
	return out, nil
}

func fromAttributionProto(a securityv1.AttributionStatus) api.AttributionStatus {
	switch a {
	case securityv1.AttributionStatus_ATTRIBUTION_STATUS_ATTRIBUTED:
		return api.AttributionAttributed
	case securityv1.AttributionStatus_ATTRIBUTION_STATUS_PRE_EXISTING:
		return api.AttributionPreExisting
	case securityv1.AttributionStatus_ATTRIBUTION_STATUS_UNAVAILABLE:
		return api.AttributionUnavailable
	default:
		return api.AttributionStatusUnspecified // unspecified means "no filter"
	}
}

func toAttributionProto(a api.AttributionStatus) securityv1.AttributionStatus {
	switch a {
	case api.AttributionAttributed:
		return securityv1.AttributionStatus_ATTRIBUTION_STATUS_ATTRIBUTED
	case api.AttributionPreExisting:
		return securityv1.AttributionStatus_ATTRIBUTION_STATUS_PRE_EXISTING
	case api.AttributionUnavailable:
		return securityv1.AttributionStatus_ATTRIBUTION_STATUS_UNAVAILABLE
	default:
		return securityv1.AttributionStatus_ATTRIBUTION_STATUS_UNSPECIFIED
	}
}

func toAttributionReasonProto(r api.AttributionUnavailableReason) securityv1.AttributionUnavailableReason {
	switch r {
	case api.AttributionUnavailableBaseNotScanned:
		return securityv1.AttributionUnavailableReason_ATTRIBUTION_UNAVAILABLE_REASON_BASE_NOT_SCANNED
	case api.AttributionUnavailableHeadScanFailed:
		return securityv1.AttributionUnavailableReason_ATTRIBUTION_UNAVAILABLE_REASON_HEAD_SCAN_FAILED
	case api.AttributionUnavailableHeadScanTimedOut:
		return securityv1.AttributionUnavailableReason_ATTRIBUTION_UNAVAILABLE_REASON_HEAD_SCAN_TIMED_OUT
	case api.AttributionUnavailableHeadScanNotRun:
		return securityv1.AttributionUnavailableReason_ATTRIBUTION_UNAVAILABLE_REASON_HEAD_SCAN_NOT_RUN
	case api.AttributionUnavailableNoMergeBase:
		return securityv1.AttributionUnavailableReason_ATTRIBUTION_UNAVAILABLE_REASON_NO_MERGE_BASE
	default:
		return securityv1.AttributionUnavailableReason_ATTRIBUTION_UNAVAILABLE_REASON_UNSPECIFIED
	}
}

func toTriageStateProto(s api.TriageState) securityv1.TriageState {
	switch s {
	case api.TriageAccept:
		return securityv1.TriageState_TRIAGE_STATE_ACCEPT
	case api.TriageFalsePositive:
		return securityv1.TriageState_TRIAGE_STATE_FALSE_POSITIVE
	case api.TriageFix:
		return securityv1.TriageState_TRIAGE_STATE_FIX
	case api.TriageDefer:
		return securityv1.TriageState_TRIAGE_STATE_DEFER
	default:
		return securityv1.TriageState_TRIAGE_STATE_UNSPECIFIED
	}
}

func fromTriageStateProto(s securityv1.TriageState) api.TriageState {
	switch s {
	case securityv1.TriageState_TRIAGE_STATE_ACCEPT:
		return api.TriageAccept
	case securityv1.TriageState_TRIAGE_STATE_FALSE_POSITIVE:
		return api.TriageFalsePositive
	case securityv1.TriageState_TRIAGE_STATE_FIX:
		return api.TriageFix
	case securityv1.TriageState_TRIAGE_STATE_DEFER:
		return api.TriageDefer
	default:
		return api.TriageStateUnspecified // unspecified is invalid; the service refuses it
	}
}

// SetTriage records a triage decision on a finding identity (SPEC-0026,
// SPEC-0027). The request shape carries no severity, no lifecycle, and no
// authorization flag; an unspecified state surfaces as the service's
// boundary refusal.
func (s *Server) SetTriage(ctx context.Context, req *securityv1.SetTriageRequest) (*securityv1.SetTriageResponse, error) {
	ctx, c, err := intoContext(ctx, req.GetContext())
	if err != nil {
		return nil, err
	}
	out, err := s.findings.SetTriage(ctx, api.TriageTransition{
		Context:         c,
		FindingID:       req.GetFindingId(),
		State:           fromTriageStateProto(req.GetState()),
		Justification:   req.GetJustification(),
		ExpectedVersion: req.GetExpectedVersion(),
	})
	if err != nil {
		if errors.Is(err, api.ErrMalformed) {
			return nil, errMalformed
		}
		return nil, denial()
	}
	return &securityv1.SetTriageResponse{Record: toTriageRecordProto(out.Record)}, nil
}

// GetTriage reads a finding's triage record (SPEC-0027 AC6). Absence and
// denial are the same coarse shape: the response simply carries no record.
func (s *Server) GetTriage(ctx context.Context, req *securityv1.GetTriageRequest) (*securityv1.GetTriageResponse, error) {
	ctx, c, err := intoContext(ctx, req.GetContext())
	if err != nil {
		return nil, err
	}
	rec, found, err := s.findings.GetTriage(ctx, c, req.GetFindingId(), req.GetVersion())
	if err != nil {
		return nil, denial()
	}
	out := &securityv1.GetTriageResponse{}
	if found {
		out.Record = toTriageRecordProto(rec)
	}
	return out, nil
}

// GetFindingsSummary returns counts and facet values computed under the
// caller's authorization (SPEC-0026 AC6). The context's repository is
// server-derived scope: the BFF does not send it, and an org-wide summary
// is the same request with no repository filter (SPEC-0026 AC1).
func (s *Server) GetFindingsSummary(ctx context.Context, req *securityv1.GetFindingsSummaryRequest) (*securityv1.GetFindingsSummaryResponse, error) {
	ctx, c, err := intoTenantContext(ctx, req.GetContext())
	if err != nil {
		return nil, err
	}
	summary, err := s.findings.GetFindingsSummary(ctx, api.SummaryRequest{
		Context:            c,
		RepositoryFilter:   req.GetRepositoryFilter(),
		ScannerClassFilter: fromScannerClassProto(req.GetScannerClassFilter()),
		SeverityFilter:     fromSeverityProto(req.GetSeverityFilter()),
		LifecycleFilter:    fromLifecycleProto(req.GetLifecycleFilter()),
		MinAgeDays:         int(req.GetMinAgeDays()),
		MaxAgeDays:         int(req.GetMaxAgeDays()),
		OwningTeamFilter:   req.GetOwningTeamFilter(),
		FacetDimensions:    append([]string(nil), req.GetFacetDimensions()...),
	})
	if err != nil {
		if errors.Is(err, api.ErrMalformed) {
			return nil, errMalformed
		}
		return nil, denial()
	}
	out := &securityv1.GetFindingsSummaryResponse{TotalCount: summary.TotalCount}
	for _, facet := range summary.Facets {
		out.Facets = append(out.Facets, toSummaryFacetProto(facet))
	}
	return out, nil
}

func toSummaryFacetProto(f api.SummaryFacet) *securityv1.SummaryFacet {
	out := &securityv1.SummaryFacet{Dimension: f.Dimension}
	for _, v := range f.Values {
		out.Values = append(out.Values, &securityv1.SummaryFacetValue{Value: v.Value, Count: v.Count})
	}
	return out
}

func toTriageRecordProto(r api.TriageRecord) *securityv1.TriageRecord {
	return &securityv1.TriageRecord{
		TriageId: r.TriageID, FindingId: r.FindingID,
		TenantId: r.TenantID, RepositoryId: r.RepositoryID,
		State: toTriageStateProto(r.State), Justification: r.Justification,
		Version: r.Version, ActorId: r.ActorID,
		OccurredAt: timestamppb.New(r.OccurredAt),
	}
}

func toMergeRequestFindingViewProto(v api.MergeRequestFindingView) *securityv1.MergeRequestFindingView {
	out := &securityv1.MergeRequestFindingView{
		Finding: toFindingProto(v.Finding),
		HeadLocation: &securityv1.FindingLocation{
			ArtifactPath:     v.HeadLocation.ArtifactPath,
			EnclosingContent: v.HeadLocation.EnclosingContent,
			Component:        v.HeadLocation.Component,
			ComponentVersion: v.HeadLocation.ComponentVersion,
		},
		Attribution:       toAttributionProto(v.Attribution),
		UnavailableReason: toAttributionReasonProto(v.UnavailableReason),
	}
	if v.Triage != nil {
		out.Triage = toTriageRecordProto(*v.Triage)
	}
	return out
}

func toAttributionSummaryProto(s api.AttributionSummary) *securityv1.AttributionSummary {
	return &securityv1.AttributionSummary{
		Status:             toAttributionProto(s.Status),
		UnavailableReason:  toAttributionReasonProto(s.UnavailableReason),
		HeadRevision:       s.HeadRevision,
		MergeBaseRevision:  s.MergeBaseRevision,
		Stale:              s.Stale,
		AttributedLow:      s.AttributedLow,
		AttributedMedium:   s.AttributedMedium,
		AttributedHigh:     s.AttributedHigh,
		AttributedCritical: s.AttributedCritical,
	}
}
