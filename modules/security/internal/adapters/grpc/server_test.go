// Adapter tests for the Findings gRPC surface: every RPC of the contract is
// implemented (no fall-through to Unimplemented), proto <-> api types map
// field-for-field, the tenant-wide read paths accept an EMPTY repository_id
// (the repository scope is server-derived per SPEC-0026 AC6) while the
// single-repository paths still demand one, and errors map to the coarse
// gRPC shapes (SPEC-0025 AC2).
package grpc

import (
	"context"
	"testing"
	"time"

	securityv1 "github.com/gitfrok/backend/gen/proto/security/v1"
	"github.com/gitfrok/backend/modules/security/api"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// stubFindings implements api.Findings, recording every mapped request and
// answering from test state. A field left zero answers the zero shape.
type stubFindings struct {
	ingestChunk api.IngestChunk
	ingestRes   api.IngestResult
	ingestErr   error

	getFindingID  string
	getFindingCtx api.Context
	finding       api.Finding
	findingErr    error

	listReq api.ListRequest
	listRes api.ListPage
	listErr error

	mrReq api.MergeRequestFindingsRequest
	mrRes api.MergeRequestFindingsPage
	mrErr error

	triageReq api.TriageTransition
	triageOut api.SetTriageOutcome
	triageErr error

	getTriageCtx     api.Context
	getTriageID      string
	getTriageVersion int64
	getTriageRec     api.TriageRecord
	getTriageFound   bool
	getTriageErr     error

	summaryReq api.SummaryRequest
	summaryRes api.FindingsSummary
	summaryErr error
}

func (s *stubFindings) IngestScanResults(_ context.Context, chunk api.IngestChunk) (api.IngestResult, error) {
	s.ingestChunk = chunk
	return s.ingestRes, s.ingestErr
}

func (s *stubFindings) GetFinding(_ context.Context, c api.Context, findingID string) (api.Finding, error) {
	s.getFindingCtx, s.getFindingID = c, findingID
	return s.finding, s.findingErr
}

func (s *stubFindings) ListFindings(_ context.Context, req api.ListRequest) (api.ListPage, error) {
	s.listReq = req
	return s.listRes, s.listErr
}

func (s *stubFindings) ListMergeRequestFindings(_ context.Context, req api.MergeRequestFindingsRequest) (api.MergeRequestFindingsPage, error) {
	s.mrReq = req
	return s.mrRes, s.mrErr
}

func (s *stubFindings) SetTriage(_ context.Context, req api.TriageTransition) (api.SetTriageOutcome, error) {
	s.triageReq = req
	return s.triageOut, s.triageErr
}

func (s *stubFindings) GetTriage(_ context.Context, c api.Context, findingID string, version int64) (api.TriageRecord, bool, error) {
	s.getTriageCtx, s.getTriageID, s.getTriageVersion = c, findingID, version
	return s.getTriageRec, s.getTriageFound, s.getTriageErr
}

func (s *stubFindings) GetFindingsSummary(_ context.Context, req api.SummaryRequest) (api.FindingsSummary, error) {
	s.summaryReq = req
	return s.summaryRes, s.summaryErr
}

// fullCtx is a context with every field, repository included.
func fullCtx() *securityv1.FindingsContext {
	return &securityv1.FindingsContext{
		TenantId: "t-1", RepositoryId: "repo-1", ActorId: "actor-1",
		ActorRoles: []string{"member"}, RequestId: "req-1",
	}
}

// tenantCtx is the BFF shape of a dashboard read (SPEC-0026 AC6): no
// repository_id — the scope is server-derived.
func tenantCtx() *securityv1.FindingsContext {
	return &securityv1.FindingsContext{
		TenantId: "t-1", ActorId: "actor-1", ActorRoles: []string{"member"}, RequestId: "req-1",
	}
}

func wantCode(t *testing.T, err error, code codes.Code) {
	t.Helper()
	if status.Code(err) != code {
		t.Fatalf("status = %v, want %s (err=%v)", status.Code(err), code, err)
	}
}

// SetTriage maps the transition request and the record in force back, and
// renders the service's boundary refusal and coarse denial as the contract's
// gRPC shapes.
func TestSetTriageAdapter(t *testing.T) {
	stub := &stubFindings{triageOut: api.SetTriageOutcome{Record: api.TriageRecord{
		TriageID: "tri-1", FindingID: "f-1", TenantID: "t-1", RepositoryID: "repo-1",
		State: api.TriageAccept, Justification: "risk accepted", Version: 1,
		ActorID: "actor-1", OccurredAt: time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC),
	}}}
	s := NewServer(stub)

	res, err := s.SetTriage(context.Background(), &securityv1.SetTriageRequest{
		Context: fullCtx(), FindingId: "f-1",
		State:         securityv1.TriageState_TRIAGE_STATE_ACCEPT,
		Justification: "risk accepted", ExpectedVersion: 0,
	})
	if err != nil {
		t.Fatalf("SetTriage: %v", err)
	}
	got := stub.triageReq
	if got.FindingID != "f-1" || got.State != api.TriageAccept ||
		got.Justification != "risk accepted" || got.ExpectedVersion != 0 ||
		got.TenantID != "t-1" || got.RepositoryID != "repo-1" || got.ActorID != "actor-1" || got.RequestID != "req-1" {
		t.Fatalf("mapped transition: %+v", got)
	}
	if res.Record.GetTriageId() != "tri-1" || res.Record.GetState() != securityv1.TriageState_TRIAGE_STATE_ACCEPT ||
		res.Record.GetVersion() != 1 || res.Record.GetFindingId() != "f-1" ||
		res.Record.GetOccurredAt().AsTime().Unix() != time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC).Unix() {
		t.Fatalf("mapped record: %+v", res.Record)
	}

	// The service's boundary refusal is InvalidArgument; anything else is the
	// coarse denial.
	stub.triageErr = api.ErrMalformed
	_, err = s.SetTriage(context.Background(), &securityv1.SetTriageRequest{Context: fullCtx(), FindingId: "f-1"})
	wantCode(t, err, codes.InvalidArgument)
	stub.triageErr = api.ErrDenied
	_, err = s.SetTriage(context.Background(), &securityv1.SetTriageRequest{Context: fullCtx(), FindingId: "f-1"})
	wantCode(t, err, codes.PermissionDenied)
}

// GetTriage maps the read and renders absence as a record-less response, the
// same coarse shape as denial.
func TestGetTriageAdapter(t *testing.T) {
	stub := &stubFindings{getTriageFound: true, getTriageRec: api.TriageRecord{
		TriageID: "tri-2", FindingID: "f-2", TenantID: "t-1", RepositoryID: "repo-1",
		State: api.TriageDefer, Version: 3, ActorID: "actor-1",
	}}
	s := NewServer(stub)

	res, err := s.GetTriage(context.Background(), &securityv1.GetTriageRequest{
		Context: fullCtx(), FindingId: "f-2", Version: 3,
	})
	if err != nil {
		t.Fatalf("GetTriage: %v", err)
	}
	if stub.getTriageID != "f-2" || stub.getTriageVersion != 3 || stub.getTriageCtx.RepositoryID != "repo-1" {
		t.Fatalf("mapped read: id=%q version=%d ctx=%+v", stub.getTriageID, stub.getTriageVersion, stub.getTriageCtx)
	}
	if res.Record.GetTriageId() != "tri-2" || res.Record.GetState() != securityv1.TriageState_TRIAGE_STATE_DEFER {
		t.Fatalf("mapped record: %+v", res.Record)
	}

	stub.getTriageFound = false
	res, err = s.GetTriage(context.Background(), &securityv1.GetTriageRequest{Context: fullCtx(), FindingId: "f-2"})
	if err != nil || res.Record != nil {
		t.Fatalf("absence must be a record-less response, got %+v err=%v", res, err)
	}

	stub.getTriageErr = api.ErrDenied
	_, err = s.GetTriage(context.Background(), &securityv1.GetTriageRequest{Context: fullCtx(), FindingId: "f-2"})
	wantCode(t, err, codes.PermissionDenied)
}

// GetFindingsSummary is one of the tenant-wide reads: it accepts an EMPTY
// repository_id, maps the full dashboard filter set including the age and
// owning-team bounds, and renders facets.
func TestGetFindingsSummaryAdapter(t *testing.T) {
	stub := &stubFindings{summaryRes: api.FindingsSummary{
		TotalCount: 7,
		Facets: []api.SummaryFacet{{Dimension: api.FacetSeverity, Values: []api.SummaryFacetValue{
			{Value: "HIGH", Count: 4}, {Value: "LOW", Count: 3},
		}}},
	}}
	s := NewServer(stub)

	res, err := s.GetFindingsSummary(context.Background(), &securityv1.GetFindingsSummaryRequest{
		Context:            tenantCtx(), // no repository_id: the BFF shape
		RepositoryFilter:   "repo-1",
		ScannerClassFilter: securityv1.ScannerClass_SCANNER_CLASS_SAST,
		SeverityFilter:     securityv1.FindingSeverity_FINDING_SEVERITY_HIGH,
		LifecycleFilter:    securityv1.FindingLifecycle_FINDING_LIFECYCLE_OPEN,
		MinAgeDays:         2, MaxAgeDays: 30,
		OwningTeamFilter: "team-a",
		FacetDimensions:  []string{api.FacetSeverity},
	})
	if err != nil {
		t.Fatalf("GetFindingsSummary: %v", err)
	}
	got := stub.summaryReq
	if got.RepositoryID != "" || got.TenantID != "t-1" || got.RepositoryFilter != "repo-1" ||
		got.ScannerClassFilter != api.ScannerClassSAST || got.SeverityFilter != api.SeverityHigh ||
		got.LifecycleFilter != api.LifecycleOpen || got.MinAgeDays != 2 || got.MaxAgeDays != 30 ||
		got.OwningTeamFilter != "team-a" || len(got.FacetDimensions) != 1 || got.FacetDimensions[0] != api.FacetSeverity {
		t.Fatalf("mapped summary request: %+v", got)
	}
	if res.TotalCount != 7 || len(res.Facets) != 1 || res.Facets[0].Dimension != api.FacetSeverity ||
		len(res.Facets[0].Values) != 2 || res.Facets[0].Values[0].Value != "HIGH" || res.Facets[0].Values[0].Count != 4 {
		t.Fatalf("mapped response: %+v", res)
	}

	stub.summaryErr = api.ErrMalformed
	_, err = s.GetFindingsSummary(context.Background(), &securityv1.GetFindingsSummaryRequest{Context: tenantCtx()})
	wantCode(t, err, codes.InvalidArgument)
	stub.summaryErr = api.ErrDenied
	_, err = s.GetFindingsSummary(context.Background(), &securityv1.GetFindingsSummaryRequest{Context: tenantCtx()})
	wantCode(t, err, codes.PermissionDenied)
}

// ListFindings accepts the tenant-wide shape and maps the dashboard filters
// the BFF parses — min/max age and owning team among them.
func TestListFindingsAdapterMapsFilters(t *testing.T) {
	stub := &stubFindings{listRes: api.ListPage{Findings: []api.Finding{{
		ID: "f-1", TenantID: "t-1", RepositoryID: "repo-1", ScannerClass: api.ScannerClassSAST,
		ToolName: "semgrep", RuleID: "rule-a", Severity: api.SeverityHigh, Lifecycle: api.LifecycleOpen,
	}}, NextPageToken: "tok"}}
	s := NewServer(stub)

	res, err := s.ListFindings(context.Background(), &securityv1.ListFindingsRequest{
		Context:            tenantCtx(), // empty repository_id
		RepositoryFilter:   "repo-1",
		ScannerClassFilter: securityv1.ScannerClass_SCANNER_CLASS_SAST,
		SeverityFilter:     securityv1.FindingSeverity_FINDING_SEVERITY_HIGH,
		LifecycleFilter:    securityv1.FindingLifecycle_FINDING_LIFECYCLE_OPEN,
		MinAgeDays:         3, MaxAgeDays: 40, OwningTeamFilter: "team-a",
		PageSize: 25, PageToken: "prev",
	})
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	got := stub.listReq
	if got.RepositoryID != "" || got.RepositoryFilter != "repo-1" ||
		got.ScannerClassFilter != api.ScannerClassSAST || got.SeverityFilter != api.SeverityHigh ||
		got.LifecycleFilter != api.LifecycleOpen || got.MinAgeDays != 3 || got.MaxAgeDays != 40 ||
		got.OwningTeamFilter != "team-a" || got.PageSize != 25 || got.PageToken != "prev" {
		t.Fatalf("mapped list request: %+v", got)
	}
	if len(res.Findings) != 1 || res.Findings[0].FindingId != "f-1" || res.NextPageToken != "tok" {
		t.Fatalf("mapped response: %+v", res)
	}

	stub.listErr = api.ErrDenied
	_, err = s.ListFindings(context.Background(), &securityv1.ListFindingsRequest{Context: tenantCtx()})
	wantCode(t, err, codes.PermissionDenied)
}

// ListMergeRequestFindings accepts the tenant-wide shape and maps filters.
func TestListMergeRequestFindingsAdapter(t *testing.T) {
	stub := &stubFindings{mrRes: api.MergeRequestFindingsPage{
		Views: []api.MergeRequestFindingView{{
			Finding:     api.Finding{ID: "f-1", TenantID: "t-1", RepositoryID: "repo-1", Severity: api.SeverityHigh},
			Attribution: api.AttributionAttributed,
		}},
		Summary: api.AttributionSummary{Status: api.AttributionAttributed, HeadRevision: "rev-head", AttributedHigh: 1},
	}}
	s := NewServer(stub)

	res, err := s.ListMergeRequestFindings(context.Background(), &securityv1.ListMergeRequestFindingsRequest{
		Context: tenantCtx(), MergeRequestId: "mr-1",
		SeverityFilter:    securityv1.FindingSeverity_FINDING_SEVERITY_HIGH,
		AttributionFilter: securityv1.AttributionStatus_ATTRIBUTION_STATUS_ATTRIBUTED,
		PageSize:          10,
	})
	if err != nil {
		t.Fatalf("ListMergeRequestFindings: %v", err)
	}
	got := stub.mrReq
	if got.RepositoryID != "" || got.MergeRequestID != "mr-1" || got.SeverityFilter != api.SeverityHigh ||
		got.AttributionFilter != api.AttributionAttributed || got.PageSize != 10 {
		t.Fatalf("mapped MR request: %+v", got)
	}
	if len(res.Findings) != 1 || res.Findings[0].Attribution != securityv1.AttributionStatus_ATTRIBUTION_STATUS_ATTRIBUTED ||
		res.Summary.GetHeadRevision() != "rev-head" || res.Summary.GetAttributedHigh() != 1 {
		t.Fatalf("mapped response: %+v", res)
	}

	stub.mrErr = api.ErrMalformed
	_, err = s.ListMergeRequestFindings(context.Background(), &securityv1.ListMergeRequestFindingsRequest{Context: tenantCtx(), MergeRequestId: "mr-1"})
	wantCode(t, err, codes.InvalidArgument)
	stub.mrErr = api.ErrDenied
	_, err = s.ListMergeRequestFindings(context.Background(), &securityv1.ListMergeRequestFindingsRequest{Context: tenantCtx(), MergeRequestId: "mr-1"})
	wantCode(t, err, codes.PermissionDenied)
}

// The contract's two context shapes: single-repository operations demand a
// repository_id, tenant-wide reads accept its absence but never an absent
// tenant, actor, or request ID (SPEC-0026 AC6).
func TestContextRequirementsAcrossRPCs(t *testing.T) {
	s := NewServer(&stubFindings{})
	ctx := context.Background()

	noRepo := tenantCtx() // repository_id empty

	// Single-repository paths keep the strict shape: no repository_id is the
	// boundary refusal.
	if _, err := s.GetFinding(ctx, &securityv1.GetFindingRequest{Context: noRepo, FindingId: "f-1"}); !isMalformed(err) {
		t.Fatalf("GetFinding without repository_id must be malformed, got %v", err)
	}
	if _, err := s.SetTriage(ctx, &securityv1.SetTriageRequest{Context: noRepo, FindingId: "f-1"}); !isMalformed(err) {
		t.Fatalf("SetTriage without repository_id must be malformed, got %v", err)
	}
	if _, err := s.GetTriage(ctx, &securityv1.GetTriageRequest{Context: noRepo, FindingId: "f-1"}); !isMalformed(err) {
		t.Fatalf("GetTriage without repository_id must be malformed, got %v", err)
	}

	// Tenant-wide paths accept the empty repository — they reach the port.
	port := &stubFindings{}
	s2 := NewServer(port)
	if _, err := s2.ListFindings(ctx, &securityv1.ListFindingsRequest{Context: noRepo}); err != nil {
		t.Fatalf("ListFindings must accept an empty repository_id, got %v", err)
	}
	if _, err := s2.GetFindingsSummary(ctx, &securityv1.GetFindingsSummaryRequest{Context: noRepo}); err != nil {
		t.Fatalf("GetFindingsSummary must accept an empty repository_id, got %v", err)
	}
	if _, err := s2.ListMergeRequestFindings(ctx, &securityv1.ListMergeRequestFindingsRequest{Context: noRepo, MergeRequestId: "mr-1"}); err != nil {
		t.Fatalf("ListMergeRequestFindings must accept an empty repository_id, got %v", err)
	}

	// But no path accepts an absent tenant, actor, or request ID.
	for name, mutate := range map[string]func(*securityv1.FindingsContext){
		"no tenant":  func(c *securityv1.FindingsContext) { c.TenantId = "" },
		"no actor":   func(c *securityv1.FindingsContext) { c.ActorId = "" },
		"no request": func(c *securityv1.FindingsContext) { c.RequestId = "" },
		"nil":        nil,
	} {
		bad := tenantCtx()
		if mutate != nil {
			mutate(bad)
		} else {
			bad = nil
		}
		if _, err := s.ListFindings(ctx, &securityv1.ListFindingsRequest{Context: bad}); !isMalformed(err) {
			t.Fatalf("ListFindings %s must be malformed, got %v", name, err)
		}
		if _, err := s.GetFindingsSummary(ctx, &securityv1.GetFindingsSummaryRequest{Context: bad}); !isMalformed(err) {
			t.Fatalf("GetFindingsSummary %s must be malformed, got %v", name, err)
		}
	}
}

func isMalformed(err error) bool {
	return status.Code(err) == codes.InvalidArgument
}
