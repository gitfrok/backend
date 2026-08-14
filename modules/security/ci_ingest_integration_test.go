package security_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/gitfrok/backend/modules/ci"
	"github.com/gitfrok/backend/modules/security"
	"github.com/gitfrok/backend/modules/security/api"
	"github.com/gitfrok/backend/platform/bus"
	"github.com/gitfrok/backend/platform/ids"
)

// These tests compose BOTH modules through their module surfaces — the report
// store on CI's side, the ingester on Security's, joined by the ports the
// composition root wires — exactly as cmd/dataplane-app does. They are the
// integration layer SPEC-0037's tests-to-write-first list names: a
// runner-shaped writer, durable read-back, visibility through ListFindings,
// and redelivery ingesting once.

// integrationJobSource mirrors the composition root's adapter: one scoped
// correlation, coarse not-known for anything out of scope.
type integrationJobSource struct {
	jobs map[string]security.CIScanJob
}

func (s *integrationJobSource) ScanJob(_ context.Context, tenantID, repositoryID, jobID string) (security.CIScanJob, error) {
	job, ok := s.jobs[jobID]
	if !ok || job.TenantID != tenantID || job.RepositoryID != repositoryID {
		return security.CIScanJob{}, security.ErrCIScanJobUnknown
	}
	return job, nil
}

// integrationReportSource is the report port over the REAL CI report store —
// the same translation the dataplane composes: refs become report bytes, and
// the backfill enumeration dedups to attempt addresses.
type integrationReportSource struct{ store *ci.ScanReportStore }

func (s integrationReportSource) AttemptReports(ctx context.Context, tenantID, repositoryID, jobID, attemptID string) ([]security.CIScanReport, error) {
	refs, err := s.store.AttemptReports(ctx, tenantID, repositoryID, jobID, attemptID)
	if err != nil {
		return nil, err
	}
	reports := make([]security.CIScanReport, 0, len(refs))
	for _, ref := range refs {
		body, err := s.store.Read(ctx, ref.TenantID, ref.RepositoryID, ref.JobID, ref.AttemptID, ref.ScannerClass)
		if err != nil {
			return nil, err
		}
		reports = append(reports, security.CIScanReport{ScannerClass: ref.ScannerClass, Report: body})
	}
	return reports, nil
}

func (s integrationReportSource) ScanReportAddrs(ctx context.Context) ([]security.CIScanReportAddr, error) {
	refs, err := s.store.AllRefs(ctx)
	if err != nil {
		return nil, err
	}
	seen := map[security.CIScanReportAddr]bool{}
	var addrs []security.CIScanReportAddr
	for _, ref := range refs {
		addr := security.CIScanReportAddr{TenantID: ref.TenantID, RepositoryID: ref.RepositoryID, JobID: ref.JobID, AttemptID: ref.AttemptID}
		if !seen[addr] {
			seen[addr] = true
			addrs = append(addrs, addr)
		}
	}
	return addrs, nil
}

// integrationPlane composes the two contexts the way the dataplane does and
// hands back every piece a test needs to assert on.
func integrationPlane(t *testing.T) (*ci.ScanReportStore, *security.CIScanIngester, api.Findings, *integrationJobSource, *allowPDP) {
	t.Helper()
	store, err := ci.NewScanReportStore(ci.NewMemoryReportTier(), 1<<20, time.Now)
	if err != nil {
		t.Fatalf("NewScanReportStore: %v", err)
	}
	pdp := &allowPDP{}
	findings := security.New(pdp, bus.NewInProcess())
	jobs := &integrationJobSource{jobs: map[string]security.CIScanJob{}}
	ingester, err := security.NewCIScanIngester(findings, jobs, integrationReportSource{store: store}, time.Now)
	if err != nil {
		t.Fatalf("NewCIScanIngester: %v", err)
	}
	return store, ingester, findings, jobs, pdp
}

// integrationSemgrepReport is one parseable SAST report with one result.
func integrationSemgrepReport() []byte {
	out, err := json.Marshal(map[string]any{
		"version": "1.99.0",
		"results": []map[string]any{{
			"check_id": "rule-1",
			"path":     "pkg/file.go",
			"extra":    map[string]any{"severity": "ERROR"},
		}},
	})
	if err != nil {
		panic(err)
	}
	return out
}

func integrationJob(tenantID, repositoryID, jobID, attemptID string) security.CIScanJob {
	base := time.Date(2026, 8, 14, 9, 55, 0, 0, time.UTC)
	return security.CIScanJob{
		ID: jobID, AttemptID: attemptID, TenantID: tenantID, RepositoryID: repositoryID,
		ActorID: "ci-runner", ActorRoles: []string{"ci"},
		CommitSHA:  "c0ffee1234567890abcdef1234567890abcdef12",
		State:      "SUCCEEDED",
		StartedAt:  base,
		FinishedAt: base.Add(5 * time.Minute),
	}
}

func listFindings(t *testing.T, findings api.Findings, tenantID, repositoryID string) []api.Finding {
	t.Helper()
	page, err := findings.ListFindings(context.Background(), api.ListRequest{
		Context: api.Context{TenantID: tenantID, RepositoryID: repositoryID, ActorID: "auditor-1", RequestID: ids.NewULID()},
	})
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	return page.Findings
}

// TestRunnerShapedReportFlowsEndToEnd is the integration AC1+AC2+AC3: the
// runner's writer stores the report by its five-part address, the finished
// job's event ingests it, and the findings are visible through the public
// ListFindings surface — under the job's own principal and revision.
func TestRunnerShapedReportFlowsEndToEnd(t *testing.T) {
	store, ingester, findings, jobs, _ := integrationPlane(t)
	jobID, attemptID := ids.NewULID(), ids.NewULID()

	// The runner-shaped write: the scan step persists its raw report by
	// (tenant, repository, job, attempt, scanner class).
	ref, err := store.Write(context.Background(), "t-1", "repo-1", jobID, attemptID, "sast", bytes.NewReader(integrationSemgrepReport()))
	if err != nil {
		t.Fatalf("the runner's report write: %v", err)
	}
	if ref.JobID != jobID || ref.AttemptID != attemptID || ref.ScannerClass != "sast" {
		t.Fatalf("report ref = %+v", ref)
	}

	jobs.jobs[jobID] = integrationJob("t-1", "repo-1", jobID, attemptID)
	err = ingester.HandleJobFinished(context.Background(), security.CIScanJobFinished{JobID: jobID, TenantID: "t-1", RepositoryID: "repo-1"})
	if err != nil {
		t.Fatalf("HandleJobFinished: %v", err)
	}

	got := listFindings(t, findings, "t-1", "repo-1")
	if len(got) != 1 {
		t.Fatalf("ListFindings = %d findings, want the one the report carried", len(got))
	}
}

// TestReportSurvivesTheAttemptAndRedeliveryIngestsOnce is the durability and
// idempotency integration (AC1, AC6): the report outlives the attempt —
// written before any job state exists, recovered by the backfill sweep once
// the job is correlatable — and both a later redelivery and a second sweep
// replay without duplicating a single finding.
func TestReportSurvivesTheAttemptAndRedeliveryIngestsOnce(t *testing.T) {
	store, ingester, findings, jobs, _ := integrationPlane(t)
	jobID, attemptID := ids.NewULID(), ids.NewULID()
	if _, err := store.Write(context.Background(), "t-1", "repo-1", jobID, attemptID, "sast", bytes.NewReader(integrationSemgrepReport())); err != nil {
		t.Fatalf("the runner's report write: %v", err)
	}

	// The attempt is gone before anything correlates: the sweep finds the
	// report but has no job to run it as, and changes nothing.
	if err := ingester.Backfill(context.Background()); err != nil {
		t.Fatalf("Backfill with a vanished job: %v", err)
	}
	if got := listFindings(t, findings, "t-1", "repo-1"); len(got) != 0 {
		t.Fatalf("a jobless backfill produced %d findings", len(got))
	}

	// The report is still readable and ingests once the job is correlatable —
	// the recovery path the at-most-once bus makes necessary.
	jobs.jobs[jobID] = integrationJob("t-1", "repo-1", jobID, attemptID)
	if err := ingester.Backfill(context.Background()); err != nil {
		t.Fatalf("Backfill: %v", err)
	}
	if got := listFindings(t, findings, "t-1", "repo-1"); len(got) != 1 {
		t.Fatalf("backfill produced %d findings, want 1", len(got))
	}

	// Redelivery of the same event — and a second sweep — replay, never
	// duplicate.
	event := security.CIScanJobFinished{JobID: jobID, TenantID: "t-1", RepositoryID: "repo-1"}
	for range 3 {
		if err := ingester.HandleJobFinished(context.Background(), event); err != nil {
			t.Fatalf("redelivery: %v", err)
		}
	}
	if err := ingester.Backfill(context.Background()); err != nil {
		t.Fatalf("second Backfill: %v", err)
	}
	if got := listFindings(t, findings, "t-1", "repo-1"); len(got) != 1 {
		t.Fatalf("redelivery produced %d findings, want exactly 1", len(got))
	}
}

// TestCrossTenantReportReadIsCoarseNotFound is the AC1 isolation clause: a
// read naming another tenant answers the same coarse not-found as a key that
// was never written — the two are indistinguishable (SPEC-0001).
func TestCrossTenantReportReadIsCoarseNotFound(t *testing.T) {
	store, _, _, _, _ := integrationPlane(t)
	jobID, attemptID := ids.NewULID(), ids.NewULID()
	if _, err := store.Write(context.Background(), "t-a", "repo-1", jobID, attemptID, "sast", bytes.NewReader(integrationSemgrepReport())); err != nil {
		t.Fatalf("write: %v", err)
	}

	// The other tenant's read of the SAME address...
	_, foreign := store.Read(context.Background(), "t-b", "repo-1", jobID, attemptID, "sast")
	// ...and a read of a key that never existed anywhere:
	_, absent := store.Read(context.Background(), "t-a", "repo-1", ids.NewULID(), ids.NewULID(), "sast")
	if !errors.Is(foreign, ci.ErrScanReportNotFound) || !errors.Is(absent, ci.ErrScanReportNotFound) {
		t.Fatalf("cross-tenant read = %v, never-written read = %v; both must be the same coarse not-found", foreign, absent)
	}
	refs, err := store.AttemptReports(context.Background(), "t-b", "repo-1", jobID, attemptID)
	if err != nil || len(refs) != 0 {
		t.Fatalf("cross-tenant AttemptReports = %d refs, %v; want none", len(refs), err)
	}
}

// TestIngestDerivedFromAnotherTenantsJobIsRefused is the policy-isolation
// clause: an event claiming another tenant's job correlates to nothing,
// ingests nothing, and reaches no decision — the scoping the composed port
// applies is the whole of it.
func TestIngestDerivedFromAnotherTenantsJobIsRefused(t *testing.T) {
	store, ingester, findings, jobs, pdp := integrationPlane(t)
	jobID, attemptID := ids.NewULID(), ids.NewULID()
	if _, err := store.Write(context.Background(), "t-a", "repo-1", jobID, attemptID, "sast", bytes.NewReader(integrationSemgrepReport())); err != nil {
		t.Fatalf("write: %v", err)
	}
	jobs.jobs[jobID] = integrationJob("t-a", "repo-1", jobID, attemptID)
	decisionsBefore := pdp.decided

	// The event claims the job for ANOTHER tenant: the correlation refuses it
	// the same way it refuses a job that does not exist.
	err := ingester.HandleJobFinished(context.Background(), security.CIScanJobFinished{JobID: jobID, TenantID: "t-b", RepositoryID: "repo-1"})
	if err == nil {
		t.Fatal("an ingest derived from another tenant's job must be refused")
	}
	if !errors.Is(err, security.ErrCIScanJobUnknown) {
		t.Fatalf("cross-tenant correlation = %v, want ErrCIScanJobUnknown", err)
	}
	if pdp.decided != decisionsBefore {
		t.Fatalf("the cross-tenant ingest reached the PDP %d times", pdp.decided-decisionsBefore)
	}
	if got := listFindings(t, findings, "t-b", "repo-1"); len(got) != 0 {
		t.Fatalf("tenant t-b gained %d findings from another tenant's job", len(got))
	}
	if got := listFindings(t, findings, "t-a", "repo-1"); len(got) != 0 {
		t.Fatalf("tenant t-a gained %d findings from a refused correlation", len(got))
	}
}
