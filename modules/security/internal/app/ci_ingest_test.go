package app_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/gitfrok/backend/modules/security/api"
	"github.com/gitfrok/backend/modules/security/internal/adapters/scanners"
	"github.com/gitfrok/backend/modules/security/internal/app"
	platformaudit "github.com/gitfrok/backend/platform/audit"
	"github.com/gitfrok/backend/platform/bus"
)

// jobULID-shaped fixtures: 26 Crockford characters, distinct values.
const (
	ciJobID     = "01M0CIJOB0000000000000000A"
	ciAttemptID = "01M0CIATTEMPT000000000000A"
	ciCommitSHA = "c0ffee1234567890abcdef1234567890abcdef12"
)

// ciJob is the job the correlation source returns: the triggering principal,
// the attempt, the revision — everything the event does NOT carry.
func ciJob(state string) app.CIScanJob {
	base := time.Date(2026, 8, 14, 9, 55, 0, 0, time.UTC)
	return app.CIScanJob{
		ID: ciJobID, AttemptID: ciAttemptID, TenantID: "t-1", RepositoryID: "repo-1",
		ActorID: "ci-runner", ActorRoles: []string{"ci"},
		CommitSHA: ciCommitSHA, State: state,
		StartedAt: base, FinishedAt: base.Add(5 * time.Minute),
	}
}

// semgrepReport is one parseable SAST report with n results.
func semgrepReport(n int) []byte {
	type result struct {
		CheckID string `json:"check_id"`
		Path    string `json:"path"`
		Extra   struct {
			Severity string `json:"severity"`
		} `json:"extra"`
	}
	results := make([]result, 0, n)
	for i := range n {
		var r result
		r.CheckID = fmt.Sprintf("rule-%d", i)
		r.Path = fmt.Sprintf("pkg/file%d.go", i)
		r.Extra.Severity = "ERROR"
		results = append(results, r)
	}
	out, err := json.Marshal(struct {
		Version string   `json:"version"`
		Results []result `json:"results"`
	}{Version: "1.99.0", Results: results})
	if err != nil {
		panic(err)
	}
	return out
}

// fakeJobSource is the composed correlation port: one job map, and
// ErrCIScanJobUnknown for anything absent.
type fakeJobSource struct {
	jobs map[string]app.CIScanJob
}

func (f *fakeJobSource) ScanJob(_ context.Context, tenantID, repositoryID, jobID string) (app.CIScanJob, error) {
	job, ok := f.jobs[jobID]
	if !ok || job.TenantID != tenantID || job.RepositoryID != repositoryID {
		return app.CIScanJob{}, app.ErrCIScanJobUnknown
	}
	return job, nil
}

// fakeReportSource serves one attempt's reports from a map keyed by
// tenant/repo/job/attempt, plus flat addresses for the backfill sweep.
type fakeReportSource struct {
	attempts map[string][]app.CIScanReport
	addrs    []app.CIScanReportAddr
}

func attemptKey(tenant, repo, job, attempt string) string {
	return tenant + "/" + repo + "/" + job + "/" + attempt
}

func (f *fakeReportSource) AttemptReports(_ context.Context, tenantID, repositoryID, jobID, attemptID string) ([]app.CIScanReport, error) {
	return f.attempts[attemptKey(tenantID, repositoryID, jobID, attemptID)], nil
}

func (f *fakeReportSource) ScanReportAddrs(_ context.Context) ([]app.CIScanReportAddr, error) {
	return f.addrs, nil
}

// ciHarness extends the shared harness with collectors for the two CI audit
// events, and wires the ingester over the same service, bus and PDP.
type ciHarness struct {
	h        *harness
	ingester *app.CIScanIngester
	jobs     *fakeJobSource
	reports  *fakeReportSource
	ingested []platformaudit.CIScanReportIngested
	rejected []platformaudit.FindingsScanReportRejected
}

func newCIHarness(allow bool) *ciHarness {
	h := newHarness(allow)
	c := &ciHarness{h: h, jobs: &fakeJobSource{jobs: map[string]app.CIScanJob{}}, reports: &fakeReportSource{attempts: map[string][]app.CIScanReport{}}}
	h.bus.Subscribe(platformaudit.EventAudit, func(_ context.Context, e bus.Event) error {
		switch a := e.(type) {
		case platformaudit.CIScanReportIngested:
			c.ingested = append(c.ingested, a)
		case platformaudit.FindingsScanReportRejected:
			c.rejected = append(c.rejected, a)
		}
		return nil
	})
	c.ingester = app.NewCIScanIngester(h.svc, c.jobs, c.reports, scanners.All(), time.Now)
	return c
}

func (c *ciHarness) seed(job app.CIScanJob, reports ...app.CIScanReport) {
	c.jobs.jobs[job.ID] = job
	c.reports.attempts[attemptKey(job.TenantID, job.RepositoryID, job.ID, job.AttemptID)] = reports
}

func (c *ciHarness) event() app.CIScanJobFinished {
	return app.CIScanJobFinished{JobID: ciJobID, TenantID: "t-1", RepositoryID: "repo-1"}
}

// TestJobFinishedIngestsUnderTheJobsOwnPrincipal covers AC2 and AC3: the
// revision and the principal come from the job the correlation port returns —
// never from the event, which carries neither — and the ingest's derived
// request ID has the reserved ci:<job>:<attempt>:<class> shape.
func TestJobFinishedIngestsUnderTheJobsOwnPrincipal(t *testing.T) {
	c := newCIHarness(true)
	c.seed(ciJob("SUCCEEDED"), app.CIScanReport{ScannerClass: "sast", Report: semgrepReport(1)})

	if err := c.ingester.HandleJobFinished(context.Background(), c.event()); err != nil {
		t.Fatalf("HandleJobFinished: %v", err)
	}
	if len(c.h.opened) != 1 || len(c.h.scans) != 1 {
		t.Fatalf("opened=%d scans=%d, want 1 and 1", len(c.h.opened), len(c.h.scans))
	}
	if c.h.scans[0].Revision != ciCommitSHA {
		t.Fatalf("ingested revision = %q, want the job's CommitSHA %q", c.h.scans[0].Revision, ciCommitSHA)
	}
	if len(c.h.pdp.requests) != 1 {
		t.Fatalf("PDP decisions = %d, want 1", len(c.h.pdp.requests))
	}
	decided := c.h.pdp.requests[0]
	if decided.Subject.ID != "ci-runner" || len(decided.Subject.Roles) != 1 || decided.Subject.Roles[0] != "ci" {
		t.Fatalf("the PDP decided for %+v, want the job's triggering principal", decided.Subject)
	}
	if decided.Context["revision"] != ciCommitSHA {
		t.Fatalf("the PDP saw revision %q, want the job's CommitSHA", decided.Context["revision"])
	}
	// The audit record carries the derived request ID in the reserved
	// namespace — the shape a wire caller is refused (AC6).
	if len(c.h.audits) != 1 {
		t.Fatalf("audits = %d, want 1", len(c.h.audits))
	}
	wantRequestID := "ci:" + ciJobID + ":" + ciAttemptID + ":sast"
	if c.h.audits[0].RequestID != wantRequestID {
		t.Fatalf("audit request ID = %q, want %q", c.h.audits[0].RequestID, wantRequestID)
	}
	if c.h.audits[0].ActorID != "ci-runner" {
		t.Fatalf("audit actor = %q, want the job's principal", c.h.audits[0].ActorID)
	}
	// AC5: the terminal state is recorded on the ingest's provenance audit.
	if len(c.ingested) != 1 {
		t.Fatalf("CIScanReportIngested audits = %d, want 1", len(c.ingested))
	}
	if c.ingested[0].TerminalState != "SUCCEEDED" || c.ingested[0].ScannerClass != "sast" {
		t.Fatalf("CIScanReportIngested = %+v, want SUCCEEDED/sast", c.ingested[0])
	}
	if c.ingested[0].JobID != ciJobID || c.ingested[0].AttemptID != ciAttemptID {
		t.Fatalf("CIScanReportIngested address = %+v", c.ingested[0])
	}
}

// TestJobFinishedWithoutReportsIsAStrictNoOp is AC4: a job that persisted no
// report changes nothing — and above all resolves nothing, which an empty
// ingest would do for that tool. The PDP is never even asked.
func TestJobFinishedWithoutReportsIsAStrictNoOp(t *testing.T) {
	c := newCIHarness(true)
	// Seed an OPEN finding that a wrongful empty ingest would resolve.
	c.seed(ciJob("SUCCEEDED"))
	if _, err := c.h.svc.IngestScanResults(context.Background(),
		singleChunk(sastScan(-time.Hour), "setup", rawFinding("py-eval", "app.py", "def handler():"))); err != nil {
		t.Fatalf("setup ingest: %v", err)
	}
	opened, resolved, scans, audits := len(c.h.opened), len(c.h.resolved), len(c.h.scans), len(c.h.audits)
	decisionsBefore := len(c.h.pdp.requests)

	if err := c.ingester.HandleJobFinished(context.Background(), c.event()); err != nil {
		t.Fatalf("HandleJobFinished: %v", err)
	}
	if len(c.h.opened) != opened || len(c.h.resolved) != resolved || len(c.h.scans) != scans || len(c.h.audits) != audits {
		t.Fatalf("a reportless job changed state: opened=%d resolved=%d scans=%d audits=%d (was %d/%d/%d/%d)",
			len(c.h.opened), len(c.h.resolved), len(c.h.scans), len(c.h.audits), opened, resolved, scans, audits)
	}
	if len(c.h.resolved) != 0 {
		t.Fatal("a reportless job resolved findings — the zero-resolutions invariant broke")
	}
	if len(c.h.pdp.requests) != decisionsBefore {
		t.Fatalf("a reportless job reached the PDP %d times", len(c.h.pdp.requests)-decisionsBefore)
	}
	if len(c.ingested) != 0 || len(c.rejected) != 0 {
		t.Fatalf("a reportless job emitted CI audits: ingested=%d rejected=%d", len(c.ingested), len(c.rejected))
	}
}

// TestFailedJobIngestsItsReportLikeAnyOther is AC5: the terminal state is
// recorded, and the report ingests regardless of it.
func TestFailedJobIngestsItsReportLikeAnyOther(t *testing.T) {
	for _, state := range []string{"FAILED", "CANCELLED"} {
		c := newCIHarness(true)
		c.seed(ciJob(state), app.CIScanReport{ScannerClass: "sast", Report: semgrepReport(1)})
		if err := c.ingester.HandleJobFinished(context.Background(), c.event()); err != nil {
			t.Fatalf("HandleJobFinished(%s): %v", state, err)
		}
		if len(c.h.opened) != 1 {
			t.Fatalf("%s job opened %d findings, want 1", state, len(c.h.opened))
		}
		if len(c.ingested) != 1 || c.ingested[0].TerminalState != state {
			t.Fatalf("%s job recorded %+v, want one audit with terminal state %s", state, c.ingested, state)
		}
	}
}

// TestUnparseableReportFailsLoudlyAndChangesNothing is AC8: the handler
// errors, the rejection is audited, and no finding changes.
func TestUnparseableReportFailsLoudlyAndChangesNothing(t *testing.T) {
	c := newCIHarness(true)
	c.seed(ciJob("SUCCEEDED"), app.CIScanReport{ScannerClass: "sast", Report: []byte("this is not json")})

	err := c.ingester.HandleJobFinished(context.Background(), c.event())
	if err == nil {
		t.Fatal("an unparseable report must fail the handler loudly")
	}
	if len(c.h.opened) != 0 || len(c.h.resolved) != 0 || len(c.h.scans) != 0 || len(c.h.audits) != 0 {
		t.Fatalf("an unparseable report changed findings: opened=%d resolved=%d scans=%d audits=%d",
			len(c.h.opened), len(c.h.resolved), len(c.h.scans), len(c.h.audits))
	}
	if len(c.rejected) != 1 || c.rejected[0].Reason != "unparseable" || c.rejected[0].ScannerClass != "sast" {
		t.Fatalf("rejection audits = %+v, want one unparseable/sast", c.rejected)
	}
	if c.rejected[0].JobID != ciJobID || c.rejected[0].ActorID != "ci-runner" {
		t.Fatalf("rejection audit address = %+v", c.rejected[0])
	}
}

// TestUnknownScannerClassIsRecordedAndSkipped: a class no adapter claims is
// audited and left on the tier for a later adapter, without failing the run.
func TestUnknownScannerClassIsRecordedAndSkipped(t *testing.T) {
	c := newCIHarness(true)
	c.seed(ciJob("SUCCEEDED"),
		app.CIScanReport{ScannerClass: "mystery", Report: []byte("{}")},
		app.CIScanReport{ScannerClass: "sast", Report: semgrepReport(1)},
	)
	if err := c.ingester.HandleJobFinished(context.Background(), c.event()); err != nil {
		t.Fatalf("HandleJobFinished: %v", err)
	}
	if len(c.h.opened) != 1 {
		t.Fatalf("the known class must still ingest: opened=%d", len(c.h.opened))
	}
	if len(c.rejected) != 1 || c.rejected[0].ScannerClass != "mystery" || c.rejected[0].Reason != "unknown_scanner_class" {
		t.Fatalf("rejection audits = %+v, want one unknown_scanner_class/mystery", c.rejected)
	}
}

// TestRedeliveryIngestsOnce is AC6: the derived request ID makes redelivery a
// replay — findings, scan events and audit records are all exactly-once.
func TestRedeliveryIngestsOnce(t *testing.T) {
	c := newCIHarness(true)
	c.seed(ciJob("SUCCEEDED"), app.CIScanReport{ScannerClass: "sast", Report: semgrepReport(2)})

	for range 3 {
		if err := c.ingester.HandleJobFinished(context.Background(), c.event()); err != nil {
			t.Fatalf("HandleJobFinished: %v", err)
		}
	}
	if len(c.h.opened) != 2 || len(c.h.scans) != 1 || len(c.h.audits) != 1 || len(c.ingested) != 1 {
		t.Fatalf("redelivery duplicated state: opened=%d scans=%d audits=%d ingested=%d",
			len(c.h.opened), len(c.h.scans), len(c.h.audits), len(c.ingested))
	}
}

// TestPDPRetrievalDenialChangesNothingAndIsRecorded: a principal the PDP
// refuses ingests nothing; the refusal is recorded on the audit trail and the
// run is terminal — a stable denial is not something to redeliver.
func TestPDPRetrievalDenialChangesNothingAndIsRecorded(t *testing.T) {
	c := newCIHarness(false)
	c.seed(ciJob("SUCCEEDED"), app.CIScanReport{ScannerClass: "sast", Report: semgrepReport(1)})

	if err := c.ingester.HandleJobFinished(context.Background(), c.event()); err != nil {
		t.Fatalf("a PDP denial is terminal, not an error: %v", err)
	}
	if len(c.h.opened) != 0 || len(c.h.scans) != 0 {
		t.Fatalf("a denied ingest changed findings: opened=%d scans=%d", len(c.h.opened), len(c.h.scans))
	}
	if len(c.rejected) != 1 || c.rejected[0].Reason != "denied" {
		t.Fatalf("rejection audits = %+v, want one denied", c.rejected)
	}
}

// TestLargeReportChunks: more findings than one chunk holds are ingested as
// consecutive chunks under one derived request ID, and only the final one
// completes the scan.
func TestLargeReportChunks(t *testing.T) {
	c := newCIHarness(true)
	c.seed(ciJob("SUCCEEDED"), app.CIScanReport{ScannerClass: "sast", Report: semgrepReport(api.MaxFindingsPerChunk + 7)})

	if err := c.ingester.HandleJobFinished(context.Background(), c.event()); err != nil {
		t.Fatalf("HandleJobFinished: %v", err)
	}
	if len(c.h.opened) != api.MaxFindingsPerChunk+7 {
		t.Fatalf("opened %d findings, want %d", len(c.h.opened), api.MaxFindingsPerChunk+7)
	}
	if len(c.h.scans) != 1 || len(c.h.audits) != 1 {
		t.Fatalf("scans=%d audits=%d, want 1 and 1", len(c.h.scans), len(c.h.audits))
	}
}

// TestBackfillIngestsReportsLackingScans: the recovery sweep re-runs the
// ingest for every stored report address — the at-most-once bus's missed
// events are caught by the idempotent core — and skips addresses whose job is
// gone rather than failing forever.
func TestBackfillIngestsReportsLackingScans(t *testing.T) {
	c := newCIHarness(true)
	job := ciJob("SUCCEEDED")
	c.jobs.jobs[job.ID] = job
	c.reports.addrs = []app.CIScanReportAddr{
		{TenantID: job.TenantID, RepositoryID: job.RepositoryID, JobID: job.ID, AttemptID: job.AttemptID},
		// A report whose job no longer exists: skipped, not fatal.
		{TenantID: "t-1", RepositoryID: "repo-1", JobID: "01M0GONE000000000000000000", AttemptID: "01M0GONEATTEMPT000000000"},
	}
	c.reports.attempts[attemptKey(job.TenantID, job.RepositoryID, job.ID, job.AttemptID)] = []app.CIScanReport{
		{ScannerClass: "sast", Report: semgrepReport(1)},
	}

	if err := c.ingester.Backfill(context.Background()); err != nil {
		t.Fatalf("Backfill: %v", err)
	}
	if len(c.h.opened) != 1 || len(c.ingested) != 1 {
		t.Fatalf("backfill ingested opened=%d ingested=%d, want 1 and 1", len(c.h.opened), len(c.ingested))
	}

	// Running the sweep again — and the live event afterwards — replays,
	// never duplicates.
	if err := c.ingester.Backfill(context.Background()); err != nil {
		t.Fatalf("second Backfill: %v", err)
	}
	if err := c.ingester.HandleJobFinished(context.Background(), c.event()); err != nil {
		t.Fatalf("HandleJobFinished after backfill: %v", err)
	}
	if len(c.h.opened) != 1 || len(c.h.scans) != 1 || len(c.h.audits) != 1 || len(c.ingested) != 1 {
		t.Fatalf("backfill+event duplicated state: opened=%d scans=%d audits=%d ingested=%d",
			len(c.h.opened), len(c.h.scans), len(c.h.audits), len(c.ingested))
	}
}

// TestBackfillWithoutReportsDoesNothing: a plane with no stored reports
// sweeps to a clean no-op.
func TestBackfillWithoutReportsDoesNothing(t *testing.T) {
	c := newCIHarness(true)
	if err := c.ingester.Backfill(context.Background()); err != nil {
		t.Fatalf("Backfill: %v", err)
	}
	if len(c.h.opened) != 0 || len(c.h.audits) != 0 || len(c.ingested) != 0 {
		t.Fatal("an empty backfill changed state")
	}
}

// TestJobFinishedForAnUnknownJobFails: an event for a job the correlation
// source does not know is an error at the handler — the backfill sweep is the
// recovery path, not a silent drop here.
func TestJobFinishedForAnUnknownJobFails(t *testing.T) {
	c := newCIHarness(true)
	err := c.ingester.HandleJobFinished(context.Background(), c.event())
	if !errors.Is(err, app.ErrCIScanJobUnknown) {
		t.Fatalf("HandleJobFinished = %v, want ErrCIScanJobUnknown", err)
	}
}
