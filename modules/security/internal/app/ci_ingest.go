package app

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/gitfrok/backend/modules/security/api"
	"github.com/gitfrok/backend/modules/security/internal/adapters/scanners"
	platformaudit "github.com/gitfrok/backend/platform/audit"
)

// ErrCIScanJobUnknown is reported by the correlation port when the job an
// ingest would run as does not exist (or is not readable under the given
// tenant and repository). The recovery sweep skips such reports; the live
// handler reports them.
var ErrCIScanJobUnknown = errors.New("security: no such CI job")

// CIScanJob is the subset of a CI job the ingest correlation needs. It is
// defined HERE — not imported from the CI context — so this package has no
// dependency on CI internals: the composition root adapts its job type onto
// this shape (the boundary gates enforce the separation).
//
// Everything the CIJobFinished event does not carry — the attempt, the
// revision, the triggering principal — arrives through this type, fetched by
// the port's implementation from the CI context's own Jobs API (SPEC-0037
// AC2, AC3).
type CIScanJob struct {
	ID           string
	AttemptID    string
	TenantID     string
	RepositoryID string
	// ActorID and ActorRoles are the job's triggering principal: the ingest
	// runs as them and the PDP decides for them. The report itself asserts
	// no identity (SPEC-0037 AC3).
	ActorID    string
	ActorRoles []string
	// CommitSHA is the revision the scan ran against. It is the ONLY
	// revision the ingest may record — never one from the event (which has
	// none) or from the report (which is caller-supplied bytes).
	CommitSHA string
	// State is the job's terminal state, recorded on the ingest's
	// provenance audit so a FAILED or CANCELLED job's report is auditable
	// as ingested like any other (SPEC-0037 AC5).
	State string
	// StartedAt and FinishedAt bound the scan run for the scan descriptor.
	StartedAt  time.Time
	FinishedAt time.Time
}

// CIScanJobSource correlates a finished-job event onto the job itself.
type CIScanJobSource interface {
	// ScanJob returns the job, scoped: an implementation must refuse a job
	// that does not belong to the given tenant and repository.
	ScanJob(ctx context.Context, tenantID, repositoryID, jobID string) (CIScanJob, error)
}

// CIScanReport is one persisted scan report for one scanner class.
type CIScanReport struct {
	ScannerClass string
	Report       []byte
}

// CIScanReportAddr addresses one attempt's reports for the recovery sweep.
type CIScanReportAddr struct {
	TenantID     string
	RepositoryID string
	JobID        string
	AttemptID    string
}

// CIScanReportSource reads the reports the CI context persisted.
type CIScanReportSource interface {
	// AttemptReports returns the reports one attempt stored, one per
	// scanner class. An attempt with none is an empty slice, not an error:
	// that is the state the ingester treats as a strict no-op (SPEC-0037
	// AC4).
	AttemptReports(ctx context.Context, tenantID, repositoryID, jobID, attemptID string) ([]CIScanReport, error)
	// ScanReportAddrs enumerates every attempt that has reports, for the
	// recovery sweep.
	ScanReportAddrs(ctx context.Context) ([]CIScanReportAddr, error)
}

// CIScanJobFinished is what the CI event reduces to for this subscriber: the
// job to correlate and the scoping to correlate it under. Everything else —
// the attempt, the revision, the principal, the terminal state — comes from
// the job itself (SPEC-0037 AC2), which is also why the cancel path's
// attempt-less event is handled identically.
type CIScanJobFinished struct {
	JobID        string
	TenantID     string
	RepositoryID string
}

// CIScanIngester is the Security-side subscriber core: it turns finished CI
// jobs into findings ingests under the job's own principal (SPEC-0037,
// ADR-0059 Option C). It is deliberately synchronous — the composition root
// decides how to keep the bus non-blocking — and every path is idempotent,
// keyed by the derived request ID ci:<job>:<attempt>:<class> (AC6), so the
// live handler and the recovery sweep may race without duplicating state.
type CIScanIngester struct {
	svc     *Service
	jobs    CIScanJobSource
	reports CIScanReportSource
	// byClass maps the report store's lowercase scanner class onto the
	// adapter that parses it.
	byClass map[string]scanners.Scanner
	now     func() time.Time
}

// NewCIScanIngester wires the ingester over the ingest service's trusted
// core, the two composed ports, and the scanner adapter registry.
func NewCIScanIngester(svc *Service, jobs CIScanJobSource, reports CIScanReportSource, registry []scanners.Scanner, now func() time.Time) *CIScanIngester {
	byClass := make(map[string]scanners.Scanner, len(registry))
	for _, scanner := range registry {
		byClass[strings.ToLower(string(scanner.Class()))] = scanner
	}
	if now == nil {
		now = time.Now
	}
	return &CIScanIngester{svc: svc, jobs: jobs, reports: reports, byClass: byClass, now: now}
}

// HandleJobFinished ingests the reports one finished job persisted. An event
// for an unknown job is an error: the recovery sweep is the path that learns
// to live with vanished jobs, not the live handler.
func (i *CIScanIngester) HandleJobFinished(ctx context.Context, event CIScanJobFinished) error {
	job, err := i.jobs.ScanJob(ctx, event.TenantID, event.RepositoryID, event.JobID)
	if err != nil {
		return fmt.Errorf("security: correlating CI job %s: %w", event.JobID, err)
	}
	return i.ingestAttempt(ctx, job)
}

// Backfill is the recovery sweep: the in-process bus is at-most-once across a
// restart, so every stored report gets a pass through the idempotent ingest
// core — reports already ingested replay, reports whose event was missed
// land, and reports whose job is gone are skipped for an operator to notice
// via the trail. Errors join rather than abort, so one bad attempt cannot
// starve the rest.
func (i *CIScanIngester) Backfill(ctx context.Context) error {
	addrs, err := i.reports.ScanReportAddrs(ctx)
	if err != nil {
		return fmt.Errorf("security: listing CI scan report addresses: %w", err)
	}
	seen := map[CIScanReportAddr]bool{}
	var errs []error
	for _, addr := range addrs {
		if seen[addr] {
			continue
		}
		seen[addr] = true
		job, err := i.jobs.ScanJob(ctx, addr.TenantID, addr.RepositoryID, addr.JobID)
		if errors.Is(err, ErrCIScanJobUnknown) {
			// A report outlived its job: nothing to correlate against, and
			// retrying every sweep changes nothing. Leave it on the tier.
			continue
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("security: correlating CI job %s: %w", addr.JobID, err))
			continue
		}
		if err := i.ingestAttempt(ctx, job); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// ingestAttempt ingests every report one attempt stored. NO reports is the
// strict no-op (SPEC-0037 AC4): an empty ingest would resolve every open
// finding for the tool, so the absence of a report must never reach the
// ingest core — and it never does.
func (i *CIScanIngester) ingestAttempt(ctx context.Context, job CIScanJob) error {
	reports, err := i.reports.AttemptReports(ctx, job.TenantID, job.RepositoryID, job.ID, job.AttemptID)
	if err != nil {
		return fmt.Errorf("security: listing scan reports for attempt %s: %w", job.AttemptID, err)
	}
	if len(reports) == 0 {
		return nil
	}
	// Deterministic class order: redelivery and the sweep must process
	// reports in the same sequence.
	slices.SortFunc(reports, func(a, b CIScanReport) int { return strings.Compare(a.ScannerClass, b.ScannerClass) })
	for _, report := range reports {
		if err := i.ingestReport(ctx, job, report); err != nil {
			return err
		}
	}
	return nil
}

// ingestReport parses one report with its class's adapter and hands the
// findings to the trusted ingest core in bounded chunks, all under the
// derived request ID ci:<job>:<attempt>:<class> (SPEC-0037 AC6).
func (i *CIScanIngester) ingestReport(ctx context.Context, job CIScanJob, report CIScanReport) error {
	scanner, ok := i.byClass[report.ScannerClass]
	if !ok {
		// No adapter claims this class today. Record it and leave the
		// report on the tier — a later adapter's sweep can still take it.
		return i.reject(ctx, job, report.ScannerClass, platformaudit.ScanReportRejectedUnknownScannerClass)
	}
	findings, err := scanner.Parse(report.Report)
	if err != nil {
		// AC8: fail loudly — the rejection is audited, no finding
		// changes, and the error propagates so the failure is visible.
		if rejectErr := i.reject(ctx, job, report.ScannerClass, platformaudit.ScanReportRejectedUnparseable); rejectErr != nil {
			return rejectErr
		}
		return fmt.Errorf("security: parsing the %s report for attempt %s: %w", report.ScannerClass, job.AttemptID, err)
	}

	// AC6: the derived request ID. It lives in the reserved namespace the
	// wire boundary refuses, and only this in-process path may mint it.
	requestID := "ci:" + job.ID + ":" + job.AttemptID + ":" + report.ScannerClass

	started, ended := job.StartedAt, job.FinishedAt
	if started.IsZero() {
		started = i.now()
	}
	if ended.IsZero() || ended.Before(started) {
		ended = started
	}
	scan := api.Scan{
		ScannerClass: scanner.Class(),
		ToolName:     scanner.ToolName(),
		ToolVersion:  scanner.ToolVersion(report.Report),
		StartedAt:    started,
		EndedAt:      ended,
	}

	for chunkIndex := 0; ; chunkIndex++ {
		lo := chunkIndex * api.MaxFindingsPerChunk
		if lo >= len(findings) && chunkIndex > 0 {
			break
		}
		hi := min(lo+api.MaxFindingsPerChunk, len(findings))
		chunk := api.IngestChunk{
			Context: api.Context{
				TenantID:     job.TenantID,
				RepositoryID: job.RepositoryID,
				ActorID:      job.ActorID,
				ActorRoles:   slices.Clone(job.ActorRoles),
				RequestID:    requestID,
			},
			// AC2: the revision is the job's CommitSHA, fetched through
			// the correlation port — never the event's (it has none) and
			// never the report's (it is caller-supplied bytes).
			Revision:   job.CommitSHA,
			Scan:       scan,
			Findings:   findings[lo:hi],
			ChunkIndex: chunkIndex,
			FinalChunk: hi >= len(findings),
		}
		result, err := i.svc.ingestScanResults(ctx, chunk)
		if errors.Is(err, api.ErrDenied) {
			// AC3: the PDP refused the job's principal. Record it and
			// stop — a stable denial gains nothing from redelivery.
			return i.reject(ctx, job, report.ScannerClass, platformaudit.ScanReportRejectedDenied)
		}
		if err != nil {
			return fmt.Errorf("security: ingesting the %s report for attempt %s: %w", report.ScannerClass, job.AttemptID, err)
		}
		if result.Completed && !result.Replayed {
			// AC5: the provenance record — including the terminal state —
			// lands exactly once, on the completing (non-replayed) pass.
			if err := i.svc.bus.Publish(ctx, platformaudit.CIScanReportIngested{
				TenantID: job.TenantID, ActorID: job.ActorID, RepositoryID: job.RepositoryID,
				JobID: job.ID, AttemptID: job.AttemptID,
				ScannerClass: report.ScannerClass, TerminalState: job.State,
				ScanID: result.ScanID, FindingsRecorded: result.FindingsRecorded,
				OccurredAt: i.now().UTC(),
			}); err != nil {
				return fmt.Errorf("security: publishing the CI ingest audit: %w", err)
			}
		}
		if chunk.FinalChunk {
			break
		}
	}
	return nil
}

// reject records one report's refusal on the audit trail. The record is the
// whole of it: no finding changes, and the reason is a fixed vocabulary.
func (i *CIScanIngester) reject(ctx context.Context, job CIScanJob, scannerClass, reason string) error {
	if err := i.svc.bus.Publish(ctx, platformaudit.FindingsScanReportRejected{
		TenantID: job.TenantID, ActorID: job.ActorID, RepositoryID: job.RepositoryID,
		JobID: job.ID, AttemptID: job.AttemptID,
		ScannerClass: scannerClass, Reason: reason,
		OccurredAt: i.now().UTC(),
	}); err != nil {
		return fmt.Errorf("security: publishing the scan report rejection: %w", err)
	}
	return nil
}
