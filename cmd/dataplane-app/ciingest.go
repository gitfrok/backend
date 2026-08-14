package main

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strconv"
	"time"

	"github.com/gitfrok/backend/modules/ci"
	ciapi "github.com/gitfrok/backend/modules/ci/api"
	"github.com/gitfrok/backend/modules/security"
	"github.com/gitfrok/backend/platform/bus"
	"github.com/gitfrok/backend/platform/ids"
)

// The CI scan report handoff (T-0029, SPEC-0037, ADR-0059 Option C): the
// runner persists its raw report, CIJobFinished drives Security's ingester,
// and the findings land under the job's own principal. The report size limit
// and retention are per-environment configuration (invariant 13) — the
// defaults below are the ones deploy/MVP-RUNBOOK.md mirrors.
const (
	// ciScanReportMaxBytesEnv bounds one scan report at WRITE time. A report
	// over the limit is refused whole, never truncated: a partial report
	// would silently become "these findings are all there were" and resolve
	// the rest (SPEC-0037 AC7).
	ciScanReportMaxBytesEnv = "GITFROK_CI_SCAN_REPORT_MAX_BYTES"
	// ciScanReportRetentionEnv is how many days a report stays on the tier
	// before the sweep deletes it. Deletion removes reports only — the
	// findings, scans and audit records derived from them outlive the source
	// (SPEC-0037 AC9).
	ciScanReportRetentionEnv = "GITFROK_CI_SCAN_REPORT_RETENTION_DAYS"
	// ciScanSweepIntervalEnv is the period of the recovery backfill and the
	// retention sweep, as a Go duration.
	ciScanSweepIntervalEnv = "GITFROK_CI_SCAN_SWEEP_INTERVAL"
)

const (
	// defaultCIScanReportMaxBytes is 16 MiB: headroom above the largest
	// plausible single-repository Semgrep or gitleaks JSON, low enough that a
	// runaway report cannot treat the object tier as unbounded.
	defaultCIScanReportMaxBytes int64 = 16 * 1024 * 1024
	// defaultCIScanReportRetention is 30 days: long enough for a report to
	// outlive any restart-window the backfill must recover, short enough to
	// keep the tier bounded (G8).
	defaultCIScanReportRetention = 30 * 24 * time.Hour
	// defaultCIScanSweepInterval is 5 minutes: the backfill catches a missed
	// CIJobFinished within one interval, and retention ages at day
	// granularity so the sweep frequency costs little precision.
	defaultCIScanSweepInterval = 5 * time.Minute
)

type ciScanReportConfig struct {
	maxBytes  int64
	retention time.Duration
	interval  time.Duration
}

// loadCIScanReportConfig resolves the report limits from the environment. A
// misconfigured value fails the rollout rather than the first scan, exactly
// like the runner configuration beside it.
func loadCIScanReportConfig(getenv func(string) string) (ciScanReportConfig, error) {
	cfg := ciScanReportConfig{
		maxBytes:  defaultCIScanReportMaxBytes,
		retention: defaultCIScanReportRetention,
		interval:  defaultCIScanSweepInterval,
	}
	if raw := getenv(ciScanReportMaxBytesEnv); raw != "" {
		limit, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || limit <= 0 {
			return cfg, fmt.Errorf("%s must be a positive byte count, got %q", ciScanReportMaxBytesEnv, raw)
		}
		cfg.maxBytes = limit
	}
	if raw := getenv(ciScanReportRetentionEnv); raw != "" {
		days, err := strconv.Atoi(raw)
		if err != nil || days <= 0 {
			return cfg, fmt.Errorf("%s must be a positive day count, got %q", ciScanReportRetentionEnv, raw)
		}
		cfg.retention = time.Duration(days) * 24 * time.Hour
	}
	if raw := getenv(ciScanSweepIntervalEnv); raw != "" {
		interval, err := time.ParseDuration(raw)
		if err != nil || interval <= 0 {
			return cfg, fmt.Errorf("%s must be a positive Go duration, got %q", ciScanSweepIntervalEnv, raw)
		}
		cfg.interval = interval
	}
	return cfg, nil
}

// ciScanJobSource adapts the CI context's in-process Jobs API onto the
// Security context's correlation port (SPEC-0037 AC2): the one route the
// ingester takes to a job, scoped to the event's tenant and repository, and
// coarse — unknown, vanished and out-of-scope are one answer. Everything the
// event does not carry (the attempt, the revision, the principal) comes from
// this read.
type ciScanJobSource struct{ jobs ciapi.Jobs }

func (s ciScanJobSource) ScanJob(ctx context.Context, tenantID, repositoryID, jobID string) (security.CIScanJob, error) {
	job, err := s.jobs.Get(ctx, ciapi.Context{
		TenantID: tenantID, RepositoryID: repositoryID,
		// The correlation is plane machinery, not a caller action: CI's Get
		// admits on shape and tenant match, and the ingest that follows is
		// the one that carries the job's OWN principal to the PDP (AC3).
		ActorID:   "dataplane-ci-scan-ingest",
		RequestID: ids.NewULID(),
	}, jobID)
	if err != nil {
		return security.CIScanJob{}, security.ErrCIScanJobUnknown
	}
	// CI's Get scopes by tenant alone; the correlation must also match the
	// repository the event names.
	if job.RepositoryID != repositoryID {
		return security.CIScanJob{}, security.ErrCIScanJobUnknown
	}
	out := security.CIScanJob{
		ID: job.ID, AttemptID: job.AttemptID, TenantID: job.TenantID, RepositoryID: job.RepositoryID,
		ActorID: job.ActorID, ActorRoles: slices.Clone(job.ActorRoles),
		CommitSHA: job.CommitSHA, State: string(job.State),
	}
	if job.StartedAt != nil {
		out.StartedAt = *job.StartedAt
	}
	if job.FinishedAt != nil {
		out.FinishedAt = *job.FinishedAt
	}
	return out, nil
}

// ciScanReportSource adapts the CI context's report store onto the Security
// context's report port: refs become report bytes, and the backfill
// enumeration dedups to attempt addresses.
type ciScanReportSource struct{ store *ci.ScanReportStore }

func (s ciScanReportSource) AttemptReports(ctx context.Context, tenantID, repositoryID, jobID, attemptID string) ([]security.CIScanReport, error) {
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

func (s ciScanReportSource) ScanReportAddrs(ctx context.Context) ([]security.CIScanReportAddr, error) {
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

// wireCIScanIngest joins CI to the findings plane (T-0029): one report store
// on the plane's object tier — the in-process tier when this plane has none —
// Security's ingester over it, the CIJobFinished subscription, and the sweep
// loop that recovers missed events and retires aged reports. It fails the
// rollout rather than starting a plane whose ingest path cannot compose.
func wireCIScanIngest(ctx context.Context, dp *dataplane, objects objectTier, cfg ciScanReportConfig) error {
	var tier ci.ScanReportTier = ci.NewMemoryReportTier()
	if objects != nil {
		converted, ok := objects.(ci.ScanReportTier)
		if !ok {
			return fmt.Errorf("the object tier cannot hold scan reports")
		}
		tier = converted
	}
	store, err := ci.NewScanReportStore(tier, cfg.maxBytes, time.Now)
	if err != nil {
		return fmt.Errorf("composing the scan report store: %w", err)
	}
	ingester, err := security.NewCIScanIngester(dp.findings, ciScanJobSource{jobs: dp.ci.Jobs()}, ciScanReportSource{store: store}, time.Now)
	if err != nil {
		return fmt.Errorf("composing the CI scan ingester: %w", err)
	}

	// The live subscriber. It runs the ingest OFF the publish path — a slow or
	// failing ingest may delay findings, never the dispatcher that publishes
	// CIJobFinished (SPEC-0037 non-functional) — and what it drops or fails,
	// the periodic backfill below recovers: the reports are durable and the
	// ingest is idempotent (AC6).
	bus.SubscribeTyped(dp.bus, func(ctx context.Context, e ciapi.CIJobFinished) error {
		go func() {
			if err := ingester.HandleJobFinished(context.WithoutCancel(ctx), security.CIScanJobFinished{
				JobID: e.JobID, TenantID: e.TenantID, RepositoryID: e.RepositoryID,
			}); err != nil {
				fmt.Fprintf(os.Stderr, "dataplane CI scan ingest (job %s): %v\n", e.JobID, err)
			}
		}()
		return nil
	})

	go runCIScanSweeps(ctx, ingester, store, cfg)
	return nil
}

// runCIScanSweeps is the recovery and retention loop. The in-process bus is
// at-most-once across a restart, so the backfill is the path that turns "the
// event was missed" from a loss into a delay: it re-runs the idempotent
// ingest over every stored report — replays replay, missed events land, and
// reports whose job is gone stay on the tier for an operator to notice. The
// retention sweep deletes aged reports only (AC9). One backfill runs at
// startup, covering every restart window at once.
func runCIScanSweeps(ctx context.Context, ingester *security.CIScanIngester, store *ci.ScanReportStore, cfg ciScanReportConfig) {
	sweep := func() {
		if err := ingester.Backfill(ctx); err != nil && ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "dataplane CI scan backfill: %v\n", err)
		}
		deleted, err := store.Sweep(ctx, cfg.retention)
		if err != nil && ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "dataplane CI scan report retention: %v\n", err)
		}
		if deleted > 0 {
			fmt.Printf("dataplane: retired %d CI scan report object(s) past retention\n", deleted)
		}
	}
	sweep()
	ticker := time.NewTicker(cfg.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sweep()
		}
	}
}
