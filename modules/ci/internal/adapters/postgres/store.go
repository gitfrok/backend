// Package postgres persists the CI context's job history, making "what has run" a property of the
// platform rather than of a process (T-0059, SPEC-0054, ADR-0072).
//
// Third instance of ADR-0062's move, after the agent/residency stores and ADR-0071's repository
// registry. The port is unchanged; this is the adapter.
//
// It holds no job output. api.Job withholds raw output by design, PR-11 destroys the sandbox at job
// end, and ADR-0072 defers log retention to its own decision covering capture, redaction, retention,
// access and residency. There is no column for it here, and adding one is that decision.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/gitfrok/backend/modules/ci/api"
	"github.com/gitfrok/backend/modules/ci/internal/app"
	"github.com/gitfrok/backend/platform/db"
	"github.com/gitfrok/backend/platform/tenancy"
)

// Store implements the CI persistence port over one db.Pool.
type Store struct {
	pool *db.Pool
}

// New wires the store. A nil pool is a composition bug, not a runtime shape.
func New(pool *db.Pool) *Store {
	if pool == nil {
		panic("ci postgres: pool is required")
	}
	return &Store{pool: pool}
}

var (
	_ app.Store  = (*Store)(nil)
	_ app.Lister = (*Store)(nil)
)

const jobColumns = `job_id, tenant_id, attempt_id, repository_id, actor_id, ref, commit_sha,
	trigger_kind, actor_roles, state, queued_at, started_at, finished_at,
	configuration_digest, outcome_summary, delay_cause`

// CreateOrGet records a job, or returns the one an equivalent request already created.
//
// The idempotency rule is the database's, not a mutex's: UNIQUE (tenant_id, idempotency_key) is what
// makes create-or-get atomic where more than one process can enqueue, which is the invariant the
// memory adapter held under a lock.
func (s *Store) CreateOrGet(ctx context.Context, key string, candidate api.Job) (api.Job, bool, error) {
	ctx, err := scoped(ctx, candidate.TenantID)
	if err != nil {
		return api.Job{}, false, err
	}
	var existing api.Job
	created := false
	err = s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`INSERT INTO ci.jobs (`+jobColumns+`, idempotency_key)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
			 ON CONFLICT (tenant_id, idempotency_key) DO NOTHING`,
			candidate.ID, candidate.TenantID, candidate.AttemptID, candidate.RepositoryID,
			candidate.ActorID, candidate.Ref, candidate.CommitSHA, string(candidate.Trigger),
			candidate.ActorRoles, string(candidate.State), candidate.QueuedAt,
			candidate.StartedAt, candidate.FinishedAt, candidate.ConfigurationDigest,
			candidate.OutcomeSummary, candidate.DelayCause, key,
		)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 1 {
			existing, created = candidate, true
			return nil
		}
		return scanJob(tx.QueryRow(ctx,
			`SELECT `+jobColumns+` FROM ci.jobs WHERE idempotency_key = $1`, key), &existing)
	})
	if err != nil {
		return api.Job{}, false, fmt.Errorf("ci postgres: create or get %s: %w", candidate.ID, err)
	}
	return existing, created, nil
}

// Get reads one job. A job of another tenant is reported ABSENT, not forbidden — RLS makes that
// true at the database rather than by a check here that could be forgotten.
func (s *Store) Get(ctx context.Context, id string) (api.Job, error) {
	tenantID, ok := tenancy.FromContext(ctx)
	if !ok {
		return api.Job{}, errors.New("ci postgres: no tenant in context")
	}
	var job api.Job
	err := s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return scanJob(tx.QueryRow(ctx, `SELECT `+jobColumns+` FROM ci.jobs WHERE job_id = $1`, id), &job)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return api.Job{}, fmt.Errorf("ci postgres: job %s not found", id)
	}
	if err != nil {
		return api.Job{}, fmt.Errorf("ci postgres: get %s (tenant %s): %w", id, tenantID, err)
	}
	return job, nil
}

// Save advances a job that already exists. It never inserts: a Save for an unknown job is a bug
// upstream, and inserting would turn it into a silently-created record.
func (s *Store) Save(ctx context.Context, job api.Job) error {
	ctx, err := scoped(ctx, job.TenantID)
	if err != nil {
		return err
	}
	return s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`UPDATE ci.jobs SET state=$2, started_at=$3, finished_at=$4, attempt_id=$5,
			        outcome_summary=$6, delay_cause=$7, configuration_digest=$8
			  WHERE job_id=$1`,
			job.ID, string(job.State), job.StartedAt, job.FinishedAt, job.AttemptID,
			job.OutcomeSummary, job.DelayCause, job.ConfigurationDigest,
		)
		if err != nil {
			return fmt.Errorf("ci postgres: save %s: %w", job.ID, err)
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("ci postgres: job %s not found", job.ID)
		}
		return nil
	})
}

// Candidates walks the tenant's jobs newest first, after the cursor.
//
// It answers nothing about authorization: which candidates the caller may see is asked above this
// port. Another tenant's jobs are not filtered out here — the statement never sees them.
func (s *Store) Candidates(ctx context.Context, tenantID, repositoryID string, after app.ListCursor, limit int) ([]api.Job, error) {
	ctx, err := scoped(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if limit <= 0 {
		return nil, nil
	}
	// A zero cursor starts at the newest. The comparison is on the total order the index provides,
	// so a page boundary cannot repeat or skip a row that shares a queued_at with its neighbour.
	cursorAt := after.QueuedAt
	if cursorAt.IsZero() {
		cursorAt = time.Now().Add(24 * time.Hour)
	}
	var out []api.Job
	err = s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT `+jobColumns+`
			   FROM ci.jobs
			  WHERE ($1 = '' OR repository_id = $1)
			    AND (queued_at, job_id) < ($2, $3)
			  ORDER BY queued_at DESC, job_id DESC
			  LIMIT $4`,
			repositoryID, cursorAt, after.JobID, limit,
		)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var job api.Job
			if err := scanJob(rows, &job); err != nil {
				return err
			}
			out = append(out, job)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("ci postgres: candidates: %w", err)
	}
	return out, nil
}

func scanJob(r interface{ Scan(dest ...any) error }, job *api.Job) error {
	var trigger, state string
	if err := r.Scan(&job.ID, &job.TenantID, &job.AttemptID, &job.RepositoryID, &job.ActorID,
		&job.Ref, &job.CommitSHA, &trigger, &job.ActorRoles, &state, &job.QueuedAt,
		&job.StartedAt, &job.FinishedAt, &job.ConfigurationDigest, &job.OutcomeSummary,
		&job.DelayCause); err != nil {
		return err
	}
	job.Trigger, job.State = api.TriggerKind(trigger), api.JobState(state)
	return nil
}

// scoped returns ctx carrying tenantID, and REFUSES when the context already names a different one.
// See the residency and repository adapters for why RLS cannot make this refusal itself.
func scoped(ctx context.Context, tenantID string) (context.Context, error) {
	if tenantID == "" {
		return nil, errors.New("ci postgres: tenant required")
	}
	if current, ok := tenancy.FromContext(ctx); ok && string(current) != tenantID {
		return nil, fmt.Errorf("ci postgres: refusing a call for tenant %q under a context scoped to %q",
			tenantID, current)
	}
	return tenancy.WithTenant(ctx, tenancy.ID(tenantID)), nil
}
