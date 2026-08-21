// Package postgres persists the Code Review context — merge requests, the reviews submitted against
// them, branch-protection rules, the ref revisions this context was told about, and the record of
// which requests were already applied (T-0078, SPEC-0061, ADR-0080).
//
// The context has never had one. `cmd/dataplane-app` built it on the in-memory store, whose own
// comment promised that "production injects a tenant-scoped database store" — an adapter that did not
// exist. What emptied on every restart was not a cache: it was who approved what, at which revision,
// against which rule.
//
// SCOPING IS THIS ADAPTER'S ONE INTERESTING DECISION (ADR-0080 decision 1). The port does not carry a
// tenant consistently: four of its methods carry none at all. So the scope comes from whichever source
// has it — an argument, a field of the aggregate being written, or the request context — and a context
// naming a DIFFERENT tenant than the call is refused before any statement runs. RLS cannot make that
// refusal: it protects one tenant's rows from a transaction scoped to another, and has nothing to say
// about a transaction scoped to the tenant the caller asked about. That is the same posture
// SPEC-0042 AC5 requires of the residency adapter and SPEC-0052 of the repository one.
//
// Where the port carries no tenant, `db.Pool.InTx` requires one from the context and refuses without
// it, so an unscoped read cannot reach Postgres even to be denied there.
package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/gitfrok/backend/modules/codereview/api"
	"github.com/gitfrok/backend/modules/codereview/internal/app"
	"github.com/gitfrok/backend/platform/db"
	"github.com/gitfrok/backend/platform/tenancy"
)

// Store implements the Code Review persistence port — app.Store — over one db.Pool.
type Store struct {
	pool *db.Pool
}

// New wires the store. A nil pool is a composition bug, not a runtime shape.
func New(pool *db.Pool) *Store {
	if pool == nil {
		panic("codereview postgres: pool is required")
	}
	return &Store{pool: pool}
}

// Compile-time proof that the durable adapter fills the same port the in-memory store does
// (ADR-0080 decision 4, following ADR-0071).
var _ app.Store = (*Store)(nil)

// ErrVersionConflict reports a write that lost the race for a version.
//
// It is the adapter's half of ADR-0080 decision 3: `Save` guards on the version in the UPDATE itself,
// so two writers who read the same version cannot both win. It wraps api.ErrVersionConflict so the
// service's errors.Is mapping (ADR-0084 decision 2) sees it across the layer boundary — the guard
// moved, the wire did not.
var ErrVersionConflict = fmt.Errorf("codereview postgres: the merge request changed under this write: %w",
	api.ErrVersionConflict)

// scoped returns ctx carrying tenantID — and REFUSES when the context already names a different one.
//
// The refusal is here because RLS cannot make it: the adapter scopes the transaction from its own
// argument, so `SET LOCAL app.tenant_id` names the tenant that was asked for and the policy then
// admits exactly the rows that call requested. A mismatch between the verified context and the
// argument is precisely what a caller must never be able to express.
func scoped(ctx context.Context, tenantID string) (context.Context, error) {
	if tenantID == "" {
		return nil, errors.New("codereview postgres: tenant required")
	}
	if current, ok := tenancy.FromContext(ctx); ok && string(current) != tenantID {
		return nil, fmt.Errorf("codereview postgres: refusing a call for tenant %q under a context scoped to %q",
			tenantID, current)
	}
	return tenancy.WithTenant(ctx, tenancy.ID(tenantID)), nil
}

// tenantOf reads the tenant for a port method that carries none.
//
// `Get`, `PutReview`, `Reviews` and `Seen` are reachable only from request paths, where the gRPC door
// has already called tenancy.WithTenant. That pairing is asserted by a test rather than trusted
// (SPEC-0061 AC7) — ADR-0080 records it as the thing it is most likely to be wrong about, and a
// refactor that breaks it should fail a test rather than a tenant.
func tenantOf(ctx context.Context) (string, error) {
	current, ok := tenancy.FromContext(ctx)
	if !ok || current == "" {
		return "", errors.New("codereview postgres: this call carries no tenant and the context names none")
	}
	return string(current), nil
}

// --- merge requests -----------------------------------------------------------------------------

// CreateOrGet records a merge request under an idempotency key, or returns the one already recorded.
//
// Both halves happen in ONE transaction: the key and the merge request are the same fact — this
// request was applied, and this is what it produced — so a crash between them would leave a key
// pointing at nothing, and the retry that follows would create a second merge request for a request
// the caller believes was applied once.
//
// The idempotency row is claimed with ON CONFLICT DO NOTHING and read back (ADR-0084 decision 4):
// two concurrent same-key calls both miss any lookup, but only one wins the insert, and the loser
// reads back the winner's merge request exactly as the mutex-serialised memory store returned it —
// instead of surfacing a unique violation where the memory store returned a record.
func (s *Store) CreateOrGet(ctx context.Context, key string, candidate api.MergeRequest) (api.MergeRequest, bool, error) {
	ctx, err := scoped(ctx, candidate.TenantID)
	if err != nil {
		return api.MergeRequest{}, false, err
	}
	var (
		out     api.MergeRequest
		created bool
	)
	err = s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`INSERT INTO codereview.applied_requests (tenant_id, kind, key, subject_id)
			 VALUES ($1, 'idempotency', $2, $3)
			 ON CONFLICT (tenant_id, kind, key) DO NOTHING`,
			candidate.TenantID, key, candidate.ID,
		)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			var existing string
			err := tx.QueryRow(ctx,
				`SELECT subject_id FROM codereview.applied_requests
				  WHERE kind = 'idempotency' AND key = $1`, key,
			).Scan(&existing)
			if err != nil {
				return err
			}
			out, err = loadMergeRequest(ctx, tx, existing)
			return err
		}
		if err := insertMergeRequest(ctx, tx, candidate); err != nil {
			return err
		}
		out, created = candidate, true
		return nil
	})
	if err != nil {
		return api.MergeRequest{}, false, fmt.Errorf("codereview postgres: create-or-get %s: %w", key, err)
	}
	return out, created, nil
}

// Get loads one merge request. The tenant comes from the context — see tenantOf.
//
// A merge request in another tenant is ABSENT, not forbidden: RLS makes the row invisible to the
// statement, so this returns the same not-found a caller gets for an ID nobody ever created
// (SPEC-0001).
func (s *Store) Get(ctx context.Context, id string) (api.MergeRequest, error) {
	if _, err := tenantOf(ctx); err != nil {
		return api.MergeRequest{}, err
	}
	var out api.MergeRequest
	err := s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		out, err = loadMergeRequest(ctx, tx, id)
		return err
	})
	if err != nil {
		return api.MergeRequest{}, err
	}
	return out, nil
}

// Save persists a merge request whose Version the service has already incremented, and serves those
// bumped writers only (ADR-0084 decision 1) — the event path's version-preserving write is
// SaveProjection.
//
// ADR-0080 decision 3: the guard is the UPDATE's own WHERE clause. The service reads a merge request
// at version N, hands back N+1, and this writes only if the stored row is still at N. A zero-row
// update is a conflict, not a success — the memory store could not lose that race because it is one
// process, and a plane with replicas can.
func (s *Store) Save(ctx context.Context, mr api.MergeRequest) error {
	ctx, err := scoped(ctx, mr.TenantID)
	if err != nil {
		return err
	}
	references, err := json.Marshal(externalIssuesOf(mr))
	if err != nil {
		return fmt.Errorf("codereview postgres: encoding references for %s: %w", mr.ID, err)
	}
	return s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`UPDATE codereview.merge_requests
			    SET source_ref = $3, target_ref = $4, title = $5, description = $6,
			        state = $7, head_revision = $8, target_revision = $9,
			        updated_at = $10, version = $11, external_issues = $12
			  WHERE merge_request_id = $1 AND version = $2`,
			mr.ID, mr.Version-1,
			mr.SourceRef, mr.TargetRef, mr.Title, mr.Description,
			string(mr.State), mr.HeadRevision, mr.TargetRevision,
			mr.UpdatedAt, mr.Version, references,
		)
		if err != nil {
			return fmt.Errorf("codereview postgres: saving %s: %w", mr.ID, err)
		}
		if tag.RowsAffected() == 0 {
			// Either the row moved under this write, or it is not there at all. Both are
			// refusals to the caller, and distinguishing them here would mean a second query
			// whose answer nothing acts on differently.
			return ErrVersionConflict
		}
		return nil
	})
}

// SaveProjection is the event path's version-preserving write (ADR-0084 decision 1, SPEC-0061 AC10).
//
// It writes the projected fields — head and target revision — where the stored row is at the version
// the event path read, and advances nothing: a ref moving under a merge request is not a caller edit,
// and bumping the version here would invalidate a review the author is mid-way through submitting.
// The guard exists anyway, because the row CAN move under this write — a caller edit landing between
// the read and the projection — and the honest response to that is not the conflict a bumped writer
// gets but a re-read and re-apply: the projection is a fact about the ref, and the fact still holds.
func (s *Store) SaveProjection(ctx context.Context, mr api.MergeRequest) error {
	ctx, err := scoped(ctx, mr.TenantID)
	if err != nil {
		return err
	}
	return s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		current := mr
		for range 8 {
			tag, err := tx.Exec(ctx,
				`UPDATE codereview.merge_requests
				    SET head_revision = $3, target_revision = $4
				  WHERE merge_request_id = $1 AND version = $2`,
				current.ID, current.Version, current.HeadRevision, current.TargetRevision,
			)
			if err != nil {
				return fmt.Errorf("codereview postgres: projecting %s: %w", current.ID, err)
			}
			if tag.RowsAffected() == 1 {
				return nil
			}
			// The row moved, or is not there. A re-read tells which: a missing row
			// surfaces loadMergeRequest's not-found, a moved one gets the projected
			// fields re-applied at the version it is at now.
			reloaded, err := loadMergeRequest(ctx, tx, current.ID)
			if err != nil {
				return err
			}
			reloaded.HeadRevision, reloaded.TargetRevision = current.HeadRevision, current.TargetRevision
			current = reloaded
		}
		return fmt.Errorf("codereview postgres: projecting %s: the row kept moving under the write", current.ID)
	})
}

// OpenForTarget returns the open merge requests in one tenant and repository whose target ref matches.
func (s *Store) OpenForTarget(ctx context.Context, tenantID, repositoryID, targetRef string) ([]api.MergeRequest, error) {
	return s.openFor(ctx, tenantID, repositoryID, "target_ref", targetRef)
}

// OpenForSource returns the open merge requests in one tenant and repository whose source ref matches.
func (s *Store) OpenForSource(ctx context.Context, tenantID, repositoryID, sourceRef string) ([]api.MergeRequest, error) {
	return s.openFor(ctx, tenantID, repositoryID, "source_ref", sourceRef)
}

// openFor is the shared body of the two open-merge-request lookups.
//
// The column is chosen from a two-value switch rather than interpolated from the caller's string:
// the two callers are in this file, and a column name assembled from an argument is the shape that
// becomes an injection the first time a caller is not.
func (s *Store) openFor(ctx context.Context, tenantID, repositoryID, column, ref string) ([]api.MergeRequest, error) {
	ctx, err := scoped(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	var query string
	switch column {
	case "target_ref":
		query = openByTargetQuery
	case "source_ref":
		query = openBySourceQuery
	default:
		return nil, fmt.Errorf("codereview postgres: %q is not a ref column", column)
	}

	var out []api.MergeRequest
	err = s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, query, repositoryID, ref)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			mr, err := scanMergeRequest(rows)
			if err != nil {
				return err
			}
			out = append(out, mr)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("codereview postgres: open merge requests for %s %q: %w", column, ref, err)
	}
	return out, nil
}

// --- reviews ------------------------------------------------------------------------------------

// PutReview replaces the submitting actor's current review.
//
// An upsert, because that is what the port means: one current position per actor. Whether the
// superseded ones should be kept is a different decision about what a review is, and ADR-0080 records
// it as a follow-up rather than answering it with a schema.
func (s *Store) PutReview(ctx context.Context, mergeRequestID string, review app.Review) error {
	tenantID, err := tenantOf(ctx)
	if err != nil {
		return err
	}
	return s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO codereview.reviews
			      (tenant_id, merge_request_id, actor_id, disposition, head_revision, submitted_at)
			 VALUES ($1, $2, $3, $4, $5, $6)
			 ON CONFLICT (tenant_id, merge_request_id, actor_id) DO UPDATE SET
			      disposition = EXCLUDED.disposition,
			      head_revision = EXCLUDED.head_revision,
			      submitted_at = EXCLUDED.submitted_at`,
			tenantID, mergeRequestID, review.ActorID,
			string(review.Disposition), review.HeadRevision, review.SubmittedAt,
		)
		if err != nil {
			return fmt.Errorf("codereview postgres: putting review by %s: %w", review.ActorID, err)
		}
		return nil
	})
}

// Reviews returns the current review per actor, oldest submission first.
//
// The order is stable and by submission rather than by actor, because it is what a reader of the
// merge request sees and an unordered read would shuffle the page between requests.
func (s *Store) Reviews(ctx context.Context, mergeRequestID string) ([]app.Review, error) {
	if _, err := tenantOf(ctx); err != nil {
		return nil, err
	}
	var out []app.Review
	err := s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT actor_id, disposition, head_revision, submitted_at
			   FROM codereview.reviews
			  WHERE merge_request_id = $1
			  ORDER BY submitted_at ASC, actor_id ASC`, mergeRequestID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var review app.Review
			var disposition string
			if err := rows.Scan(&review.ActorID, &disposition, &review.HeadRevision, &review.SubmittedAt); err != nil {
				return err
			}
			review.Disposition = api.Disposition(disposition)
			review.SubmittedAt = review.SubmittedAt.UTC()
			out = append(out, review)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("codereview postgres: reviews for %s: %w", mergeRequestID, err)
	}
	return out, nil
}

// --- branch protection --------------------------------------------------------------------------

// Protection returns the exact-ref rule, and false when the ref is not protected.
//
// Not-protected is an answer, not an error: most refs are not, and a caller that had to distinguish
// "unprotected" from "the lookup failed" by inspecting an error would eventually stop.
func (s *Store) Protection(ctx context.Context, tenantID, repositoryID, targetRef string) (api.BranchProtection, bool, error) {
	ctx, err := scoped(ctx, tenantID)
	if err != nil {
		return api.BranchProtection{}, false, err
	}
	var (
		out   api.BranchProtection
		found bool
	)
	err = s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var required int32
		var version int64
		err := tx.QueryRow(ctx,
			`SELECT required_approvals, version FROM codereview.branch_protections
			  WHERE repository_id = $1 AND target_ref = $2`, repositoryID, targetRef,
		).Scan(&required, &version)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		out = api.BranchProtection{
			TenantID: tenantID, RepositoryID: repositoryID, TargetRef: targetRef,
			RequiredApprovals: required, Version: version,
		}
		found = true
		return nil
	})
	if err != nil {
		return api.BranchProtection{}, false, fmt.Errorf("codereview postgres: protection for %s: %w", targetRef, err)
	}
	return out, found, nil
}

// SaveProtection replaces the exact-ref rule.
func (s *Store) SaveProtection(ctx context.Context, protection api.BranchProtection) error {
	ctx, err := scoped(ctx, protection.TenantID)
	if err != nil {
		return err
	}
	return s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO codereview.branch_protections
			      (tenant_id, repository_id, target_ref, required_approvals, version)
			 VALUES ($1, $2, $3, $4, $5)
			 ON CONFLICT (tenant_id, repository_id, target_ref) DO UPDATE SET
			      required_approvals = EXCLUDED.required_approvals,
			      version = EXCLUDED.version`,
			protection.TenantID, protection.RepositoryID, protection.TargetRef,
			protection.RequiredApprovals, protection.Version,
		)
		if err != nil {
			return fmt.Errorf("codereview postgres: saving protection for %s: %w", protection.TargetRef, err)
		}
		return nil
	})
}

// --- ref revisions ------------------------------------------------------------------------------

// SaveRefRevision records where Repository/Git last announced a ref to be.
func (s *Store) SaveRefRevision(ctx context.Context, tenantID, repositoryID, ref, revision string) error {
	ctx, err := scoped(ctx, tenantID)
	if err != nil {
		return err
	}
	return s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO codereview.ref_revisions (tenant_id, repository_id, ref, revision)
			 VALUES ($1, $2, $3, $4)
			 ON CONFLICT (tenant_id, repository_id, ref) DO UPDATE SET revision = EXCLUDED.revision`,
			tenantID, repositoryID, ref, revision,
		)
		if err != nil {
			return fmt.Errorf("codereview postgres: saving ref revision %s: %w", ref, err)
		}
		return nil
	})
}

// RefRevision returns the last announced revision, empty when this context has never been told.
func (s *Store) RefRevision(ctx context.Context, tenantID, repositoryID, ref string) (string, error) {
	ctx, err := scoped(ctx, tenantID)
	if err != nil {
		return "", err
	}
	var revision string
	err = s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		err := tx.QueryRow(ctx,
			`SELECT revision FROM codereview.ref_revisions
			  WHERE repository_id = $1 AND ref = $2`, repositoryID, ref,
		).Scan(&revision)
		if errors.Is(err, pgx.ErrNoRows) {
			// Never announced is an empty answer, exactly as the port documents. The memory
			// store returns the zero value from a map miss and says the same thing.
			revision = ""
			return nil
		}
		return err
	})
	if err != nil {
		return "", fmt.Errorf("codereview postgres: ref revision %s: %w", ref, err)
	}
	return revision, nil
}

// --- applied requests ---------------------------------------------------------------------------

// Seen reports whether a request ID was already applied, recording it if not.
//
// The insert IS the test: `ON CONFLICT DO NOTHING` returns no row when the key was already there, so
// two concurrent replays of the same request cannot both be told they are the first. A read-then-write
// would have that race, and the race is the whole thing this method exists to prevent.
func (s *Store) Seen(ctx context.Context, requestID string) (bool, error) {
	tenantID, err := tenantOf(ctx)
	if err != nil {
		return false, err
	}
	var seen bool
	err = s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var inserted string
		err := tx.QueryRow(ctx,
			`INSERT INTO codereview.applied_requests (tenant_id, kind, key)
			 VALUES ($1, 'seen', $2)
			 ON CONFLICT (tenant_id, kind, key) DO NOTHING
			 RETURNING key`, tenantID, requestID,
		).Scan(&inserted)
		if errors.Is(err, pgx.ErrNoRows) {
			seen = true
			return nil
		}
		return err
	})
	if err != nil {
		return false, fmt.Errorf("codereview postgres: seen %s: %w", requestID, err)
	}
	return seen, nil
}

// --- row plumbing -------------------------------------------------------------------------------

const mergeRequestColumns = `tenant_id, merge_request_id, repository_id, source_ref, target_ref,
	title, description, creator_id, state, head_revision, target_revision,
	created_at, updated_at, version, external_issues`

const openByTargetQuery = `SELECT ` + mergeRequestColumns + `
	  FROM codereview.merge_requests
	 WHERE repository_id = $1 AND target_ref = $2 AND state = 'OPEN'
	 ORDER BY merge_request_id ASC`

const openBySourceQuery = `SELECT ` + mergeRequestColumns + `
	  FROM codereview.merge_requests
	 WHERE repository_id = $1 AND source_ref = $2 AND state = 'OPEN'
	 ORDER BY merge_request_id ASC`

func loadMergeRequest(ctx context.Context, tx pgx.Tx, id string) (api.MergeRequest, error) {
	row := tx.QueryRow(ctx, `SELECT `+mergeRequestColumns+`
		  FROM codereview.merge_requests WHERE merge_request_id = $1`, id)
	mr, err := scanMergeRequest(row)
	if errors.Is(err, pgx.ErrNoRows) {
		// The same words the memory store uses, because the service compares on the error's
		// presence and a reader compares on its text.
		return api.MergeRequest{}, errors.New("not found")
	}
	return mr, err
}

// scanner is what both a single row and a row set satisfy, so one scan body serves the lookup and
// the two list queries.
type scanner interface {
	Scan(dest ...any) error
}

func scanMergeRequest(row scanner) (api.MergeRequest, error) {
	var (
		mr         api.MergeRequest
		state      string
		references []byte
	)
	if err := row.Scan(
		&mr.TenantID, &mr.ID, &mr.RepositoryID, &mr.SourceRef, &mr.TargetRef,
		&mr.Title, &mr.Description, &mr.CreatorID, &state, &mr.HeadRevision, &mr.TargetRevision,
		&mr.CreatedAt, &mr.UpdatedAt, &mr.Version, &references,
	); err != nil {
		return api.MergeRequest{}, err
	}
	mr.State = api.State(state)
	mr.CreatedAt, mr.UpdatedAt = mr.CreatedAt.UTC(), mr.UpdatedAt.UTC()
	issues, err := decodeExternalIssues(references)
	if err != nil {
		return api.MergeRequest{}, err
	}
	mr.ExternalIssues = issues
	return mr, nil
}

func insertMergeRequest(ctx context.Context, tx pgx.Tx, mr api.MergeRequest) error {
	references, err := json.Marshal(externalIssuesOf(mr))
	if err != nil {
		return fmt.Errorf("encoding references for %s: %w", mr.ID, err)
	}
	_, err = tx.Exec(ctx,
		`INSERT INTO codereview.merge_requests (`+mergeRequestColumns+`)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
		mr.TenantID, mr.ID, mr.RepositoryID, mr.SourceRef, mr.TargetRef,
		mr.Title, mr.Description, mr.CreatorID, string(mr.State), mr.HeadRevision, mr.TargetRevision,
		mr.CreatedAt, mr.UpdatedAt, mr.Version, references,
	)
	return err
}

// storedIssue is the JSONB shape. It is a type of this package rather than api.ExternalIssue with
// tags, because the column is a storage format: renaming a field in the API should be a decision
// about the API, and adding a json tag to the API type would make it one about the database too.
type storedIssue struct {
	Tracker  string    `json:"tracker"`
	IssueKey string    `json:"issue_key"`
	URL      string    `json:"url"`
	LinkedBy string    `json:"linked_by"`
	LinkedAt time.Time `json:"linked_at"`
}

func externalIssuesOf(mr api.MergeRequest) []storedIssue {
	// Never nil: the column is `NOT NULL DEFAULT '[]'` and a null would defeat that on the first
	// merge request with no references.
	out := make([]storedIssue, 0, len(mr.ExternalIssues))
	for _, reference := range mr.ExternalIssues {
		out = append(out, storedIssue{
			Tracker: reference.Tracker, IssueKey: reference.IssueKey, URL: reference.URL,
			LinkedBy: reference.LinkedBy, LinkedAt: reference.LinkedAt.UTC(),
		})
	}
	return out
}

func decodeExternalIssues(raw []byte) ([]api.ExternalIssue, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var stored []storedIssue
	if err := json.Unmarshal(raw, &stored); err != nil {
		return nil, fmt.Errorf("codereview postgres: decoding references: %w", err)
	}
	if len(stored) == 0 {
		// An empty array reads back as no references, not as an empty slice a caller has to
		// distinguish from nil.
		return nil, nil
	}
	out := make([]api.ExternalIssue, 0, len(stored))
	for _, reference := range stored {
		out = append(out, api.ExternalIssue{
			Tracker: reference.Tracker, IssueKey: reference.IssueKey, URL: reference.URL,
			LinkedBy: reference.LinkedBy, LinkedAt: reference.LinkedAt.UTC(),
		})
	}
	return out, nil
}
