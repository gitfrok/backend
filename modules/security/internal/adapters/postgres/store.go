// Package postgres is the Security/Findings persistence adapter.
//
// The schema's load-bearing properties live in the migration, not here:
// UNIQUE (tenant_id, repository_id, identity) IS the SPEC-0024 dedup rule,
// the scans table's CHECK constraint IS the one-way INGESTING→COMPLETE state
// machine, and RLS IS the tenant boundary (SPEC-0001). This adapter merely
// refuses to work outside those properties: every chunk applies inside one
// transaction serialized per scan, chunks stage invisibly until the final
// one, and a redelivered request ID replays the recorded outcome instead of
// re-applying (SPEC-0025 AC1).
package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/gitfrok/backend/modules/security/api"
	"github.com/gitfrok/backend/modules/security/internal/app"
	"github.com/gitfrok/backend/platform/db"
	"github.com/gitfrok/backend/platform/ids"
	"github.com/gitfrok/backend/platform/tenancy"
)

// Store is the Postgres findings store.
type Store struct {
	pool   *db.Pool
	nextID func() string
}

// New builds the store over a tenant-scoped pool.
func New(pool *db.Pool) *Store {
	return &Store{pool: pool, nextID: ids.NewULID}
}

var _ app.Store = (*Store)(nil)

// replayRecord is what the idempotency table stores per accepted chunk.
type replayRecord struct {
	findingsRecorded int
	completed        bool
}

// IngestChunk applies one chunk inside a transaction serialized per scan.
func (s *Store) IngestChunk(ctx context.Context, p app.IngestParams) (app.IngestOutcome, error) {
	ctx = tenancy.WithTenant(ctx, tenancy.ID(p.TenantID))
	var out app.IngestOutcome
	err := s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		// Serialize concurrent chunks of the same scan; everything below is
		// one atomic step per scan (SPEC-0025 non-functional).
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1)::bigint)`, p.ScanID); err != nil {
			return fmt.Errorf("lock scan: %w", err)
		}

		// Idempotency first (SPEC-0025 AC1): the recorded outcome replays.
		var rec replayRecord
		err := tx.QueryRow(ctx,
			`SELECT findings_recorded, completed FROM security.scan_chunks
			  WHERE scan_id = $1 AND chunk_index = $2 AND request_id = $3`,
			p.ScanID, p.ChunkIndex, p.RequestID).Scan(&rec.findingsRecorded, &rec.completed)
		if err == nil {
			out = app.IngestOutcome{
				ScanID:           p.ScanID,
				FindingsRecorded: int64(rec.findingsRecorded),
				Completed:        rec.completed,
				Replayed:         true,
			}
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("replay check: %w", err)
		}

		// First chunk creates the scan record, INGESTING.
		if _, err := tx.Exec(ctx,
			`INSERT INTO security.scans
			   (id, tenant_id, repository_id, scanner_class, tool_name, tool_version,
			    revision, started_at, ended_at, state)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'INGESTING')
			 ON CONFLICT (id) DO NOTHING`,
			p.ScanID, p.TenantID, p.RepositoryID, string(p.Scan.ScannerClass),
			p.Scan.ToolName, p.Scan.ToolVersion, p.Revision,
			p.Scan.StartedAt.UTC(), p.Scan.EndedAt.UTC()); err != nil {
			return fmt.Errorf("scan record: %w", err)
		}

		var state string
		var chunkCount int
		if err := tx.QueryRow(ctx,
			`SELECT state, chunk_count FROM security.scans WHERE id = $1`, p.ScanID,
		).Scan(&state, &chunkCount); err != nil {
			return fmt.Errorf("scan state: %w", err)
		}
		if state != "INGESTING" {
			return errors.New("security: scan already complete")
		}
		if p.ChunkIndex != chunkCount {
			return errors.New("security: chunk out of order")
		}

		// Stage the chunk's findings; nothing is visible yet.
		for _, pf := range p.Findings {
			if _, err := tx.Exec(ctx,
				`INSERT INTO security.scan_staged_findings
				   (tenant_id, scan_id, identity, rule_id, severity,
				    artifact_path, enclosing_content, component, component_version,
				    provenance, provenance_media_type)
				 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
				 ON CONFLICT (tenant_id, scan_id, identity) DO NOTHING`,
				p.TenantID, p.ScanID, pf.Identity, pf.Raw.RuleID, string(pf.Raw.Severity),
				pf.Raw.Location.ArtifactPath, pf.Raw.Location.EnclosingContent,
				pf.Raw.Location.Component, pf.Raw.Location.ComponentVersion,
				pf.Raw.Provenance, pf.Raw.ProvenanceMediaType); err != nil {
				return fmt.Errorf("stage finding: %w", err)
			}
		}

		out = app.IngestOutcome{ScanID: p.ScanID, FindingsRecorded: int64(len(p.Findings))}
		if !p.FinalChunk {
			if err := recordChunk(ctx, tx, p, false); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx,
				`UPDATE security.scans SET chunk_count = chunk_count + 1 WHERE id = $1`,
				p.ScanID); err != nil {
				return fmt.Errorf("advance scan: %w", err)
			}
			return nil
		}

		// Final chunk: apply the staged set, run the lifecycle consequences,
		// complete the scan, clear the stage — one atomic step.
		opened, resolved, err := applyLifecycle(ctx, tx, p, s.nextID)
		if err != nil {
			return err
		}
		out.Completed = true
		out.Opened, out.Resolved = opened, resolved

		if err := recordChunk(ctx, tx, p, true); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`UPDATE security.scans
			    SET state = 'COMPLETE', chunk_count = chunk_count + 1, completed_at = now()
			  WHERE id = $1 AND state = 'INGESTING'`, p.ScanID); err != nil {
			return fmt.Errorf("complete scan: %w", err)
		}
		if _, err := tx.Exec(ctx,
			`DELETE FROM security.scan_staged_findings WHERE scan_id = $1`, p.ScanID); err != nil {
			return fmt.Errorf("clear stage: %w", err)
		}
		return nil
	})
	if err != nil {
		return app.IngestOutcome{}, err
	}
	return out, nil
}

// recordChunk stores the idempotency record for one accepted chunk.
func recordChunk(ctx context.Context, tx pgx.Tx, p app.IngestParams, completed bool) error {
	summary, _ := json.Marshal(map[string]any{"completed": completed})
	if _, err := tx.Exec(ctx,
		`INSERT INTO security.scan_chunks
		   (tenant_id, scan_id, chunk_index, request_id, findings_recorded, completed, outcome_json)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		p.TenantID, p.ScanID, p.ChunkIndex, p.RequestID,
		len(p.Findings), completed, summary); err != nil {
		return fmt.Errorf("record chunk: %w", err)
	}
	return nil
}

// applyLifecycle upserts the scan's staged set into security.findings and
// resolves the open findings of the same reporting tool the scan no longer
// reports. Returned opened/resolved carry everything the events need.
func applyLifecycle(ctx context.Context, tx pgx.Tx, p app.IngestParams, nextID func() string) ([]api.Finding, []api.Finding, error) {
	reported := make([]string, 0, len(p.Findings))
	rows, err := tx.Query(ctx,
		`SELECT identity, rule_id, severity, artifact_path, enclosing_content,
		        component, component_version, provenance, provenance_media_type
		   FROM security.scan_staged_findings WHERE scan_id = $1 ORDER BY identity`, p.ScanID)
	if err != nil {
		return nil, nil, fmt.Errorf("read stage: %w", err)
	}
	type staged struct {
		identity, ruleID, severity, path, content, comp, compVer, mediaType string
		provenance                                                          []byte
	}
	var all []staged
	for rows.Next() {
		var st staged
		if err := rows.Scan(&st.identity, &st.ruleID, &st.severity, &st.path, &st.content,
			&st.comp, &st.compVer, &st.provenance, &st.mediaType); err != nil {
			rows.Close()
			return nil, nil, fmt.Errorf("scan stage: %w", err)
		}
		all = append(all, st)
		reported = append(reported, st.identity)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("stage rows: %w", err)
	}

	opened := []api.Finding{}
	for _, st := range all {
		// The UNIQUE constraint does the dedup: a re-reported identity
		// upserts onto its record. xmax = 0 says the row was inserted —
		// that is a first sight.
		var id string
		var inserted bool
		if err := tx.QueryRow(ctx,
			`INSERT INTO security.findings
			   (id, tenant_id, repository_id, identity, scanner_class, tool_name, tool_version,
			    rule_id, severity, artifact_path, enclosing_content, component, component_version,
			    lifecycle, first_seen_scan_id, last_seen_scan_id, provenance, provenance_media_type)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
			         'OPEN', $14, $14, $15, $16)
			 ON CONFLICT (tenant_id, repository_id, identity) DO UPDATE
			   SET severity = EXCLUDED.severity,
			       artifact_path = EXCLUDED.artifact_path,
			       enclosing_content = EXCLUDED.enclosing_content,
			       component = EXCLUDED.component,
			       component_version = EXCLUDED.component_version,
			       lifecycle = 'OPEN',
			       last_seen_scan_id = EXCLUDED.last_seen_scan_id,
			       provenance = EXCLUDED.provenance,
			       provenance_media_type = EXCLUDED.provenance_media_type,
			       updated_at = now()
			 RETURNING id, (xmax = 0)`,
			nextID(), p.TenantID, p.RepositoryID, st.identity,
			string(p.Scan.ScannerClass), p.Scan.ToolName, p.Scan.ToolVersion,
			st.ruleID, st.severity, st.path, st.content, st.comp, st.compVer,
			p.ScanID, st.provenance, st.mediaType).Scan(&id, &inserted); err != nil {
			return nil, nil, fmt.Errorf("upsert finding: %w", err)
		}
		if !inserted {
			continue
		}
		opened = append(opened, api.Finding{
			ID: id, TenantID: p.TenantID, RepositoryID: p.RepositoryID,
			ScannerClass: p.Scan.ScannerClass, ToolName: p.Scan.ToolName,
			ToolVersion: p.Scan.ToolVersion, RuleID: st.ruleID,
			Severity: api.Severity(st.severity),
			Location: api.Location{
				ArtifactPath: st.path, EnclosingContent: st.content,
				Component: st.comp, ComponentVersion: st.compVer,
			},
			Lifecycle: api.LifecycleOpen, FirstSeenScanID: p.ScanID, LastSeenScanID: p.ScanID,
		})
	}

	// Resolution: open findings of the same repository, scanner class, and
	// tool that this scan no longer reports — resolved, never deleted
	// (SPEC-0024 AC9).
	resolvedRows, err := tx.Query(ctx,
		`UPDATE security.findings
		    SET lifecycle = 'RESOLVED', updated_at = now()
		  WHERE repository_id = $1 AND scanner_class = $2 AND tool_name = $3
		    AND lifecycle = 'OPEN' AND NOT (identity = ANY($4))
		RETURNING id, rule_id, severity`,
		p.RepositoryID, string(p.Scan.ScannerClass), p.Scan.ToolName, reported)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve: %w", err)
	}
	resolved := []api.Finding{}
	for resolvedRows.Next() {
		var f api.Finding
		var severity string
		if err := resolvedRows.Scan(&f.ID, &f.RuleID, &severity); err != nil {
			resolvedRows.Close()
			return nil, nil, fmt.Errorf("scan resolved: %w", err)
		}
		f.TenantID, f.RepositoryID = p.TenantID, p.RepositoryID
		f.ScannerClass, f.ToolName = p.Scan.ScannerClass, p.Scan.ToolName
		f.Severity, f.Lifecycle = api.Severity(severity), api.LifecycleResolved
		resolved = append(resolved, f)
	}
	resolvedRows.Close()
	if err := resolvedRows.Err(); err != nil {
		return nil, nil, fmt.Errorf("resolved rows: %w", err)
	}
	return opened, resolved, nil
}

// GetFinding returns one tenant-scoped finding. RLS makes another tenant's
// row invisible, which reads as not-found — the same coarse refusal the
// service returns (SPEC-0001).
func (s *Store) GetFinding(ctx context.Context, tenantID, findingID string) (api.Finding, error) {
	ctx = tenancy.WithTenant(ctx, tenancy.ID(tenantID))
	var f api.Finding
	var scannerClass, severity, lifecycle string
	err := s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT id, tenant_id, repository_id, scanner_class, tool_name, tool_version,
			        rule_id, severity, artifact_path, enclosing_content, component,
			        component_version, lifecycle, first_seen_scan_id, last_seen_scan_id,
			        provenance, provenance_media_type
			   FROM security.findings WHERE id = $1`, findingID).Scan(
			&f.ID, &f.TenantID, &f.RepositoryID, &scannerClass, &f.ToolName, &f.ToolVersion,
			&f.RuleID, &severity, &f.Location.ArtifactPath, &f.Location.EnclosingContent,
			&f.Location.Component, &f.Location.ComponentVersion, &lifecycle,
			&f.FirstSeenScanID, &f.LastSeenScanID, &f.Provenance, &f.ProvenanceMediaType)
	})
	if err != nil {
		return api.Finding{}, err
	}
	f.ScannerClass, f.Severity, f.Lifecycle = api.ScannerClass(scannerClass), api.Severity(severity), api.Lifecycle(lifecycle)
	return f, nil
}

// ListFindings returns one page of the tenant's findings in ID order.
//
// NOTE (T-0023 WIP): the authorization-derived RepositoryIDs set and the
// age/owning-team filters the app.ListFilter now carries are enforced by the
// MemoryStore and still awaiting this adapter's parity; the triage-dashboard
// work that owns them lands the remaining clauses.
func (s *Store) ListFindings(ctx context.Context, tenantID string, f app.ListFilter) ([]api.Finding, error) {
	ctx = tenancy.WithTenant(ctx, tenancy.ID(tenantID))
	where := []string{"repository_id = $1"}
	args := []any{f.RepositoryID}
	if f.ScannerClass != "" {
		args = append(args, string(f.ScannerClass))
		where = append(where, fmt.Sprintf("scanner_class = $%d", len(args)))
	}
	if f.Severity != "" {
		args = append(args, string(f.Severity))
		where = append(where, fmt.Sprintf("severity = $%d", len(args)))
	}
	if f.Lifecycle != "" {
		args = append(args, string(f.Lifecycle))
		where = append(where, fmt.Sprintf("lifecycle = $%d", len(args)))
	}
	if f.AfterID != "" {
		args = append(args, f.AfterID)
		where = append(where, fmt.Sprintf("id > $%d", len(args)))
	}
	query := `SELECT id, tenant_id, repository_id, scanner_class, tool_name, tool_version,
	                 rule_id, severity, artifact_path, enclosing_content, component,
	                 component_version, lifecycle, first_seen_scan_id, last_seen_scan_id,
	                 provenance, provenance_media_type
	            FROM security.findings WHERE ` + strings.Join(where, " AND ") + `
	           ORDER BY id`
	if f.Limit > 0 {
		args = append(args, f.Limit)
		query += fmt.Sprintf(" LIMIT $%d", len(args))
	}

	out := []api.Finding{}
	err := s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, query, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var f api.Finding
			var scannerClass, severity, lifecycle string
			if err := rows.Scan(&f.ID, &f.TenantID, &f.RepositoryID, &scannerClass,
				&f.ToolName, &f.ToolVersion, &f.RuleID, &severity,
				&f.Location.ArtifactPath, &f.Location.EnclosingContent,
				&f.Location.Component, &f.Location.ComponentVersion, &lifecycle,
				&f.FirstSeenScanID, &f.LastSeenScanID, &f.Provenance, &f.ProvenanceMediaType); err != nil {
				return err
			}
			f.ScannerClass, f.Severity, f.Lifecycle = api.ScannerClass(scannerClass), api.Severity(severity), api.Lifecycle(lifecycle)
			out = append(out, f)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// filterClause builds the shared WHERE clause and argument list for the
// dashboard-read aggregates: the authorization-derived repository set is
// part of the query, not a mask applied late (SPEC-0026 AC6, SPEC-0027 AC4).
// The owning-team filter joins the attribution table; the returned join is
// empty when no clause needs it.
func filterClause(f app.ListFilter) (where []string, args []any, join string) {
	if f.RepositoryIDs != nil && len(f.RepositoryIDs) > 0 {
		args = append(args, f.RepositoryIDs)
		where = append(where, fmt.Sprintf("f.repository_id = ANY($%d)", len(args)))
	} else if f.RepositoryID != "" {
		args = append(args, f.RepositoryID)
		where = append(where, fmt.Sprintf("f.repository_id = $%d", len(args)))
	}
	if f.ScannerClass != "" {
		args = append(args, string(f.ScannerClass))
		where = append(where, fmt.Sprintf("f.scanner_class = $%d", len(args)))
	}
	if f.Severity != "" {
		args = append(args, string(f.Severity))
		where = append(where, fmt.Sprintf("f.severity = $%d", len(args)))
	}
	if f.Lifecycle != "" {
		args = append(args, string(f.Lifecycle))
		where = append(where, fmt.Sprintf("f.lifecycle = $%d", len(args)))
	}
	// Age bounds measure whole days since first sight, which the upsert
	// never touches: created_at stands in for the MemoryStore's firstSeenAt.
	if f.MinAgeDays > 0 {
		args = append(args, f.MinAgeDays)
		where = append(where, fmt.Sprintf("floor(EXTRACT(EPOCH FROM (now() - f.created_at)) / 86400) >= $%d", len(args)))
	}
	if f.MaxAgeDays > 0 {
		args = append(args, f.MaxAgeDays)
		where = append(where, fmt.Sprintf("floor(EXTRACT(EPOCH FROM (now() - f.created_at)) / 86400) <= $%d", len(args)))
	}
	if f.OwningTeam != "" {
		join = ` LEFT JOIN security.repository_ownership ro
	                 ON ro.repository_id = f.repository_id`
		args = append(args, f.OwningTeam)
		where = append(where, fmt.Sprintf("ro.owning_team = $%d", len(args)))
	}
	return where, args, join
}

// RepositoriesWithFindings returns the distinct repositories holding the
// tenant's findings, in stable order. It reveals no counts: it is the
// candidate set the service asks the PDP about (SPEC-0026 AC1).
func (s *Store) RepositoriesWithFindings(ctx context.Context, tenantID string) ([]string, error) {
	ctx = tenancy.WithTenant(ctx, tenancy.ID(tenantID))
	out := []string{}
	err := s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT DISTINCT repository_id FROM security.findings ORDER BY repository_id`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r string
			if err := rows.Scan(&r); err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// FindingsSummary computes counts and facet values in scoped aggregates —
// the authorization-derived repository set among the filters, so a value
// that exists only outside the caller's readable set appears in no facet
// (SPEC-0027 AC4).
func (s *Store) FindingsSummary(ctx context.Context, tenantID string, q app.SummaryQuery) (api.FindingsSummary, error) {
	ctx = tenancy.WithTenant(ctx, tenancy.ID(tenantID))
	out := api.FindingsSummary{Facets: []api.SummaryFacet{}}

	// A non-nil empty repository set matches nothing, fail closed
	// (SPEC-0026 AC6): no query runs at all.
	if q.RepositoryIDs != nil && len(q.RepositoryIDs) == 0 {
		for _, dim := range q.Facets {
			out.Facets = append(out.Facets, api.SummaryFacet{Dimension: dim, Values: []api.SummaryFacetValue{}})
		}
		return out, nil
	}

	where, args, join := filterClause(q.ListFilter)
	whereSQL := ""
	if len(where) > 0 {
		whereSQL = " WHERE " + strings.Join(where, " AND ")
	}

	err := s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if err := tx.QueryRow(ctx,
			`SELECT COUNT(*) FROM security.findings f`+join+whereSQL, args...,
		).Scan(&out.TotalCount); err != nil {
			return fmt.Errorf("count: %w", err)
		}
		for _, dim := range q.Facets {
			var column string
			switch dim {
			case api.FacetSeverity:
				column = "f.severity"
			case api.FacetScannerClass:
				column = "f.scanner_class"
			case api.FacetLifecycle:
				column = "f.lifecycle"
			case api.FacetOwningTeam:
				column = "ro.owning_team"
			default:
				return fmt.Errorf("security: unknown facet dimension %q", dim)
			}
			facetJoin := join
			if dim == api.FacetOwningTeam && facetJoin == "" {
				facetJoin = ` LEFT JOIN security.repository_ownership ro
	                    ON ro.repository_id = f.repository_id`
			}
			facetWhere := whereSQL
			// A repository with no owning-team attribution contributes to
			// no owning_team value: absence, not an empty bucket.
			if dim == api.FacetOwningTeam {
				extra := "ro.owning_team IS NOT NULL AND ro.owning_team <> ''"
				if facetWhere == "" {
					facetWhere = " WHERE " + extra
				} else {
					facetWhere += " AND " + extra
				}
			}
			rows, err := tx.Query(ctx,
				`SELECT `+column+`, COUNT(*) FROM security.findings f`+facetJoin+facetWhere+
					` GROUP BY 1 ORDER BY 1`, args...)
			if err != nil {
				return fmt.Errorf("facet %s: %w", dim, err)
			}
			facet := api.SummaryFacet{Dimension: dim, Values: []api.SummaryFacetValue{}}
			for rows.Next() {
				var v api.SummaryFacetValue
				if err := rows.Scan(&v.Value, &v.Count); err != nil {
					rows.Close()
					return err
				}
				facet.Values = append(facet.Values, v)
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return err
			}
			out.Facets = append(out.Facets, facet)
		}
		return nil
	})
	if err != nil {
		return api.FindingsSummary{}, err
	}
	return out, nil
}

// SetRepositoryOwningTeam records the repository-level owning-team
// attribution (SPEC-0026 v1 assumption).
func (s *Store) SetRepositoryOwningTeam(ctx context.Context, tenantID, repositoryID, owningTeam string) error {
	ctx = tenancy.WithTenant(ctx, tenancy.ID(tenantID))
	return s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO security.repository_ownership (tenant_id, repository_id, owning_team)
			 VALUES ($1, $2, $3)
			 ON CONFLICT (tenant_id, repository_id)
			 DO UPDATE SET owning_team = EXCLUDED.owning_team, updated_at = now()`,
			tenantID, repositoryID, owningTeam)
		return err
	})
}

// readTriage returns one triage record: the finding's latest when version is
// zero, the exact history version otherwise.
func readTriage(ctx context.Context, tx pgx.Tx, findingID string, version int64) (api.TriageRecord, bool, error) {
	query := `SELECT triage_id, finding_id, tenant_id, repository_id, state,
	                 justification, version, actor_id, occurred_at
	            FROM security.triages WHERE finding_id = $1`
	if version == 0 {
		query += ` ORDER BY version DESC LIMIT 1`
	} else {
		query += ` AND version = $2`
	}
	var rec api.TriageRecord
	var state string
	var err error
	if version == 0 {
		err = tx.QueryRow(ctx, query, findingID).Scan(
			&rec.TriageID, &rec.FindingID, &rec.TenantID, &rec.RepositoryID,
			&state, &rec.Justification, &rec.Version, &rec.ActorID, &rec.OccurredAt)
	} else {
		err = tx.QueryRow(ctx, query, findingID, version).Scan(
			&rec.TriageID, &rec.FindingID, &rec.TenantID, &rec.RepositoryID,
			&state, &rec.Justification, &rec.Version, &rec.ActorID, &rec.OccurredAt)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return api.TriageRecord{}, false, nil
	}
	if err != nil {
		return api.TriageRecord{}, false, err
	}
	rec.State = api.TriageState(state)
	return rec, true, nil
}

// SetTriage appends one triage record inside a transaction serialized per
// finding: replay first, then the version guard, then the append
// (SPEC-0027 AC1, SPEC-0026 AC5). Superseded records are retained, never
// mutated.
func (s *Store) SetTriage(ctx context.Context, p app.SetTriageParams) (app.SetTriageResult, error) {
	ctx = tenancy.WithTenant(ctx, tenancy.ID(p.TenantID))
	var out app.SetTriageResult
	err := s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		// Serialize concurrent transitions on the same finding.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1)::bigint)`, p.FindingID); err != nil {
			return fmt.Errorf("lock finding: %w", err)
		}

		// Idempotency first (SPEC-0027 AC1): a recorded request ID replays.
		var replayTriageID string
		err := tx.QueryRow(ctx,
			`SELECT triage_id FROM security.triage_requests
			  WHERE finding_id = $1 AND request_id = $2`,
			p.FindingID, p.RequestID).Scan(&replayTriageID)
		if err == nil {
			rec, _, err := readTriageByTriageID(ctx, tx, replayTriageID)
			if err != nil {
				return err
			}
			out = app.SetTriageResult{Record: rec, Replayed: true}
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("replay check: %w", err)
		}

		var current int64
		if err := tx.QueryRow(ctx,
			`SELECT COALESCE(MAX(version), 0) FROM security.triages WHERE finding_id = $1`,
			p.FindingID).Scan(&current); err != nil {
			return fmt.Errorf("current version: %w", err)
		}
		if current != p.ExpectedVersion {
			inForce, _, err := readTriage(ctx, tx, p.FindingID, 0)
			if err != nil {
				return err
			}
			out = app.SetTriageResult{Record: inForce, Mismatch: true}
			return nil
		}

		rec := api.TriageRecord{
			TriageID: p.TriageID, FindingID: p.FindingID, TenantID: p.TenantID,
			RepositoryID: p.RepositoryID, State: p.State, Justification: p.Justification,
			Version: current + 1, ActorID: p.ActorID, OccurredAt: p.OccurredAt,
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO security.triages
			   (tenant_id, finding_id, triage_id, repository_id, state,
			    justification, version, actor_id, occurred_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			p.TenantID, p.FindingID, p.TriageID, p.RepositoryID, string(p.State),
			p.Justification, rec.Version, p.ActorID, p.OccurredAt.UTC()); err != nil {
			return fmt.Errorf("append triage: %w", err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO security.triage_requests (tenant_id, finding_id, request_id, triage_id)
			 VALUES ($1, $2, $3, $4)`,
			p.TenantID, p.FindingID, p.RequestID, p.TriageID); err != nil {
			return fmt.Errorf("record triage request: %w", err)
		}
		out = app.SetTriageResult{Record: rec}
		return nil
	})
	if err != nil {
		return app.SetTriageResult{}, err
	}
	return out, nil
}

// readTriageByTriageID loads one record by its opaque identity — the replay
// path of SetTriage.
func readTriageByTriageID(ctx context.Context, tx pgx.Tx, triageID string) (api.TriageRecord, bool, error) {
	var rec api.TriageRecord
	var state string
	err := tx.QueryRow(ctx,
		`SELECT triage_id, finding_id, tenant_id, repository_id, state,
	        justification, version, actor_id, occurred_at
	   FROM security.triages WHERE triage_id = $1`, triageID).Scan(
		&rec.TriageID, &rec.FindingID, &rec.TenantID, &rec.RepositoryID,
		&state, &rec.Justification, &rec.Version, &rec.ActorID, &rec.OccurredAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return api.TriageRecord{}, false, nil
	}
	if err != nil {
		return api.TriageRecord{}, false, err
	}
	rec.State = api.TriageState(state)
	return rec, true, nil
}

// GetTriage returns the finding's triage record: the latest when version is
// zero, the exact history version otherwise. Found is false when there is no
// record — RLS makes another tenant's record invisible, which reads as the
// same absence (SPEC-0001).
func (s *Store) GetTriage(ctx context.Context, tenantID, findingID string, version int64) (api.TriageRecord, bool, error) {
	ctx = tenancy.WithTenant(ctx, tenancy.ID(tenantID))
	var rec api.TriageRecord
	var found bool
	err := s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		rec, found, err = readTriage(ctx, tx, findingID, version)
		return err
	})
	if err != nil {
		return api.TriageRecord{}, false, err
	}
	return rec, found, nil
}
