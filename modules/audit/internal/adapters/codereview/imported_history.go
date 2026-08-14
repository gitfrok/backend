// Package codereview adapts Code Review's import surface to the evidence
// pack's appendix port (T-0026, SPEC-0031 AC2).
//
// It crosses the module boundary at the two api/ surfaces only — Audit reads
// imported history through codereviewapi.ImportService, never through its
// storage (ADR-0022) — and it renders every record it hands over with its
// ADR-0029 provenance block: the appendix's records are labelled foreign
// history by construction, and no control section can carry them because the
// assembler's SectionRecord has no field that could.
package codereview

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/gitfrok/backend/modules/audit/api"
	codereviewapi "github.com/gitfrok/backend/modules/codereview/api"
	"github.com/gitfrok/backend/platform/ids"
)

// ImportedHistorySource supplies the appendix from Code Review's import
// surface. It carries no authorization of its own: the evidence service asks
// the PDP before it ever calls this, and the import surface itself scopes
// every read to the tenant it is given (SPEC-0001).
type ImportedHistorySource struct {
	imports codereviewapi.ImportService
}

// NewImportedHistorySource wires the adapter over the import surface.
func NewImportedHistorySource(imports codereviewapi.ImportService) *ImportedHistorySource {
	return &ImportedHistorySource{imports: imports}
}

// AttestedHistory returns the attested imported records whose declared time
// intersects the range, grouped by the admitting import. Revoked imports
// contribute nothing — their records are dropped from every read (SPEC-0011
// AC17), and the appendix honours the same tombstone.
func (s *ImportedHistorySource) AttestedHistory(ctx context.Context, tenantID string, from, to time.Time, repositoryID string) ([]api.AttestedGroup, error) {
	principal := codereviewapi.Context{
		TenantID:  tenantID,
		ActorID:   "system:audit-evidence-assembler",
		RequestID: ids.NewULID(),
		// Roles stay empty on purpose: the assembler is a server-side
		// projection of Audit's own authorized operation, not a principal
		// with its own grants. The pack's authorization is the evidence
		// service's PDP decision, recorded before this is ever called.
		RepositoryID: repositoryID,
	}

	imports, err := s.imports.List(ctx, principal, repositoryID)
	if err != nil {
		return nil, fmt.Errorf("audit: listing imports for the appendix: %w", err)
	}

	var groups []api.AttestedGroup
	for _, imp := range imports {
		if imp.State != codereviewapi.ImportComplete {
			continue // pending, failed, stalled and revoked admit nothing
		}
		records, err := s.recordsInRange(ctx, principal, imp, from, to)
		if err != nil {
			return nil, err
		}
		if len(records) == 0 {
			continue
		}
		groups = append(groups, api.AttestedGroup{
			Import: api.HistoryImportedRef{
				// The admitting HistoryImported event correlates by import ID;
				// the event's own ID is not persisted on the import record,
				// so the reference names the import it admitted.
				EventID:        imp.ID,
				RepositoryID:   imp.RepositoryID,
				ImportID:       imp.ID,
				SourceSystem:   imp.SourceSystem,
				SourceInstance: imp.SourceInstance,
				RecordCounts:   imp.RecordCounts,
				ManifestDigest: imp.ManifestDigest,
				OccurredAt:     imp.UpdatedAt,
			},
			Records: records,
		})
	}
	return groups, nil
}

// recordsInRange pages through one import's imported merge requests and
// renders the records whose declared time intersects the range. A record
// with no declared time falls back to the import's completion time for the
// range check: the platform's witness of the import is the only time it has.
func (s *ImportedHistorySource) recordsInRange(ctx context.Context, principal codereviewapi.Context, imp codereviewapi.Import, from, to time.Time) ([]api.AttestedRecord, error) {
	var out []api.AttestedRecord
	pageToken := ""
	for {
		page, err := s.imports.ListImportedHistory(ctx, codereviewapi.ListImportedHistoryRequest{
			Context:   principal,
			ImportID:  imp.ID,
			PageSize:  codereviewapi.MaxImportedHistoryPageSize,
			PageToken: pageToken,
		})
		if err != nil {
			return nil, fmt.Errorf("audit: reading imported history %s: %w", imp.ID, err)
		}
		for _, mr := range page.MergeRequests {
			inRange := func(t time.Time) bool {
				if t.IsZero() {
					t = imp.UpdatedAt
				}
				return !t.Before(from) && !t.After(to)
			}
			if inRange(mr.Provenance.DeclaredAt) {
				rec, err := render("merge_request", mr, mr.Provenance)
				if err != nil {
					return nil, err
				}
				out = append(out, rec)
			}
			for _, approval := range mr.Approvals {
				if !inRange(approval.DeclaredAt) {
					continue
				}
				rec, err := render("approval", approval, approval.Provenance)
				if err != nil {
					return nil, err
				}
				out = append(out, rec)
			}
		}
		if page.NextPageToken == "" {
			break
		}
		pageToken = page.NextPageToken
	}
	return out, nil
}

// render embeds one imported record's payload at generation time (ADR-0055
// rule 3) with its provenance block. The payload is a deterministic JSON
// rendering: the appendix is a snapshot, readable after the attested store's
// retention expires the original.
func render(kind string, record any, prov codereviewapi.Provenance) (api.AttestedRecord, error) {
	payload, err := json.Marshal(record)
	if err != nil {
		return api.AttestedRecord{}, fmt.Errorf("audit: rendering attested record: %w", err)
	}
	return api.AttestedRecord{
		RecordKind: kind,
		Payload:    payload,
		Provenance: api.AttestedProvenance{
			ImportID:       prov.ImportID,
			SourceSystem:   prov.SourceSystem,
			SourceInstance: prov.SourceInstance,
			SourceRef:      prov.SourceRef,
			ForeignHandle:  prov.DeclaredActor,
			DeclaredAt:     prov.DeclaredAt,
			PayloadDigest:  prov.PayloadDigest,
		},
	}, nil
}
