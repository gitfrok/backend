package main

import (
	"context"

	auditapi "github.com/gitfrok/backend/modules/audit/api"
	identityapi "github.com/gitfrok/backend/modules/identity/api"
)

// grantTrailWitness adapts the tenant's audit trail onto the auditor grant
// lifecycle's witness port (T-0027, SPEC-0033 AC4). The composition root is
// the only place that may know both surfaces: Identity&Access declares the
// port in its own terms so the module graph stays acyclic (invariant 14),
// and the plane supplies the rendering — every grant lifecycle record is an
// authorized, first-party fact, so the outcome is always ALLOWED and the
// provenance always FIRST_PARTY.
type grantTrailWitness struct {
	trail auditapi.Log
}

// AppendGrantRecord implements identityapi.GrantWitness over the tenant's
// audit chain, returning the chain position the writer assigned — the facts
// the witnessed transition cites.
func (w grantTrailWitness) AppendGrantRecord(ctx context.Context, e identityapi.GrantWitnessEntry) (identityapi.GrantWitnessRecord, error) {
	record, err := w.trail.Append(ctx, auditapi.Entry{
		TenantID:   e.TenantID,
		Action:     auditapi.Action(e.Action),
		ActorID:    e.ActorID,
		Resource:   e.Resource,
		Outcome:    auditapi.OutcomeAllowed,
		Detail:     e.Detail,
		OccurredAt: e.OccurredAt,
		Provenance: auditapi.ProvenanceFirstParty,
	})
	if err != nil {
		return identityapi.GrantWitnessRecord{}, err
	}
	return identityapi.GrantWitnessRecord{Seq: record.Seq, Hash: record.Hash}, nil
}
