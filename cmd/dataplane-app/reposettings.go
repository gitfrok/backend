package main

import (
	"context"

	auditapi "github.com/gitfrok/backend/modules/audit/api"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
	repoapi "github.com/gitfrok/backend/modules/repository/api"
)

// The composition of the Repository context's settings surface (T-0068, SPEC-0057, ADR-0076).
//
// Both adapters live here for the reason repoAuthorizer does: the Repository module is a leaf at
// fan-out zero, so it declares the abstractions it needs and this root — the one place that may know
// every context — supplies them (invariant 14, ADR-0025).

// repoAdministrator adapts the PDP onto the Repository context's Administrator port.
//
// It asks `repo.admin`, which the policy bundle already grants to `owner` and to no other role. That
// is the point: this surface adds no action to the vocabulary and no role to the model, so ADR-0076
// decision 1 — no setting may change an authorization outcome — holds at the decision point and not
// only in the UI. A settings page that needed a new permission would have been a settings page
// changing the authorization model.
type repoAdministrator struct {
	pdp policyapi.DecisionPoint
}

// MayAdminister asks whether the caller may change one repository's settings.
//
// An error is returned as an error rather than as a false: the caller decides what an unavailable
// decision point means for its own shape, and for a settings write it means refuse — there is no
// reading of ADR-0006 in which a write proceeds because the PDP could not be reached.
func (a repoAdministrator) MayAdminister(ctx context.Context, tenantID, actorID string, roles []string, repoID string) (bool, error) {
	d, err := a.pdp.Decide(ctx, policyapi.Request{
		TenantID: tenantID,
		Subject: policyapi.Subject{
			ID:       actorID,
			TenantID: tenantID,
			Roles:    roles,
		},
		Action:   "repo.admin",
		Resource: policyapi.Resource{Type: "repository", ID: repoID},
	})
	if err != nil {
		return false, err
	}
	return d.Allowed, nil
}

// repoSettingsWitness adapts the plane's audit trail onto the Repository context's Witness port.
//
// Every record from that surface is a first-party fact this service observed — the actor was
// authenticated by us, authorized by our PDP and timestamped by our clock — so the provenance is
// stated once here rather than asserted per call (ADR-0029 §1). The outcome mirrors the entry's
// denied flag: a refused settings change is a record, and it is the half of the trail an
// investigation wants (SPEC-0057 AC5).
type repoSettingsWitness struct {
	trail auditapi.Log
}

// AppendSettingsRecord implements repoapi.Witness over the tenant's audit chain.
//
// It returns no chain position, unlike the grant and residency witnesses: nothing on this surface
// cites a record. A settings change is audited because PR-30 requires it, not because another fact
// depends on it, and returning a sequence number nobody reads would invite someone to render it.
func (w repoSettingsWitness) AppendSettingsRecord(ctx context.Context, e repoapi.WitnessEntry) error {
	outcome := auditapi.OutcomeAllowed
	if e.Denied {
		outcome = auditapi.OutcomeDenied
	}
	_, err := w.trail.Append(ctx, auditapi.Entry{
		TenantID:   e.TenantID,
		Action:     auditapi.Action(e.Action),
		ActorID:    e.ActorID,
		Resource:   e.Resource,
		Outcome:    outcome,
		Detail:     e.Detail,
		OccurredAt: e.OccurredAt,
		Provenance: auditapi.ProvenanceFirstParty,
	})
	return err
}

var (
	_ repoapi.Administrator = repoAdministrator{}
	_ repoapi.Witness       = repoSettingsWitness{}
)
