package app

import (
	"context"
	"errors"

	"github.com/gitfrok/backend/modules/repository/api"
	"github.com/gitfrok/backend/modules/repository/internal/domain"
)

// The settings use cases (SPEC-0057, PR-30, ADR-0076).
//
// Three acts: read the settings, change name and description, set or clear the archived label. Each
// is a PDP decision asked through a port this context owns, and each accepted change appends exactly
// one audit record.
//
// What this file does NOT contain is the interesting part. Nothing here consults or produces a
// ReadOnlyState, narrows a list, or adds a field to a PDP input. Archival is a label, and the way
// that stays true is that the archival path has no code capable of doing anything else.

// WithAdministrator wires the abstraction that authorizes a settings change.
//
// A Service without one refuses every write with api.ErrNoAdministrationPoint rather than performing
// it, because the wrong default for "may administer" is the one that says yes.
func WithAdministrator(a api.Administrator) Option {
	return func(s *Service) { s.admin = a }
}

// WithWitness wires the port through which a settings act reaches the audit trail.
//
// A Service without one refuses every write. PR-30's own clause is "each change audited": a write
// that cannot be recorded is not the thing that was asked for, and performing it anyway would lose
// the record quietly, which is the failure mode auditability exists to prevent.
func WithWitness(w api.Witness) Option {
	return func(s *Service) { s.witness = w }
}

// GetSettings returns one repository's settings for a caller allowed to see that it exists.
//
// It asks `repo.read` through the same Authorizer the listing path uses, not `repo.admin`: being
// shown a repository's name and description is a read, and a reader who can see the repository can
// already see its name in the list. A caller who may not read it gets the same coarse refusal a
// caller asking about a repository in another tenant gets — the two must be indistinguishable
// (invariant 1, SPEC-0001).
func (s *Service) GetSettings(ctx context.Context, q api.SettingsQuery) (api.SettingsView, error) {
	if q.TenantID == "" || q.RepoID == "" {
		return api.SettingsView{}, errors.New("app: tenant and repository required")
	}
	if s.auth == nil {
		return api.SettingsView{}, api.ErrNoDecisionPoint
	}
	allowed, err := s.auth.MayRead(ctx, q.TenantID, q.ActorID, q.ActorRoles, q.RepoID)
	if err != nil || !allowed {
		return api.SettingsView{}, api.ErrSettingsForbidden
	}
	repo, err := s.load(ctx, q.TenantID, q.RepoID)
	if err != nil {
		return api.SettingsView{}, err
	}
	return settingsOf(repo), nil
}

// UpdateSettings changes the name and the description, and records that it did.
//
// The order is deliberate: authorize, load, apply in the domain, store, then witness. The audit
// record follows the write because it asserts a fact — the same reason Create publishes its event
// after the Save succeeds. A record of a change that did not happen is worse than a missing one,
// because an investigation believes it.
func (s *Service) UpdateSettings(ctx context.Context, u api.SettingsUpdate) (api.SettingsView, error) {
	if u.TenantID == "" || u.RepoID == "" {
		return api.SettingsView{}, errors.New("app: tenant and repository required")
	}
	if err := s.mayAdminister(ctx, u.TenantID, u.RepoID, u.ActorID, u.ActorRoles, api.ActionSettingsUpdated); err != nil {
		return api.SettingsView{}, err
	}
	repo, err := s.load(ctx, u.TenantID, u.RepoID)
	if err != nil {
		return api.SettingsView{}, err
	}
	// The domain decides whether this is a repository at all after the change: a rename to nothing
	// is refused here rather than at the column, so the caller learns which field it was.
	updated, err := repo.WithSettings(u.Name, u.Description, u.ActorID, s.now())
	if err != nil {
		return api.SettingsView{}, err
	}
	if err := s.store.Save(ctx, updated); err != nil {
		return api.SettingsView{}, err
	}
	if err := s.witnessAct(ctx, u.TenantID, u.RepoID, u.ActorID, api.ActionSettingsUpdated, false, map[string]string{
		// The record names what the settings now are, not a diff of prose nobody sent. A
		// description's previous text is in the previous record; reconstructing the change is
		// the trail's job, and it can, because the trail is append-only (ADR-0007).
		"name":        updated.Name,
		"description": describedAs(updated.Description),
	}); err != nil {
		return api.SettingsView{}, err
	}
	return settingsOf(updated), nil
}

// SetArchived sets or clears the archived label.
//
// Archiving an archived repository is accepted and writes nothing: no store round-trip, no audit
// record, and the recorded instant does not move (SPEC-0057 AC3). The aggregate decides that, not a
// comparison here — see domain.Repository.WithArchived.
//
// Nothing in this method touches authorization, listing or read-only state. That absence is the
// ADR-0076 decision-1 boundary, and SPEC-0057 AC7 asserts it from the outside.
func (s *Service) SetArchived(ctx context.Context, a api.ArchiveRequest) (api.SettingsView, error) {
	if a.TenantID == "" || a.RepoID == "" {
		return api.SettingsView{}, errors.New("app: tenant and repository required")
	}
	if err := s.mayAdminister(ctx, a.TenantID, a.RepoID, a.ActorID, a.ActorRoles, api.ActionArchivalChanged); err != nil {
		return api.SettingsView{}, err
	}
	repo, err := s.load(ctx, a.TenantID, a.RepoID)
	if err != nil {
		return api.SettingsView{}, err
	}
	updated, changed, err := repo.WithArchived(a.Archived, a.ActorID, s.now())
	if err != nil {
		return api.SettingsView{}, err
	}
	if !changed {
		return settingsOf(updated), nil
	}
	if err := s.store.Save(ctx, updated); err != nil {
		return api.SettingsView{}, err
	}
	if err := s.witnessAct(ctx, a.TenantID, a.RepoID, a.ActorID, api.ActionArchivalChanged, false, map[string]string{
		"archived": archivedAs(updated.IsArchived()),
	}); err != nil {
		return api.SettingsView{}, err
	}
	return settingsOf(updated), nil
}

// mayAdminister asks the PDP and records a refusal that reached it.
//
// A refusal is audited before it is returned, with the outcome marked denied: PR-30 asks that each
// change is audited, and a refused change is the half of the trail an investigation actually wants.
// A refusal the PDP never saw — no decision point, no witness — is a composition bug and is not
// audited, because there is nothing to record about a request the product could not evaluate.
func (s *Service) mayAdminister(ctx context.Context, tenantID, repoID, actorID string, roles []string, action string) error { //arch:allow-inline-authz decides nothing — it ASKS the PDP through api.Administrator and audits the refusal; no role literal appears in this module
	if s.admin == nil {
		return api.ErrNoAdministrationPoint
	}
	if s.witness == nil {
		return api.ErrNoWitness
	}
	allowed, err := s.admin.MayAdminister(ctx, tenantID, actorID, roles, repoID)
	if err != nil || !allowed {
		// The refusal is recorded, then returned coarsely. The record names the repository
		// because the trail is the tenant's own; the caller is told nothing.
		if wErr := s.witnessAct(ctx, tenantID, repoID, actorID, action, true, nil); wErr != nil {
			return wErr
		}
		return api.ErrSettingsForbidden
	}
	return nil
}

// witnessAct appends one record for one settings act.
func (s *Service) witnessAct(ctx context.Context, tenantID, repoID, actorID, action string, denied bool, detail map[string]string) error {
	if s.witness == nil {
		return api.ErrNoWitness
	}
	return s.witness.AppendSettingsRecord(ctx, api.WitnessEntry{
		TenantID:   tenantID,
		Action:     action,
		ActorID:    actorID,
		Resource:   repoID,
		Denied:     denied,
		Detail:     detail,
		OccurredAt: s.now().UTC(),
	})
}

// load reads one repository within one tenant, refusing a cross-tenant aggregate at the boundary the
// way Get does.
func (s *Service) load(ctx context.Context, tenantID, repoID string) (domain.Repository, error) {
	t := domain.TenantID(tenantID)
	repo, err := s.store.Load(ctx, t, domain.RepoID(repoID))
	if err != nil {
		return domain.Repository{}, err
	}
	if !repo.BelongsTo(t) {
		return domain.Repository{}, domain.ErrCrossTenant
	}
	return repo, nil
}

// settingsOf shapes the aggregate into the settings read model.
func settingsOf(r domain.Repository) api.SettingsView {
	return api.SettingsView{
		TenantID:          string(r.Tenant),
		RepoID:            string(r.ID),
		Name:              r.Name,
		Description:       r.Description,
		ArchivedAt:        r.ArchivedAt,
		SettingsUpdatedAt: r.SettingsUpdatedAt,
		SettingsUpdatedBy: r.SettingsUpdatedBy,
	}
}

// describedAs reports whether a description is present, without copying it into the record.
//
// The audit trail records that the description changed and who changed it; the text itself is the
// repository's, and a trail that accumulates prose becomes a place people read prose. This is the
// same posture ADR-0074 decision 2 takes for issue text — free-form user content is referenced from
// a control record, never carried into one.
func describedAs(description string) string {
	if description == "" {
		return "cleared"
	}
	return "set"
}

// archivedAs renders the archival state as the trail's vocabulary rather than as a Go bool's.
func archivedAs(archived bool) string {
	if archived {
		return "archived"
	}
	return "active"
}

var _ api.Settings = (*Service)(nil)
