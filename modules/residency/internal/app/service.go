// Package app is the Residency context's application service (T-0033, SPEC-0040): declare
// the tenant's residency under a PDP decision, observe the placements its data planes
// actually run at, and refuse the ones that would leave the declaration.
//
// Every act is witnessed through the context's own append-only port before it takes effect
// (the GrantWitness pattern): a declaration that cannot be recorded is not set, and a
// refusal that cannot be recorded is a failure, not a silent denial. The witness returns
// the chain position each fact cites; the evidence pack's residency section re-derives
// these records from the tenant's own chain (ADR-0007, SPEC-0040 AC4).
package app

import (
	"context"
	"time"

	policyapi "github.com/gitfrok/backend/modules/policy/api"
	"github.com/gitfrok/backend/modules/residency/api"
	"github.com/gitfrok/backend/modules/residency/internal/domain"
	platformaudit "github.com/gitfrok/backend/platform/audit"
)

// Store is the residency state the service reads and writes, in the app's own terms. The
// in-memory adapter implements it; a durable store is future work and a composition-line
// change (invariant 13).
type Store interface {
	PutDeclaration(ctx context.Context, d api.Declaration) error
	Declaration(ctx context.Context, tenantID string) (api.Declaration, bool, error)
	PutObservation(ctx context.Context, tenantID, dataPlaneID, cloud, region string) error
	ObservedPlacements(ctx context.Context, tenantID string) ([]api.ObservedPlacement, error)
}

// Service implements api.Service. Safe for concurrent use.
type Service struct {
	pdp     policyapi.DecisionPoint
	witness api.Witness
	store   Store
	now     func() time.Time
	logf    func(format string, args ...any)
}

// New builds the service on a decision point, a witness and a store. None is optional: a
// residency act is either decided, witnessed and stored, or it does not happen.
func New(pdp policyapi.DecisionPoint, witness api.Witness, store Store, cfg api.Config, logf func(format string, args ...any)) *Service {
	if pdp == nil {
		panic("residency: no PDP — declaring residency is a policy decision (invariant 2)")
	}
	if witness == nil || store == nil {
		panic("residency: witness and store are both required — an unwitnessed act does not happen")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Service{pdp: pdp, witness: witness, store: store, now: cfg.Now, logf: logf}
}

// Declare implements api.Service (SPEC-0040 AC1, AC3, AC6).
func (s *Service) Declare(ctx context.Context, tenantID, actorID string, roles []string, cloud, region string) (api.Declaration, error) {
	if tenantID == "" || actorID == "" || cloud == "" || region == "" {
		// A malformed declaration is indistinguishable from any other failure
		// (SPEC-0001): the surface gives nothing back to probe with.
		return api.Declaration{}, api.ErrResidencyUnavailable
	}

	// Declaring is a PDP decision asked about the tenant (authz.rego: owner-only,
	// resource kind tenant). A denial and an unreachable PDP are the same coarse shape;
	// neither is witnessed (ADR-0006).
	decision, err := s.pdp.Decide(ctx, policyapi.Request{
		TenantID: tenantID,
		Subject:  policyapi.Subject{ID: actorID, TenantID: tenantID, Roles: roles},
		Action:   platformaudit.ActionResidencyDeclarationSet,
		Resource: policyapi.Resource{Type: "tenant", ID: tenantID},
		Context: map[string]string{
			platformaudit.DetailResidencyPinnedCloud:  cloud,
			platformaudit.DetailResidencyPinnedRegion: region,
		},
	})
	if err != nil || !decision.Allowed {
		return api.Declaration{}, api.ErrResidencyUnavailable
	}

	// The declaration is witnessed BEFORE it takes effect: the record's effective time is
	// the server's clock at witness time — the only instant a pack cites (AC1, AC6). A
	// witness that cannot take the record fails the declaration; an unrecorded declaration
	// is a worse failure than a refused one.
	now := s.now()
	rec, err := s.witness.AppendResidencyRecord(ctx, api.WitnessEntry{
		TenantID: tenantID,
		Action:   platformaudit.ActionResidencyDeclarationSet,
		ActorID:  actorID,
		Resource: "tenant/" + tenantID,
		Detail: map[string]string{
			platformaudit.DetailResidencyPinnedCloud:  cloud,
			platformaudit.DetailResidencyPinnedRegion: region,
		},
		OccurredAt: now,
	})
	if err != nil {
		return api.Declaration{}, api.ErrResidencyUnavailable
	}

	decl := api.Declaration{
		TenantID: tenantID, Cloud: cloud, Region: region,
		EffectiveAt: now, ActorID: actorID,
		ChainSeq: rec.Seq, RecordHash: rec.Hash,
	}
	if err := s.store.PutDeclaration(ctx, decl); err != nil {
		return api.Declaration{}, api.ErrResidencyUnavailable
	}

	// AC3: a declaration taking effect against an already-observed placement raises the
	// violation state NOW — detection is synchronous at declaration time, so it lands
	// inside any configured detection window by construction. Each contradicting plane
	// gets its own witnessed contradiction record naming both placements.
	planes, err := s.store.ObservedPlacements(ctx, tenantID)
	if err != nil {
		return api.Declaration{}, api.ErrResidencyUnavailable
	}
	for _, p := range planes {
		if !domain.Contradiction(cloud, region, p.Cloud, p.Region) {
			continue
		}
		if _, werr := s.witness.AppendResidencyRecord(ctx, api.WitnessEntry{
			TenantID: tenantID,
			Action:   platformaudit.ActionResidencyPlacementContradiction,
			Resource: "data_plane/" + p.DataPlaneID,
			Detail: map[string]string{
				platformaudit.DetailResidencyPinnedCloud:    cloud,
				platformaudit.DetailResidencyPinnedRegion:   region,
				platformaudit.DetailResidencyObservedCloud:  p.Cloud,
				platformaudit.DetailResidencyObservedRegion: p.Region,
			},
			Denied:     true,
			OccurredAt: now,
		}); werr != nil {
			// The declaration itself stands — it was witnessed. A contradiction the
			// trail cannot take is logged, never silent.
			s.logf("residency: witnessing contradiction for data plane %s: %v", p.DataPlaneID, werr)
		}
	}
	return decl, nil
}

// Declaration implements api.Service. The caller's tenant scope is enforced by the store:
// a cross-tenant read is the same coarse denial as an absent declaration (SPEC-0001).
func (s *Service) Declaration(ctx context.Context, tenantID string) (api.Declaration, bool, error) {
	if tenantID == "" {
		return api.Declaration{}, false, api.ErrResidencyUnavailable
	}
	return s.store.Declaration(ctx, tenantID)
}

// ObservePlacement implements api.Service (SPEC-0040 AC2, AC4). The caller's tenant scope
// is the caller's own: the enrolment path scopes the context after resolving the tenant
// from the token, and the store refuses any mismatch.
func (s *Service) ObservePlacement(ctx context.Context, tenantID, dataPlaneID, cloud, region string) error {
	if tenantID == "" || dataPlaneID == "" {
		return api.ErrResidencyUnavailable
	}
	decl, ok, err := s.store.Declaration(ctx, tenantID)
	if err != nil {
		return api.ErrResidencyUnavailable
	}
	now := s.now()

	if ok && domain.Contradiction(decl.Cloud, decl.Region, cloud, region) {
		// AC2: the attempt is refused AND witnessed with the declared and the attempted
		// placement. An unrecorded refusal is a failure, not a silent denial.
		if _, werr := s.witness.AppendResidencyRecord(ctx, api.WitnessEntry{
			TenantID: tenantID,
			Action:   platformaudit.ActionResidencyPlacementRefused,
			Resource: "data_plane/" + dataPlaneID,
			Detail: map[string]string{
				platformaudit.DetailResidencyPinnedCloud:    decl.Cloud,
				platformaudit.DetailResidencyPinnedRegion:   decl.Region,
				platformaudit.DetailResidencyObservedCloud:  cloud,
				platformaudit.DetailResidencyObservedRegion: region,
			},
			Denied:     true,
			OccurredAt: now,
		}); werr != nil {
			return api.ErrResidencyUnavailable
		}
		return api.ErrPlacementRefused
	}

	// Admitted: witnessed as an observed placement carrying both facts — the declaration
	// in force (empty when the tenant pins nothing) and the placement reported.
	detail := map[string]string{
		platformaudit.DetailResidencyObservedCloud:  cloud,
		platformaudit.DetailResidencyObservedRegion: region,
	}
	if ok {
		detail[platformaudit.DetailResidencyPinnedCloud] = decl.Cloud
		detail[platformaudit.DetailResidencyPinnedRegion] = decl.Region
	}
	if _, err := s.witness.AppendResidencyRecord(ctx, api.WitnessEntry{
		TenantID:   tenantID,
		Action:     platformaudit.ActionResidencyPlacementObserved,
		Resource:   "data_plane/" + dataPlaneID,
		Detail:     detail,
		OccurredAt: now,
	}); err != nil {
		return api.ErrResidencyUnavailable
	}
	if err := s.store.PutObservation(ctx, tenantID, dataPlaneID, cloud, region); err != nil {
		return api.ErrResidencyUnavailable
	}
	return nil
}
