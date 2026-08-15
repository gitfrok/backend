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
// read is effective-dated: DeclarationAt answers "the declaration in force at this
// instant" from retained history, and same-instant rows tie-break on the LATER chain
// position — the deterministic read the PlacementGate's enforcement consults (T-0039,
// SPEC-0042 AC3, ADR-0062). The in-memory adapter implements it; the durable Postgres
// adapter is a composition-line change (invariant 13).
type Store interface {
	PutDeclaration(ctx context.Context, d api.Declaration) error
	DeclarationAt(ctx context.Context, tenantID string, at time.Time) (api.Declaration, bool, error)
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

// Declare implements api.Service (SPEC-0040 AC1, AC3, AC6; SPEC-0043 AC1).
func (s *Service) Declare(ctx context.Context, tenantID, actorID string, roles []string, cloud, region string) (api.Declaration, error) {
	if tenantID == "" || actorID == "" || cloud == "" || region == "" {
		// A malformed declaration is indistinguishable from any other failure
		// (SPEC-0001): the surface gives nothing back to probe with. Nothing is
		// witnessed: a shapeless attempt names no tenant to audit under.
		return api.Declaration{}, api.ErrResidencyUnavailable
	}

	// The declaration in force before this act, if any: every record this act
	// appends — allowed or refused — names previous and new pinning on the one
	// record (SPEC-0043 AC1). A read failure is the coarse failure; a declaration
	// that cannot know what it replaces does not happen.
	prev, hasPrev, err := s.store.DeclarationAt(ctx, tenantID, s.now())
	if err != nil {
		return api.Declaration{}, api.ErrResidencyUnavailable
	}

	// Declaring is a PDP decision asked about the tenant (authz.rego: the tenant's
	// owner and its tenant-scoped platform operator, resource kind tenant). A denial
	// and an unreachable PDP are the same coarse shape — and both are witnessed as
	// exactly one DENIED record naming the actor and both pinnings, because a
	// refusal is the more investigation-relevant half (SPEC-0043 AC1, G5).
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
		if _, werr := s.witness.AppendResidencyRecord(ctx, declarationRecord(tenantID, actorID, roles, cloud, region, prev, hasPrev, true, s.now())); werr != nil {
			// A refusal that cannot be recorded is a failure, not a silent denial
			// (package invariant): the caller sees the same coarse shape either way.
			return api.Declaration{}, api.ErrResidencyUnavailable
		}
		return api.Declaration{}, api.ErrResidencyUnavailable
	}

	// AC3's sweep input is read BEFORE the declaration takes effect (Wave-3
	// review W1): with everything the sweep needs in hand before the commit,
	// no post-commit store failure can report failure for an act that already
	// stands — and fail-closed is preserved, because this read fails while
	// nothing is committed yet. A declaration that cannot know what it
	// contradicts does not happen.
	planes, err := s.store.ObservedPlacements(ctx, tenantID)
	if err != nil {
		return api.Declaration{}, api.ErrResidencyUnavailable
	}

	// The declaration is witnessed BEFORE it takes effect: the record's effective time is
	// the server's clock at witness time — the only instant a pack cites (AC1, AC6). A
	// witness that cannot take the record fails the declaration; an unrecorded declaration
	// is a worse failure than a refused one.
	now := s.now()
	rec, err := s.witness.AppendResidencyRecord(ctx, declarationRecord(tenantID, actorID, roles, cloud, region, prev, hasPrev, false, now))
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
	// gets its own witnessed contradiction record naming both placements. The sweep runs
	// over the placements read BEFORE the commit (Wave-3 review W1): the only failure
	// left on this side of the commit is a witness the trail refuses, and that is
	// logged, never reported — the declaration already stands.
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

// declarationRecord is the one witness entry a declaration act appends — allowed or
// refused. It names tenant, actor, the role the act was decided under, previous and new
// pinning, and the server's effective time (SPEC-0043 AC1, AC7); the record and the
// enforcement cannot disagree because both are built from the same verified facts.
func declarationRecord(tenantID, actorID string, roles []string, cloud, region string, prev api.Declaration, hasPrev, denied bool, at time.Time) api.WitnessEntry {
	detail := map[string]string{
		platformaudit.DetailResidencyPinnedCloud:  cloud,
		platformaudit.DetailResidencyPinnedRegion: region,
		platformaudit.DetailResidencyGrantedRole:  grantedRole(roles),
	}
	if hasPrev {
		detail[platformaudit.DetailResidencyPreviousCloud] = prev.Cloud
		detail[platformaudit.DetailResidencyPreviousRegion] = prev.Region
	}
	return api.WitnessEntry{
		TenantID:   tenantID,
		Action:     platformaudit.ActionResidencyDeclarationSet,
		ActorID:    actorID,
		Resource:   "tenant/" + tenantID,
		Detail:     detail,
		Denied:     denied,
		OccurredAt: at,
	}
}

// grantedRole is the AC7 derivation (ADR-0067 decision 3): the declaration
// record names the role its PDP decision consumed, derived from the verified
// roles the caller held — never a caller claim. A tenant-scoped platform
// operator acts on the tenant's behalf, and vendor involvement is the more
// investigation-relevant half, so it wins when present; otherwise the act is
// the tenant's own (owner). This is audit labeling of a decision ALREADY
// made by the PDP — the decision itself is never re-derived here (invariant
// 2).
func grantedRole(roles []string) string {
	for _, r := range roles {
		if r == "platform_operator" {
			return "platform_operator"
		}
	}
	return "owner"
}

// Declaration implements api.Service. The tenant is the CALLER'S OWN — established at the
// door from a verified principal, or from the enrolment token on the observation path — and
// that is where the scope is enforced: the durable store scopes its transaction from this
// argument, so RLS is evaluated for the tenant asked about and can never itself refuse a
// caller who asks about someone else. What the store does add is a refusal of the one shape
// no caller may express: a tenant argument that contradicts the tenant already on the
// context (postgres.scoped). A cross-tenant read is then the same coarse denial as an absent
// declaration (SPEC-0001). The read is the effective-dated one at the service's clock — the
// same instant enforcement consults (T-0039).
func (s *Service) Declaration(ctx context.Context, tenantID string) (api.Declaration, bool, error) {
	if tenantID == "" {
		return api.Declaration{}, false, api.ErrResidencyUnavailable
	}
	return s.store.DeclarationAt(ctx, tenantID, s.now())
}

// ObservePlacement implements api.Service (SPEC-0040 AC2, AC4). The caller's tenant scope
// is the caller's own: the enrolment path scopes the context after resolving the tenant
// from the token, and the store refuses any mismatch.
func (s *Service) ObservePlacement(ctx context.Context, tenantID, dataPlaneID, cloud, region string) error {
	if tenantID == "" || dataPlaneID == "" {
		return api.ErrResidencyUnavailable
	}
	now := s.now()
	// The gate consults the effective-dated declaration at the service's clock — the
	// durable store's DeclarationAt read, same-instant rows tie-broken on the later
	// chain position (T-0039, SPEC-0042 AC3). A read failure is the coarse failure: an
	// unavailable constraint refuses, never admits (SPEC-0043 AC4).
	decl, ok, err := s.store.DeclarationAt(ctx, tenantID, now)
	if err != nil {
		return api.ErrResidencyUnavailable
	}

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
