// Package app is the auditor grant lifecycle service (T-0027, SPEC-0033).
//
// It is Identity&Access's first application service: issue, revoke and list
// scoped, read-only, time-boxed grants, and serve the two server-side reads
// the enforcement and evidence paths compose on — decision-time grant facts
// for the PEP (SPEC-0033 AC7) and lifecycle transitions for the evidence
// pack's access-changes section (SPEC-0032).
//
// Every lifecycle action is a PDP decision (auditor.grant.manage, asked
// about the tenant, with the grant's scope and expiry as server-derived
// context — the vocabulary governance/policies reviews) and appends the
// immutable audit record AC4 requires, correlated to the decision. A grant
// that cannot be audited is not issued: an unrecorded grant is a worse
// failure than a refused one (ADR-0007).
package app

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gitfrok/backend/modules/identity/api"
	"github.com/gitfrok/backend/modules/identity/internal/domain"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
	platformaudit "github.com/gitfrok/backend/platform/audit"
	"github.com/gitfrok/backend/platform/bus"
	"github.com/gitfrok/backend/platform/ids"
	"github.com/gitfrok/backend/platform/tenancy"
)

// GrantStore persists grant records and their witnessed transitions,
// tenant-scoped. Implementations carry no authorization of their own: the
// service decides before it stores, and RLS scopes every stored row.
type GrantStore interface {
	// FindByRequest returns the grant an earlier issue request created under
	// this tenant's request ID — the idempotent replay answer.
	FindByRequest(ctx context.Context, tenantID, requestID string) (api.AuditorGrant, bool, error)
	// Insert stores one issued grant under its request ID. Inserting a
	// second grant under the same (tenant, request ID) is an error: the
	// store makes a duplicate issue impossible.
	Insert(ctx context.Context, g api.AuditorGrant, requestID string) error
	// Revoke terminates a grant that is still authorizing — stored ACTIVE
	// and strictly before its expiry. ok is false for a nonexistent,
	// already-revoked or expired grant: every one of those is the same
	// coarse denial upstream (SPEC-0001).
	Revoke(ctx context.Context, tenantID, grantID string, at time.Time) (api.AuditorGrant, bool, error)
	// List returns the tenant's grants, optionally narrowed to one auditor
	// principal, in issue order.
	List(ctx context.Context, tenantID, auditorPrincipalID string) ([]api.AuditorGrant, error)
	// FindForRead returns the tenant's grants naming packID that were
	// issued to auditorPrincipalID, in issue order — the PEP's decision-time
	// lookup (SPEC-0033 AC7).
	FindForRead(ctx context.Context, tenantID, auditorPrincipalID, packID string) ([]api.AuditorGrant, error)
	// Transitions returns the witnessed lifecycle transitions whose instant
	// lies within the inclusive range, narrowed to grants scoped to
	// repositoryID when non-empty (an empty grant repository scope covers
	// the tenant's repositories and is included either way), in chain order.
	Transitions(ctx context.Context, tenantID string, from, to time.Time, repositoryID string) ([]api.GrantTransition, error)
	// TransitionRecorded reports whether the (tenant, grant, kind)
	// transition was already witnessed — the pre-check that keeps an expiry
	// from appending a second audit record.
	TransitionRecorded(ctx context.Context, tenantID, grantID string, kind api.GrantTransitionKind) (bool, error)
	// AppendTransition records one witnessed transition. It returns false
	// when the (tenant, grant, kind) transition was already recorded: a
	// transition happens once, whatever observed it twice.
	AppendTransition(ctx context.Context, t api.GrantTransition) (bool, error)
}

// Service is the auditor grant lifecycle service. Safe for concurrent use.
type Service struct {
	pdp    policyapi.DecisionPoint
	events bus.Bus
	trail  api.GrantWitness
	store  GrantStore
	now    func() time.Time

	// expiryMu serializes expiry recognition so one expiry appends exactly
	// one audit record and publishes exactly one event, whatever read path
	// observed it first in this process.
	expiryMu sync.Mutex
}

// New assembles the service on a decision point, an event bus, the witness
// log it appends its immutable records to, and the grant store it persists
// on. All four are required: a grant lifecycle without a PDP would be
// self-authorizing, without a witness it would violate AC4, and without a
// store it would forget its own grants.
func New(pdp policyapi.DecisionPoint, events bus.Bus, trail api.GrantWitness, store GrantStore) *Service {
	if pdp == nil {
		panic("identity grants: no PDP — grant lifecycle actions require authorization")
	}
	if trail == nil {
		panic("identity grants: no witness log — grant lifecycle is accountability evidence (SPEC-0033 AC4)")
	}
	if store == nil {
		panic("identity grants: no store")
	}
	return &Service{
		pdp:    pdp,
		events: events,
		trail:  trail,
		store:  store,
		now:    func() time.Time { return time.Now().UTC() },
	}
}

// IssueGrant implements api.AuditorGrants.
func (s *Service) IssueGrant(ctx context.Context, c api.GrantContext, req api.GrantIssue) (api.AuditorGrant, error) {
	tenant, principal, err := s.authorizedTenant(ctx)
	if err != nil {
		return api.AuditorGrant{}, err
	}

	// Idempotent replay: the same tenant and request ID return the grant the
	// first request created — no second decision, no second audit record.
	if c.RequestID != "" {
		if existing, ok, err := s.store.FindByRequest(ctx, tenant, c.RequestID); err == nil && ok {
			existing.State = domain.DeriveState(existing, s.now())
			return existing, nil
		}
	}

	now := s.now()
	if err := domain.ValidateIssue(req, now); err != nil {
		return api.AuditorGrant{}, api.ErrGrantUnavailable
	}

	// Issuing is a PDP decision asked about the tenant, with the grant's
	// scope and expiry as server-derived context (SPEC-0033 vocabulary
	// table). A denial or an unreachable PDP is the one coarse shape.
	decision, err := s.decide(ctx, tenant, principal, map[string]string{
		"request_id":           c.RequestID,
		"auditor_principal_id": req.AuditorPrincipalID,
		"range_from":           req.RangeFrom.UTC().Format(time.RFC3339Nano),
		"range_to":             req.RangeTo.UTC().Format(time.RFC3339Nano),
		"repository_id":        req.RepositoryID,
		"pack_ids":             strings.Join(req.PackIDs, ","),
		"expires_at":           req.ExpiresAt.UTC().Format(time.RFC3339Nano),
	})
	if err != nil || !decision.Allowed {
		return api.AuditorGrant{}, api.ErrGrantUnavailable
	}

	grant := api.AuditorGrant{
		GrantID:            ids.NewULID(),
		TenantID:           tenant,
		AuditorPrincipalID: req.AuditorPrincipalID,
		RangeFrom:          req.RangeFrom.UTC(),
		RangeTo:            req.RangeTo.UTC(),
		RepositoryID:       req.RepositoryID,
		PackIDs:            append([]string(nil), req.PackIDs...),
		ExpiresAt:          req.ExpiresAt.UTC(),
		GrantedBy:          principal.ActorID,
		IssuedAt:           now,
		State:              api.GrantActive,
	}

	// Issuance appends exactly one immutable audit record naming the
	// granting admin and the auditor principal (SPEC-0033 AC4), correlated
	// to the decision. If the witness cannot take it, the grant is not
	// created: an unrecorded grant is a worse failure than a refused one.
	record, err := s.append(ctx, grant.TenantID, platformaudit.ActionAuditorGrantIssued, principal.ActorID, grant, map[string]string{
		"grant_id":             grant.GrantID,
		"auditor_principal_id": grant.AuditorPrincipalID,
		"granted_by":           grant.GrantedBy,
		"decision_id":          decision.DecisionID,
		"request_id":           c.RequestID,
		"range_from":           grant.RangeFrom.Format(time.RFC3339Nano),
		"range_to":             grant.RangeTo.Format(time.RFC3339Nano),
		"repository_id":        grant.RepositoryID,
		"pack_ids":             strings.Join(grant.PackIDs, ","),
		"expires_at":           grant.ExpiresAt.Format(time.RFC3339Nano),
	}, now)
	if err != nil {
		return api.AuditorGrant{}, api.ErrGrantUnavailable
	}

	if err := s.store.Insert(ctx, grant, c.RequestID); err != nil {
		// A concurrent replay of the same request ID raced us: honour the
		// first writer's grant rather than registering a second.
		if existing, ok, findErr := s.store.FindByRequest(ctx, tenant, c.RequestID); findErr == nil && ok {
			existing.State = domain.DeriveState(existing, s.now())
			return existing, nil
		}
		return api.AuditorGrant{}, api.ErrGrantUnavailable
	}
	if err := s.recordTransition(ctx, api.GrantTransition{
		Kind: api.GrantIssued, ChainSeq: record.Seq, RecordHash: record.Hash,
		GrantID: grant.GrantID, ActorID: principal.ActorID, GrantedBy: grant.GrantedBy,
		AuditorPrincipalID: grant.AuditorPrincipalID, RepositoryID: grant.RepositoryID,
		DecisionID: decision.DecisionID, OccurredAt: now,
	}); err != nil {
		return api.AuditorGrant{}, api.ErrGrantUnavailable
	}

	_ = s.events.Publish(ctx, api.AuditorGrantIssued{
		EventID: ids.NewULID(), TenantID: grant.TenantID, GrantID: grant.GrantID,
		GrantedBy: grant.GrantedBy, AuditorPrincipalID: grant.AuditorPrincipalID,
		RangeFrom: grant.RangeFrom, RangeTo: grant.RangeTo, RepositoryID: grant.RepositoryID,
		PackIDs: append([]string(nil), grant.PackIDs...), ExpiresAt: grant.ExpiresAt,
		DecisionID: decision.DecisionID, OccurredAt: now,
	})
	return cloneGrant(grant), nil
}

// RevokeGrant implements api.AuditorGrants.
func (s *Service) RevokeGrant(ctx context.Context, c api.GrantContext, grantID string) (api.AuditorGrant, error) {
	tenant, principal, err := s.authorizedTenant(ctx)
	if err != nil {
		return api.AuditorGrant{}, err
	}
	if grantID == "" {
		return api.AuditorGrant{}, api.ErrGrantUnavailable
	}

	// Revoking is a PDP decision asked about the tenant (SPEC-0033
	// vocabulary table). The grant itself is named in the context; a denial
	// or an unreachable PDP is the one coarse shape.
	decision, err := s.decide(ctx, tenant, principal, map[string]string{
		"request_id": c.RequestID,
		"grant_id":   grantID,
	})
	if err != nil || !decision.Allowed {
		return api.AuditorGrant{}, api.ErrGrantUnavailable
	}

	now := s.now()
	// Not-found, cross-tenant (RLS-invisible), already-revoked and expired
	// are all ok=false here — the same coarse denial (SPEC-0001).
	stored, ok, err := s.store.Revoke(ctx, tenant, grantID, now)
	if err != nil || !ok {
		return api.AuditorGrant{}, api.ErrGrantUnavailable
	}
	stored.RevokedAt = now
	stored.State = api.GrantRevoked

	// Revocation appends the immutable audit record naming the revoking
	// admin, the granting admin and the auditor principal (SPEC-0033 AC4).
	record, err := s.append(ctx, tenant, platformaudit.ActionAuditorGrantRevoked, principal.ActorID, stored, map[string]string{
		"grant_id":             stored.GrantID,
		"auditor_principal_id": stored.AuditorPrincipalID,
		"granted_by":           stored.GrantedBy,
		"decision_id":          decision.DecisionID,
		"request_id":           c.RequestID,
	}, now)
	if err != nil {
		return api.AuditorGrant{}, api.ErrGrantUnavailable
	}
	if err := s.recordTransition(ctx, api.GrantTransition{
		Kind: api.GrantRevocation, ChainSeq: record.Seq, RecordHash: record.Hash,
		GrantID: stored.GrantID, ActorID: principal.ActorID, GrantedBy: stored.GrantedBy,
		AuditorPrincipalID: stored.AuditorPrincipalID, RepositoryID: stored.RepositoryID,
		DecisionID: decision.DecisionID, OccurredAt: now,
	}); err != nil {
		return api.AuditorGrant{}, api.ErrGrantUnavailable
	}

	// Revocation takes effect on the next decision — the state above is a
	// fact the PEP reads fresh, not a cached outcome to invalidate
	// (SPEC-0033 AC7). The event announces the transition.
	_ = s.events.Publish(ctx, api.AuditorGrantRevoked{
		EventID: ids.NewULID(), TenantID: tenant, GrantID: stored.GrantID,
		ActorID: principal.ActorID, GrantedBy: stored.GrantedBy,
		AuditorPrincipalID: stored.AuditorPrincipalID,
		DecisionID:         decision.DecisionID, OccurredAt: now,
	})
	return cloneGrant(stored), nil
}

// ListGrants implements api.AuditorGrants.
func (s *Service) ListGrants(ctx context.Context, c api.GrantContext, auditorPrincipalID string) ([]api.AuditorGrant, error) {
	tenant, principal, err := s.authorizedTenant(ctx)
	if err != nil {
		return nil, err
	}

	// Listing is the same owner-only decision (SPEC-0033: issuing, revoking
	// AND listing are auditor.grant.manage); a cross-tenant or unauthorized
	// list is the same coarse denial as an empty one.
	decision, err := s.decide(ctx, tenant, principal, map[string]string{
		"request_id":           c.RequestID,
		"auditor_principal_id": auditorPrincipalID,
	})
	if err != nil || !decision.Allowed {
		return nil, api.ErrGrantUnavailable
	}

	grants, err := s.store.List(ctx, tenant, auditorPrincipalID)
	if err != nil {
		return nil, api.ErrGrantUnavailable
	}
	now := s.now()
	out := make([]api.AuditorGrant, 0, len(grants))
	for _, g := range grants {
		s.recognizeExpiry(ctx, g)
		g.State = domain.DeriveState(g, now)
		out = append(out, cloneGrant(g))
	}
	return out, nil
}

// GrantFacts implements api.AuditorGrants: the grant's validity facts, read
// fresh at decision time (SPEC-0033 AC7).
func (s *Service) GrantFacts(ctx context.Context, auditorPrincipalID, packID string) (api.GrantDecisionFacts, bool, error) {
	tenant, err := tenancy.Require(ctx)
	if err != nil {
		return api.GrantDecisionFacts{}, false, err
	}
	if auditorPrincipalID == "" || packID == "" {
		return api.GrantDecisionFacts{}, false, nil
	}
	grants, err := s.store.FindForRead(ctx, string(tenant), auditorPrincipalID, packID)
	if err != nil {
		return api.GrantDecisionFacts{}, false, api.ErrGrantUnavailable
	}
	if len(grants) == 0 {
		return api.GrantDecisionFacts{}, false, nil
	}

	now := s.now()
	for i := range grants {
		s.recognizeExpiry(ctx, grants[i])
		grants[i].State = domain.DeriveState(grants[i], now)
	}
	// Prefer a grant that is still authorizing; when several name the pack,
	// the one expiring latest governs. Otherwise the most recently issued
	// grant's facts still travel — its REVOKED or EXPIRED state is exactly
	// the fact that denies the decision.
	var pick *api.AuditorGrant
	for i := range grants {
		g := &grants[i]
		if g.State == api.GrantActive {
			if pick == nil || pick.State != api.GrantActive || g.ExpiresAt.After(pick.ExpiresAt) {
				pick = g
			}
		} else if pick == nil || (pick.State != api.GrantActive && g.IssuedAt.After(pick.IssuedAt)) {
			pick = g
		}
	}
	if pick == nil {
		return api.GrantDecisionFacts{}, false, nil
	}
	return api.GrantDecisionFacts{
		GrantID:   pick.GrantID,
		State:     pick.State,
		TenantID:  pick.TenantID,
		ExpiresAt: pick.ExpiresAt,
		RangeFrom: pick.RangeFrom,
		RangeTo:   pick.RangeTo,
		Packs:     append([]string(nil), pick.PackIDs...),
	}, true, nil
}

// GrantTransitions implements api.AuditorGrants: the witnessed lifecycle
// transitions the evidence pack's access-changes section cites.
func (s *Service) GrantTransitions(ctx context.Context, tenantID string, from, to time.Time, repositoryID string) ([]api.GrantTransition, error) {
	tenant, err := tenancy.Require(ctx)
	if err != nil {
		return nil, err
	}
	// The surrounding request's tenant scope must match the tenant asked
	// about; a mismatch is the same coarse shape as an empty answer.
	if string(tenant) != tenantID || tenantID == "" {
		return nil, api.ErrGrantUnavailable
	}
	transitions, err := s.store.Transitions(ctx, tenantID, from, to, repositoryID)
	if err != nil {
		return nil, api.ErrGrantUnavailable
	}
	out := append([]api.GrantTransition(nil), transitions...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].ChainSeq < out[j].ChainSeq })
	return out, nil
}

// authorizedTenant resolves the verified caller and checks the request is
// operating inside its own tenant — the same guard the credential lifecycle
// applies (SPEC-0006).
func (s *Service) authorizedTenant(ctx context.Context) (string, api.Principal, error) {
	tenant, err := tenancy.Require(ctx)
	if err != nil {
		return "", api.Principal{}, err
	}
	principal, err := api.RequirePrincipal(ctx)
	if err != nil {
		return "", api.Principal{}, err
	}
	if principal.TenantID != string(tenant) {
		return "", api.Principal{}, api.ErrTenantMismatch
	}
	return string(tenant), principal, nil
}

// decide asks the PDP for auditor.grant.manage about the tenant, with the
// caller's verified subject and server-derived context. A non-nil error is a
// refusal, not an answer to inspect (ADR-0006).
func (s *Service) decide(ctx context.Context, tenant string, principal api.Principal, pctx map[string]string) (policyapi.Decision, error) {
	return s.pdp.Decide(ctx, policyapi.Request{
		TenantID: tenant,
		Subject:  policyapi.Subject{ID: principal.ActorID, TenantID: principal.TenantID, Roles: append([]string(nil), principal.Roles...)},
		Action:   platformaudit.ActionAuditorGrantManage,
		Resource: policyapi.Resource{Type: "tenant", ID: tenant},
		Context:  pctx,
	})
}

// append writes one first-party record to the tenant's witness log and
// returns the record as persisted — the chain position the transition cites.
// The composition root renders outcome and provenance when it adapts the
// tenant's audit trail onto this port: a lifecycle transition is always an
// authorized, first-party fact.
func (s *Service) append(ctx context.Context, tenant, action, actor string, grant api.AuditorGrant, detail map[string]string, at time.Time) (api.GrantWitnessRecord, error) {
	return s.trail.AppendGrantRecord(tenancy.WithTenant(ctx, tenancy.ID(tenant)), api.GrantWitnessEntry{
		TenantID:   tenant,
		Action:     action,
		ActorID:    actor,
		Resource:   "auditor_grant/" + grant.GrantID,
		Detail:     detail,
		OccurredAt: at,
	})
}

// recordTransition stores one witnessed transition; the store's uniqueness
// is what makes a transition happen once.
func (s *Service) recordTransition(ctx context.Context, t api.GrantTransition) error {
	if _, err := s.store.AppendTransition(ctx, t); err != nil {
		return err
	}
	return nil
}

// recognizeExpiry records a grant's expiry the first time any read path
// observes it past its expiry — without an operator action (SPEC-0033 AC3).
// The expiry is itself a lifecycle fact: one immutable audit record naming
// the granting admin and the auditor principal, one transition, one event.
func (s *Service) recognizeExpiry(ctx context.Context, g api.AuditorGrant) {
	now := s.now()
	if !g.RevokedAt.IsZero() || now.Before(g.ExpiresAt) {
		return
	}
	s.expiryMu.Lock()
	defer s.expiryMu.Unlock()

	// Already witnessed — by this read path or another: an expiry is one
	// transition, one audit record, one event.
	if recorded, err := s.store.TransitionRecorded(ctx, g.TenantID, g.GrantID, api.GrantExpiration); err != nil || recorded {
		return
	}

	// Append the audit record first so the transition cites real chain
	// positions. A distinct plane racing this one can still land a second
	// record in the append window; the store's unique transition then keeps
	// exactly one transition citing exactly one of them. Within a process
	// expiryMu makes the race impossible.
	record, err := s.append(ctx, g.TenantID, platformaudit.ActionAuditorGrantExpired, "", g, map[string]string{
		"grant_id":             g.GrantID,
		"auditor_principal_id": g.AuditorPrincipalID,
		"granted_by":           g.GrantedBy,
		"expires_at":           g.ExpiresAt.Format(time.RFC3339Nano),
	}, now)
	if err != nil {
		return // an unrecordable expiry still expires: decisions read the clock
	}
	recorded, err := s.store.AppendTransition(ctx, api.GrantTransition{
		Kind: api.GrantExpiration, ChainSeq: record.Seq, RecordHash: record.Hash,
		GrantID: g.GrantID, GrantedBy: g.GrantedBy,
		AuditorPrincipalID: g.AuditorPrincipalID, RepositoryID: g.RepositoryID,
		OccurredAt: now,
	})
	if err != nil || !recorded {
		return
	}
	_ = s.events.Publish(ctx, api.AuditorGrantExpired{
		EventID: ids.NewULID(), TenantID: g.TenantID, GrantID: g.GrantID,
		GrantedBy: g.GrantedBy, AuditorPrincipalID: g.AuditorPrincipalID, OccurredAt: now,
	})
}

func cloneGrant(g api.AuditorGrant) api.AuditorGrant {
	g.PackIDs = append([]string(nil), g.PackIDs...)
	return g
}

var _ api.AuditorGrants = (*Service)(nil)
