// Package app is the evidence pack assembler (T-0026, SPEC-0031, SPEC-0032).
//
// It is the Audit context's first read-side application service: request a
// date-ranged pack, observe its assembly, retrieve it. Every shape of the
// answer is server-determined — a caller names a range, never records — and
// every operation is a PDP decision with server-derived context, itself
// audited (SPEC-0032 AC6).
//
// Sections assemble through contract surfaces and the event-fed projection,
// never by reading another context's tables (ADR-0022): the three sections
// with a projection today are classified out of the tenant's own audit chain
// — the chain IS the projection the owning contexts feed through auditsink —
// and the access-changes section reads Identity & Access's contract surface
// through the api.AccessChangesSource port, wired since T-0027 to the
// auditor-grant lifecycle. A plane composing no source still degrades the
// section per contract: an explicit gap marker over the range, never a
// partial section presented as complete (SPEC-0031 AC10).
package app

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/gitfrok/backend/modules/audit/api"
	"github.com/gitfrok/backend/modules/audit/internal/domain"
	identityapi "github.com/gitfrok/backend/modules/identity/api"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
	platformaudit "github.com/gitfrok/backend/platform/audit"
	"github.com/gitfrok/backend/platform/bus"
	"github.com/gitfrok/backend/platform/ids"
	"github.com/gitfrok/backend/platform/tenancy"
)

// auditorRole is the principal kind SPEC-0033 reads evidence through: the
// role table grants it NOTHING — its pack reads are decided solely on the
// grant facts this service composes fresh into every evidence.pack.read
// decision (governance/policies authz.rego, T-0027).
const auditorRole = "auditor"

// Service is the evidence pack assembler. Safe for concurrent use.
type Service struct {
	pdp      policyapi.DecisionPoint
	events   bus.Bus
	trail    api.TrailStore
	now      func() time.Time
	attested api.AttestedHistorySource
	access   api.AccessChangesSource
	// grants is Identity & Access's auditor grant surface (T-0027, SPEC-0033):
	// the decision-time facts source an auditor principal's pack read composes
	// fresh on every decision. nil means the plane has no grant surface, so
	// every auditor pack read fails closed — member principals are unaffected.
	grants identityapi.AuditorGrants

	mu    sync.Mutex
	packs map[string]*packEntry
	// idempotency keys (tenant|requestID|range|scope) onto reservations: the
	// key is RESERVED under the mutex before any side effect, so concurrent
	// duplicates wait on the first writer and replay its result instead of
	// each taking a PDP decision and appending an audit record (SPEC-0032
	// AC1) — a rolled-back reservation replays its failure to every
	// concurrent duplicate. A completed reservation stays registered as the
	// replay record forever; a rolled-back one leaves the map when its last
	// waiter has observed the failure — that is when the key is released
	// for a fresh attempt.
	byIDKey map[string]*packReservation
}

// packReservation is one idempotency key's in-flight or recorded state. The
// first writer reserves it under the service mutex before the PDP decision
// and the trail append; concurrent duplicates block on done and replay the
// first writer's outcome — never a second decision or audit record
// (SPEC-0032 AC1). done is closed exactly once, after packID/registered or
// err is final.
type packReservation struct {
	done chan struct{}
	// packID and registered are final once done is closed with no err.
	packID     string
	registered bool
	// err is set when the reservation rolled back (decision denied or append
	// failed): waiters see the same coarse failure, and the key is released
	// once no waiter is left holding it.
	err error
	// waiters counts requests still holding the reservation: the reservation
	// itself plus every duplicate queued on it. When it reaches zero the
	// reservation leaves byIDKey — the key's release point.
	waiters int
}

// packEntry is one pack under assembly or assembled. The header fields are
// set when the pack is requested; sections and appendix land as assembly
// progresses; state is the lifecycle the status surface reports.
type packEntry struct {
	pack          api.Pack
	state         api.PackState
	failureReason string
	// liveCounts and liveGaps are the per-section assembly view, updated as
	// sections land (SPEC-0031 non-functional: observable per section).
	liveCounts map[api.SectionType]int64
	liveGaps   map[api.SectionType][]api.SectionGap
}

// New assembles the service on a decision point, an event bus and the trail
// it reads and audits to. attested, access and grants may be nil: a nil
// attested source means the plane has no import surface, so an empty appendix
// is the truthful answer; a nil access source degrades the access-changes
// section into an explicit gap (SPEC-0031 AC10); a nil grants source fails
// every auditor pack read closed (SPEC-0033), which is the only honest answer
// for a plane with no grant surface.
func New(pdp policyapi.DecisionPoint, events bus.Bus, trail api.TrailStore,
	attested api.AttestedHistorySource, access api.AccessChangesSource,
	grants identityapi.AuditorGrants) *Service {
	return &Service{
		pdp:      pdp,
		events:   events,
		trail:    trail,
		now:      func() time.Time { return time.Now().UTC() },
		attested: attested,
		access:   access,
		grants:   grants,
		packs:    map[string]*packEntry{},
		byIDKey:  map[string]*packReservation{},
	}
}

// RequestPack implements api.PackService.
func (s *Service) RequestPack(ctx context.Context, c api.Context, req api.PackRequest) (string, api.PackState, error) {
	if err := validateContext(c); err != nil {
		return "", 0, err
	}
	if req.RangeFrom.IsZero() || req.RangeTo.IsZero() || req.RangeFrom.After(req.RangeTo) {
		return "", 0, fmt.Errorf("%w: the range is closed — both bounds required, from not after to", api.ErrInvalidPackRequest)
	}

	// Idempotent replay, race-proof (SPEC-0032 AC1): the key is RESERVED
	// under the mutex before any side effect. A completed reservation
	// replays the first writer's pack; an in-flight one blocks its
	// duplicates until the first writer finishes, then serves that outcome —
	// no second pack, no second PDP decision, no second audit record.
	idKey := fmt.Sprintf("%s|%s|%s|%s|%s", c.TenantID, c.RequestID,
		req.RangeFrom.UTC().Format(time.RFC3339Nano), req.RangeTo.UTC().Format(time.RFC3339Nano), req.RepositoryID)
	s.mu.Lock()
	if res, ok := s.byIDKey[idKey]; ok {
		res.waiters++
		s.mu.Unlock()
		<-res.done
		if res.err != nil {
			// The first writer rolled back; its failure is the answer, and
			// this duplicate releases the key when it was the last holder.
			err := res.err
			s.releaseReservation(idKey, res)
			return "", 0, err
		}
		s.mu.Lock()
		state := s.packs[res.packID].state
		s.mu.Unlock()
		// A completed reservation stays registered: later duplicates replay
		// it forever — that is the idempotency of SPEC-0032 AC1.
		return res.packID, state, nil
	}
	res := &packReservation{done: make(chan struct{}), waiters: 1}
	s.byIDKey[idKey] = res
	s.mu.Unlock()

	// Generation is a PDP decision asked about the tenant, with the range
	// bounds and repository scope as server-derived context (SPEC-0032
	// vocabulary table). A denial or an unreachable PDP is the same coarse
	// shape as every other failed pack operation: the denial itself is
	// audited by the policy surface, never by a second record here. The
	// reservation rolls back: a later retry may ask again.
	decision, err := s.decide(ctx, c, platformaudit.ActionEvidencePackGenerate,
		policyapi.Resource{Type: "tenant", ID: c.TenantID}, map[string]string{
			"range_from":    req.RangeFrom.UTC().Format(time.RFC3339Nano),
			"range_to":      req.RangeTo.UTC().Format(time.RFC3339Nano),
			"repository_id": req.RepositoryID,
		})
	if err != nil || !decision.Allowed {
		s.rollbackReservation(idKey, res, api.ErrPackUnavailable)
		return "", 0, api.ErrPackUnavailable
	}

	now := s.now()
	packID := ids.NewULID()
	entry := &packEntry{
		pack: api.Pack{
			PackID:       packID,
			TenantID:     c.TenantID,
			RangeFrom:    req.RangeFrom,
			RangeTo:      req.RangeTo,
			RepositoryID: req.RepositoryID,
			RequestedBy:  c.ActorID,
			DecisionID:   decision.DecisionID,
			GeneratedAt:  now,
			Appendix:     api.Appendix{Label: api.AppendixLabel},
		},
		state:      api.PackPending,
		liveCounts: map[api.SectionType]int64{},
		liveGaps:   map[api.SectionType][]api.SectionGap{},
	}

	// Generation appends exactly one immutable audit record correlated to the
	// decision ID (SPEC-0032 AC6). If the trail cannot take it, the pack is
	// not created: an unaudited export is a worse failure than a refused one.
	// The reservation rolls back with the failure, so no in-flight sentinel
	// outlives the attempt.
	if _, err := s.trail.Append(tenancy.WithTenant(ctx, tenancy.ID(c.TenantID)), api.Entry{
		TenantID: c.TenantID,
		Action:   api.Action(platformaudit.ActionEvidencePackGenerate),
		ActorID:  c.ActorID,
		Resource: "tenant/" + c.TenantID,
		Outcome:  api.OutcomeAllowed,
		Detail: map[string]string{
			"pack_id":       packID,
			"decision_id":   decision.DecisionID,
			"request_id":    c.RequestID,
			"range_from":    req.RangeFrom.UTC().Format(time.RFC3339Nano),
			"range_to":      req.RangeTo.UTC().Format(time.RFC3339Nano),
			"repository_id": req.RepositoryID,
		},
		OccurredAt: now,
		Provenance: api.ProvenanceFirstParty,
	}); err != nil {
		appendErr := fmt.Errorf("audit: recording evidence pack generation: %w", err)
		s.rollbackReservation(idKey, res, appendErr)
		return "", 0, appendErr
	}

	// Registration completes ONLY after the trail accepted the audit record:
	// the pack becomes visible and the reservation becomes the PERMANENT
	// replay record for this idempotency key (SPEC-0032 AC1).
	s.mu.Lock()
	s.packs[packID] = entry
	res.packID = packID
	res.registered = true
	close(res.done)
	s.mu.Unlock()

	// The lifecycle events carry identifiers, scope, bounds and counts —
	// never record contents (SPEC-0032 G9).
	_ = s.events.Publish(ctx, platformaudit.EvidencePackRequested{
		EventID: ids.NewULID(), TenantID: c.TenantID, ActorID: c.ActorID,
		PackID: packID, RequestID: c.RequestID,
		RangeFrom: req.RangeFrom, RangeTo: req.RangeTo, RepositoryID: req.RepositoryID,
		OccurredAt: now,
	})

	go s.assemble(packID)
	return packID, api.PackPending, nil
}

// rollbackReservation records one failed attempt on its reservation and
// wakes every waiter with the same coarse failure. The reservation stays in
// byIDKey until its last waiter has observed the outcome — that is when the
// key is released and a later retry can become the first writer of a fresh
// attempt. Releasing it here instead would let a concurrent duplicate sneak
// a fresh attempt in while waiters are still blocked (SPEC-0032 AC1).
func (s *Service) rollbackReservation(idKey string, res *packReservation, err error) {
	s.mu.Lock()
	res.err = err
	s.releaseLocked(idKey, res)
	close(res.done)
	s.mu.Unlock()
}

// releaseReservation drops the caller's hold on a reservation after it
// observed the outcome.
func (s *Service) releaseReservation(idKey string, res *packReservation) {
	s.mu.Lock()
	s.releaseLocked(idKey, res)
	s.mu.Unlock()
}

// releaseLocked drops one hold on a reservation; the caller owns s.mu. When
// no holder is left the reservation leaves byIDKey: the idempotency key is
// released.
func (s *Service) releaseLocked(idKey string, res *packReservation) {
	res.waiters--
	if res.waiters == 0 && s.byIDKey[idKey] == res {
		delete(s.byIDKey, idKey)
	}
}

// PackStatus implements api.PackService.
func (s *Service) PackStatus(ctx context.Context, c api.Context, packID string) (api.PackStatus, error) {
	if err := validateContext(c); err != nil {
		return api.PackStatus{}, err
	}
	entry, err := s.authorizedPack(ctx, c, packID)
	if err != nil {
		return api.PackStatus{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	st := api.PackStatus{
		State:         entry.state,
		FailureReason: entry.failureReason,
		RangeFrom:     entry.pack.RangeFrom,
		RangeTo:       entry.pack.RangeTo,
		RepositoryID:  entry.pack.RepositoryID,
	}
	for _, section := range api.AllSectionTypes {
		ss := api.SectionStatus{Type: section, RecordCount: entry.liveCounts[section], Gaps: entry.liveGaps[section]}
		if entry.state == api.PackReady {
			// Final truth once assembled: the sections themselves.
			for _, sec := range entry.pack.Sections {
				if sec.Type == section {
					ss.RecordCount = int64(len(sec.Records))
					ss.Gaps = sec.Gaps
				}
			}
		}
		st.SectionCounts = append(st.SectionCounts, ss)
	}
	st.AppendixRecordCount = appendixCount(entry.pack.Appendix)
	return st, nil
}

// GetPack implements api.PackService: the READY pack as its bounded chunk
// sequence (SPEC-0032 streaming shape). Not-ready, nonexistent, cross-tenant
// and unauthorized are one coarse denial.
func (s *Service) GetPack(ctx context.Context, c api.Context, packID string) ([]api.PackChunk, error) {
	if err := validateContext(c); err != nil {
		return nil, err
	}
	entry, err := s.authorizedPack(ctx, c, packID)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if entry.state != api.PackReady {
		return nil, api.ErrPackUnavailable
	}
	return domain.Chunks(entry.pack), nil
}

// authorizedPack resolves one pack under both guards: tenancy and policy.
// The lookup is tenant-scoped first, so a cross-tenant pack is invisible
// before policy is ever asked; either failure is the same coarse denial
// (SPEC-0001, SPEC-0032 AC5).
func (s *Service) authorizedPack(ctx context.Context, c api.Context, packID string) (*packEntry, error) {
	if packID == "" {
		return nil, api.ErrPackUnavailable
	}
	s.mu.Lock()
	entry, ok := s.packs[packID]
	scoped := ok && entry.pack.TenantID == c.TenantID
	var state api.PackState
	var rangeFrom, rangeTo time.Time
	if scoped {
		state = entry.state
		rangeFrom, rangeTo = entry.pack.RangeFrom, entry.pack.RangeTo
	}
	s.mu.Unlock()
	if !scoped {
		return nil, api.ErrPackUnavailable
	}

	// Retrieval (and status reads) are PDP decisions asked about the pack
	// itself, with tenant, range bounds and pack state as server-derived
	// context (SPEC-0032 vocabulary table).
	decision, err := s.decide(ctx, c, platformaudit.ActionEvidencePackRead,
		policyapi.Resource{Type: "evidence_pack", ID: packID}, map[string]string{
			"tenant_id":  c.TenantID,
			"range_from": rangeFrom.UTC().Format(time.RFC3339Nano),
			"range_to":   rangeTo.UTC().Format(time.RFC3339Nano),
			"pack_state": state.String(),
		})
	if err != nil || !decision.Allowed {
		return nil, api.ErrPackUnavailable
	}
	return entry, nil
}

// decide asks the PDP with the verified subject the context carries. A
// non-nil error is a refusal, not an answer to inspect (ADR-0006): the zero
// Decision denies, and this service maps both to the coarse shape.
//
// T-0027 / SPEC-0033 AC7: when an auditor principal asks to read a pack, the
// decision is composed with the grant's validity facts read FRESH from
// Identity & Access on this very request — never cached, never a caller
// claim. A facts source that is absent or failing refuses the decision here,
// fail-closed, before the PDP is ever asked.
func (s *Service) decide(ctx context.Context, c api.Context, action string, res policyapi.Resource, pctx map[string]string) (policyapi.Decision, error) {
	if action == platformaudit.ActionEvidencePackRead && res.Type == "evidence_pack" && hasRole(c.ActorRoles, auditorRole) { //arch:allow-inline-authz selects which facts the PDP decision is composed with; only the PDP decides access
		composed, ok := s.composeGrantFacts(ctx, c, res.ID, pctx)
		if !ok {
			return policyapi.Decision{}, nil
		}
		pctx = composed
	}
	return s.pdp.Decide(ctx, policyapi.Request{
		TenantID: c.TenantID,
		Subject:  policyapi.Subject{ID: c.ActorID, TenantID: c.TenantID, Roles: c.ActorRoles},
		Action:   action,
		Resource: res,
		Context:  pctx,
	})
}

// composeGrantFacts renders the decision-time grant facts the merged policy's
// auditor grant rule consumes (governance/policies authz.rego, T-0027) into a
// copy of the decision context: grant identity, state, tenant, expiry, range
// bounds and named packs, plus the pack's own range and the instant the
// decision was requested. The read goes to Identity & Access on every call —
// a revoked or expired grant therefore fails this very decision by
// construction, because its state arrives here fresh (SPEC-0033 AC7).
//
// ok is false only when the facts SOURCE is absent or failing — a fail-closed
// refusal. A principal with no matching grant is distinct: absent facts still
// travel to the PDP, so deny-by-default denies and the denial is recorded by
// the policy surface like every other decision (SPEC-0033).
func (s *Service) composeGrantFacts(ctx context.Context, c api.Context, packID string, pctx map[string]string) (map[string]string, bool) {
	if s.grants == nil {
		return nil, false
	}
	// The pack's own bounds, as this service derived them from its records —
	// the policy compares them against the grant's range (SPEC-0033 AC6).
	packFrom, packTo := pctx["range_from"], pctx["range_to"]
	if packFrom == "" || packTo == "" {
		return nil, false
	}
	facts, ok, err := s.grants.GrantFacts(tenancy.WithTenant(ctx, tenancy.ID(c.TenantID)), c.ActorID, packID)
	if err != nil {
		return nil, false
	}
	composed := make(map[string]string, len(pctx)+10)
	for k, v := range pctx {
		composed[k] = v
	}
	composed["decision_time"] = s.now().UTC().Format(time.RFC3339Nano)
	composed["pack_range_from"] = packFrom
	composed["pack_range_to"] = packTo
	if ok {
		composed["auditor_grant_id"] = facts.GrantID
		composed["auditor_grant_state"] = string(facts.State)
		composed["auditor_grant_tenant"] = facts.TenantID
		composed["auditor_grant_expires_at"] = facts.ExpiresAt.UTC().Format(time.RFC3339Nano)
		composed["auditor_grant_range_from"] = facts.RangeFrom.UTC().Format(time.RFC3339Nano)
		composed["auditor_grant_range_to"] = facts.RangeTo.UTC().Format(time.RFC3339Nano)
		composed["auditor_grant_packs"] = strings.Join(facts.Packs, ",")
	}
	return composed, true
}

func hasRole(roles []string, want string) bool { //arch:allow-inline-authz input-shape selection for the PDP request, never an access decision
	for _, r := range roles {
		if r == want {
			return true
		}
	}
	return false
}

// assemble builds one pack's sections, updating the live status as each
// lands, then publishes the completion event. It runs on its own goroutine
// with the pack's tenant scope: assembly is asynchronous, and a large range
// must not block the request that started it (SPEC-0031 non-functional).
func (s *Service) assemble(packID string) {
	s.mu.Lock()
	entry := s.packs[packID]
	if entry == nil {
		s.mu.Unlock()
		return
	}
	entry.state = api.PackAssembling
	pack := entry.pack
	s.mu.Unlock()

	ctx := tenancy.WithTenant(context.Background(), tenancy.ID(pack.TenantID))
	sections, appendix, appendixRecords, failReason := s.assembleSections(ctx, entry, pack)

	s.mu.Lock()
	if failReason != "" {
		entry.state = api.PackFailed
		entry.failureReason = failReason
	} else {
		entry.pack.Sections = sections
		entry.pack.Appendix = appendix
		entry.state = api.PackReady
	}
	finalState := entry.state
	s.mu.Unlock()

	counts := map[string]int64{}
	for _, sec := range sections {
		counts[sec.Type.String()] = int64(len(sec.Records))
	}
	if failReason != "" {
		for _, st := range api.AllSectionTypes {
			counts[st.String()] = 0
		}
	}
	_ = s.events.Publish(ctx, platformaudit.EvidencePackCompleted{
		EventID: ids.NewULID(), TenantID: pack.TenantID, ActorID: pack.RequestedBy,
		PackID: packID, State: finalState.String(),
		SectionCounts: counts, AppendixRecordCount: appendixRecords,
		RangeFrom: pack.RangeFrom, RangeTo: pack.RangeTo, OccurredAt: s.now(),
	})
}

// assembleSections builds the four control sections and the appendix. The
// three trail-fed sections classify out of the tenant's chain; the
// access-changes section reads the identity surface port, degrading into an
// explicit gap when no such surface is wired; the appendix reads the
// attested-history port, empty when the plane has no import surface.
func (s *Service) assembleSections(ctx context.Context, entry *packEntry, pack api.Pack) ([]api.Section, api.Appendix, int64, string) {
	records, err := s.trail.Query(ctx, api.TrailQuery{
		From: pack.RangeFrom, To: pack.RangeTo, RepositoryID: pack.RepositoryID,
	})
	if err != nil {
		return nil, api.Appendix{}, 0, fmt.Sprintf("trail query failed: %v", err)
	}

	sections := domain.AssembleSections(records, pack.RepositoryID)

	// Access changes: Identity & Access's own surface, or the honest degraded
	// shape — a gap over the whole range, SOURCE_UNAVAILABLE. A section that
	// cannot be assembled says so; it never presents silence as completeness.
	if s.access != nil {
		recs, err := s.access.AccessChanges(ctx, pack.TenantID, pack.RangeFrom, pack.RangeTo, pack.RepositoryID)
		if err != nil {
			s.setLive(entry, api.SectionAccessChanges, 0, []api.SectionGap{{From: pack.RangeFrom, To: pack.RangeTo, Reason: api.GapSourceUnavailable}})
			sections = append(sections, degradedAccessSection(pack))
		} else {
			s.setLive(entry, api.SectionAccessChanges, int64(len(recs)), nil)
			sections = append(sections, api.Section{
				Type:          api.SectionAccessChanges,
				Anchor:        domain.AnchorWithPrev(recs, ""),
				Records:       recs,
				Complete:      true,
				RecordsDigest: domain.RecordsDigest(recs),
			})
		}
	} else {
		s.setLive(entry, api.SectionAccessChanges, 0, []api.SectionGap{{From: pack.RangeFrom, To: pack.RangeTo, Reason: api.GapSourceUnavailable}})
		sections = append(sections, degradedAccessSection(pack))
	}

	// Update the live view for the trail-fed sections as they stand.
	for _, sec := range sections {
		if sec.Type != api.SectionAccessChanges {
			s.setLive(entry, sec.Type, int64(len(sec.Records)), sec.Gaps)
		}
	}

	// The appendix: attested imported history, representable ONLY here. A nil
	// source means the plane has no import surface at all, and an empty
	// appendix is then the truthful answer; a source that fails is a failed
	// pack — the appendix can never silently drop what it was told to carry.
	appendix := api.Appendix{Label: api.AppendixLabel}
	var appendixRecords int64
	if s.attested != nil {
		groups, err := s.attested.AttestedHistory(ctx, pack.TenantID, pack.RangeFrom, pack.RangeTo, pack.RepositoryID)
		if err != nil {
			return nil, appendix, 0, fmt.Sprintf("attested history source failed: %v", err)
		}
		appendix.Groups = groups
		for _, g := range groups {
			appendixRecords += int64(len(g.Records))
		}
	}
	return sections, appendix, appendixRecords, ""
}

// degradedAccessSection is the access-changes section when its source surface
// is absent or failing: complete=false with one gap over the whole range —
// never an empty section rendered as complete (SPEC-0031 AC10).
func degradedAccessSection(pack api.Pack) api.Section {
	return api.Section{
		Type:     api.SectionAccessChanges,
		Complete: false,
		Gaps: []api.SectionGap{{
			From: pack.RangeFrom, To: pack.RangeTo, Reason: api.GapSourceUnavailable,
		}},
		RecordsDigest: domain.RecordsDigest(nil),
	}
}

// setLive updates one section's observable assembly state.
func (s *Service) setLive(entry *packEntry, st api.SectionType, count int64, gaps []api.SectionGap) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry.liveCounts[st] = count
	entry.liveGaps[st] = gaps
}

func validateContext(c api.Context) error {
	if c.TenantID == "" || c.ActorID == "" || c.RequestID == "" {
		return fmt.Errorf("%w: tenant, actor and request ID are required; an empty context is a coarse denial", api.ErrInvalidPackRequest)
	}
	return nil
}

func appendixCount(a api.Appendix) int64 {
	var n int64
	for _, g := range a.Groups {
		n += int64(len(g.Records))
	}
	return n
}
