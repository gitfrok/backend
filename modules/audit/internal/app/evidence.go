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
// through the api.AccessChangesSource port. No such surface exists yet (the
// auditor-grant lifecycle is a later task), so a plane composes none and the
// section degrades per contract: an explicit gap marker over the range,
// never a partial section presented as complete (SPEC-0031 AC10).
package app

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/gitfrok/backend/modules/audit/api"
	"github.com/gitfrok/backend/modules/audit/internal/domain"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
	platformaudit "github.com/gitfrok/backend/platform/audit"
	"github.com/gitfrok/backend/platform/bus"
	"github.com/gitfrok/backend/platform/ids"
	"github.com/gitfrok/backend/platform/tenancy"
)

// Service is the evidence pack assembler. Safe for concurrent use.
type Service struct {
	pdp     policyapi.DecisionPoint
	events  bus.Bus
	trail   api.TrailStore
	now     func() time.Time
	attested api.AttestedHistorySource
	access   api.AccessChangesSource

	mu   sync.Mutex
	packs map[string]*packEntry
	// idempotency keys (tenant|requestID|range|scope) onto pack IDs: replaying
	// a request returns the same pack and creates no second pack or audit
	// record (SPEC-0032 AC1).
	byIDKey map[string]string
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
// it reads and audits to. attested and access may be nil: a nil attested
// source means the plane has no import surface, so an empty appendix is the
// truthful answer; a nil access source degrades the access-changes section
// into an explicit gap (SPEC-0031 AC10).
func New(pdp policyapi.DecisionPoint, events bus.Bus, trail api.TrailStore,
	attested api.AttestedHistorySource, access api.AccessChangesSource) *Service {
	return &Service{
		pdp:      pdp,
		events:   events,
		trail:    trail,
		now:      func() time.Time { return time.Now().UTC() },
		attested: attested,
		access:   access,
		packs:    map[string]*packEntry{},
		byIDKey:  map[string]string{},
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

	// Idempotent replay: the same tenant, request ID, range and scope return
	// the pack the first request created — no second pack, no second PDP
	// decision, no second audit record (SPEC-0032 AC1).
	idKey := fmt.Sprintf("%s|%s|%s|%s|%s", c.TenantID, c.RequestID,
		req.RangeFrom.UTC().Format(time.RFC3339Nano), req.RangeTo.UTC().Format(time.RFC3339Nano), req.RepositoryID)
	s.mu.Lock()
	if packID, ok := s.byIDKey[idKey]; ok {
		entry := s.packs[packID]
		state := entry.state
		s.mu.Unlock()
		return packID, state, nil
	}
	s.mu.Unlock()

	// Generation is a PDP decision asked about the tenant, with the range
	// bounds and repository scope as server-derived context (SPEC-0032
	// vocabulary table). A denial or an unreachable PDP is the same coarse
	// shape as every other failed pack operation: the denial itself is
	// audited by the policy surface, never by a second record here.
	decision, err := s.decide(ctx, c, platformaudit.ActionEvidencePackGenerate,
		policyapi.Resource{Type: "tenant", ID: c.TenantID}, map[string]string{
			"range_from":    req.RangeFrom.UTC().Format(time.RFC3339Nano),
			"range_to":      req.RangeTo.UTC().Format(time.RFC3339Nano),
			"repository_id": req.RepositoryID,
		})
	if err != nil || !decision.Allowed {
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
		return "", 0, fmt.Errorf("audit: recording evidence pack generation: %w", err)
	}

	s.mu.Lock()
	// A concurrent replay of the same request ID raced us: honour the first
	// writer's pack rather than registering a second.
	if existing, ok := s.byIDKey[idKey]; ok {
		state := s.packs[existing].state
		s.mu.Unlock()
		return existing, state, nil
	}
	s.packs[packID] = entry
	s.byIDKey[idKey] = packID
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
		State:        entry.state,
		FailureReason: entry.failureReason,
		RangeFrom:    entry.pack.RangeFrom,
		RangeTo:      entry.pack.RangeTo,
		RepositoryID: entry.pack.RepositoryID,
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
func (s *Service) decide(ctx context.Context, c api.Context, action string, res policyapi.Resource, pctx map[string]string) (policyapi.Decision, error) {
	return s.pdp.Decide(ctx, policyapi.Request{
		TenantID: c.TenantID,
		Subject:  policyapi.Subject{ID: c.ActorID, TenantID: c.TenantID, Roles: c.ActorRoles},
		Action:   action,
		Resource: res,
		Context:  pctx,
	})
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
