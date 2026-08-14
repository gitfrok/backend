package app

import (
	"cmp"
	"context"
	"encoding/json"
	"slices"
	"sort"
	"time"

	codereviewapi "github.com/gitfrok/backend/modules/codereview/api"
	"github.com/gitfrok/backend/modules/security/api"
	"github.com/gitfrok/backend/platform/bus"
)

// The attribution engine (SPEC-0028). A merge request reaches
// Security/Findings only as an opaque identifier fed by Code Review's events
// into a tenant-scoped local projection; attribution is the set difference
// between what the MR's head revision reports and what its merge base
// reports, by SPEC-0024 identity. The comparison is materialized once per
// (merge request, head revision, merge base) triple and recomputed when the
// head or the base moves; an UNAVAILABLE comparison is reported with its
// reason, never degraded to an empty result set (SPEC-0028 AC7).

// precomputeActor is the subject identity attribution pre-materialization
// resolves merge bases under. It is a server-side computation, not a caller
// action; the read path re-resolves under the caller's own identity.
const precomputeActor = "security-attribution"

// mergeRequestProjection is one merge request as Code Review's events
// announced it. Security/Findings reads no Code Review table: this local,
// tenant-scoped projection is everything it knows (ADR-0022, SPEC-0028).
type mergeRequestProjection struct {
	MergeRequestID string
	TenantID       string
	RepositoryID   string
	SourceRef      string
	TargetRef      string
	HeadRevision   string
	Merged         bool
}

// attributedView is one finding of a materialized comparison.
type attributedView struct {
	finding     api.Finding
	attribution api.AttributionStatus
}

// attributionRecord is the materialized comparison for one (merge request,
// head revision, merge base) triple. Views are sorted by finding ID: the
// pagination order.
type attributionRecord struct {
	head string
	base string
	// status is AttributionUnavailable when the triple names a comparison
	// that could not be computed; views are empty and reason says why.
	status api.AttributionStatus
	reason api.AttributionUnavailableReason
	views  []attributedView
	low    int64
	medium int64
	high   int64
	// critical counts ATTRIBUTED findings of critical severity.
	critical int64
	emitted  bool
	computed time.Time
}

// attributionOutcome is what one comparison attempt produced. record is nil
// when the comparison is UNAVAILABLE (reason says why) or when the engine
// has nothing to compare yet; err from the caller covers infrastructure
// failures (store or resolver errors), which the read path renders as a
// stale fallback or a coarse denial.
type attributionOutcome struct {
	record *attributionRecord
	reason api.AttributionUnavailableReason
}

// subscribeAttributionEvents feeds the merge-request projection from Code
// Review's events and pre-materializes comparisons when a head moves or a
// scan lands (SPEC-0028: derived state recomputes on head/base move). The
// handlers never fail event delivery: a comparison that cannot be
// pre-materialized surfaces as UNAVAILABLE or stale at read time, not as an
// ingest failure.
func (s *Service) subscribeAttributionEvents(events bus.Bus) {
	bus.SubscribeTyped(events, s.onMergeRequestUpdated)
	bus.SubscribeTyped(events, s.onMergeRequestMerged)
	bus.SubscribeTyped(events, s.onScanIngestedAttribution)
}

// onMergeRequestUpdated upserts the projection with the MR's current head,
// source, and target — the open itself announces its head through the same
// event — then attempts a pre-materialization.
func (s *Service) onMergeRequestUpdated(ctx context.Context, e codereviewapi.MergeRequestUpdated) error {
	s.attrMu.Lock()
	tenant := s.mergeRequests[e.TenantID]
	if tenant == nil {
		tenant = map[string]mergeRequestProjection{}
		s.mergeRequests[e.TenantID] = tenant
	}
	tenant[e.MergeRequestID] = mergeRequestProjection{
		MergeRequestID: e.MergeRequestID, TenantID: e.TenantID, RepositoryID: e.RepositoryID,
		SourceRef: e.SourceRef, TargetRef: e.TargetRef, HeadRevision: e.HeadRevision,
	}
	s.attrMu.Unlock()
	_, _ = s.computeAttribution(ctx, e.TenantID, e.MergeRequestID, precomputeActor)
	return nil
}

// onMergeRequestMerged marks the projection merged. The comparison stays
// servable: a merged merge request's attributed findings remain readable.
func (s *Service) onMergeRequestMerged(_ context.Context, e codereviewapi.MergeRequestMerged) error {
	s.attrMu.Lock()
	defer s.attrMu.Unlock()
	if mr, ok := s.mergeRequests[e.TenantID][e.MergeRequestID]; ok {
		mr.Merged = true
		s.mergeRequests[e.TenantID][e.MergeRequestID] = mr
	}
	return nil
}

// onScanIngestedAttribution pre-materializes every open comparison of the
// scanned repository: a new scan can complete the head side or the base
// side of any of them.
func (s *Service) onScanIngestedAttribution(ctx context.Context, e api.ScanIngested) error {
	s.attrMu.Lock()
	var targets []string
	for id, mr := range s.mergeRequests[e.TenantID] {
		if mr.RepositoryID == e.RepositoryID {
			targets = append(targets, id)
		}
	}
	s.attrMu.Unlock()
	slices.Sort(targets)
	for _, id := range targets {
		_, _ = s.computeAttribution(ctx, e.TenantID, id, precomputeActor)
	}
	return nil
}

// projectionFor returns the tenant-scoped projection of one merge request.
func (s *Service) projectionFor(tenantID, mergeRequestID string) (mergeRequestProjection, bool) {
	s.attrMu.Lock()
	defer s.attrMu.Unlock()
	mr, ok := s.mergeRequests[tenantID][mergeRequestID]
	return mr, ok
}

// SetMergeBaseResolver attaches the Repository/Git route attribution
// resolves merge bases through (repository.v1
// RepositoryReader.GetMergeBase). Without one, comparisons are honestly
// UNAVAILABLE; attaching one is a composition step, not a construction
// argument, because the route to Git storage exists only once the plane's
// doors are open.
func (s *Service) SetMergeBaseResolver(r api.MergeBaseResolver) {
	s.attrMu.Lock()
	defer s.attrMu.Unlock()
	s.mergeBase = r
}

// computeAttribution runs the comparison for one merge request under the
// actor's identity and materializes it per (merge request, head, merge
// base) triple: the first successful computation of a triple caches the
// record and emits FindingsAttributed, and a repeat computes nothing new
// (SPEC-0028 idempotency). A nil record with no error means the comparison
// is UNAVAILABLE and reason says why.
func (s *Service) computeAttribution(ctx context.Context, tenantID, mergeRequestID, actorID string) (attributionOutcome, error) {
	mr, ok := s.projectionFor(tenantID, mergeRequestID)
	if !ok || mr.HeadRevision == "" {
		return attributionOutcome{reason: api.AttributionUnavailableHeadScanNotRun}, nil
	}

	headReport, found, err := s.store.ScanReportAt(ctx, tenantID, mr.RepositoryID, mr.HeadRevision)
	if err != nil {
		return attributionOutcome{}, err
	}
	if !found {
		return attributionOutcome{reason: api.AttributionUnavailableHeadScanNotRun}, nil
	}

	s.attrMu.Lock()
	resolver := s.mergeBase
	s.attrMu.Unlock()
	if resolver == nil {
		// No route to Repository/Git on this plane: the comparison cannot be
		// answered, and the honest rendering is UNAVAILABLE — never
		// "no findings" and never "everything attributed" (SPEC-0028 AC7).
		return attributionOutcome{reason: ""}, nil
	}
	base, baseFound, err := resolver.MergeBase(ctx, tenantID, mr.RepositoryID, actorID, mr.SourceRef, mr.TargetRef)
	if err != nil {
		return attributionOutcome{}, err
	}
	if !baseFound {
		return attributionOutcome{
			record: &attributionRecord{
				head: mr.HeadRevision, status: api.AttributionUnavailable,
				reason: api.AttributionUnavailableNoMergeBase, views: []attributedView{},
				computed: s.now().UTC(),
			},
		}, nil
	}

	baseReport, found, err := s.store.ScanReportAt(ctx, tenantID, mr.RepositoryID, base)
	if err != nil {
		return attributionOutcome{}, err
	}
	if !found {
		return attributionOutcome{
			record: &attributionRecord{
				head: mr.HeadRevision, base: base, status: api.AttributionUnavailable,
				reason: api.AttributionUnavailableBaseNotScanned, views: []attributedView{},
				computed: s.now().UTC(),
			},
		}, nil
	}

	baseIDs := make(map[string]struct{}, len(baseReport.Findings))
	for _, rf := range baseReport.Findings {
		baseIDs[rf.Identity] = struct{}{}
	}
	rec := &attributionRecord{
		head: mr.HeadRevision, base: base, status: api.AttributionAttributed,
		views: make([]attributedView, 0, len(headReport.Findings)), computed: s.now().UTC(),
	}
	for _, rf := range headReport.Findings {
		view := attributedView{finding: rf.Finding, attribution: api.AttributionAttributed}
		if _, preExisting := baseIDs[rf.Identity]; preExisting {
			view.attribution = api.AttributionPreExisting
		} else {
			switch rf.Finding.Severity {
			case api.SeverityLow:
				rec.low++
			case api.SeverityMedium:
				rec.medium++
			case api.SeverityHigh:
				rec.high++
			case api.SeverityCritical:
				rec.critical++
			}
		}
		rec.views = append(rec.views, view)
	}
	slices.SortFunc(rec.views, func(a, b attributedView) int {
		return cmp.Compare(a.finding.ID, b.finding.ID)
	})

	key := attributionKey(tenantID, mergeRequestID, mr.HeadRevision, base)
	s.attrMu.Lock()
	if existing, ok := s.attributions[key]; ok {
		rec = existing
	} else {
		s.attributions[key] = rec
	}
	needsEmit := !rec.emitted
	if needsEmit {
		rec.emitted = true
	}
	s.attrMu.Unlock()

	if needsEmit && rec.status == api.AttributionAttributed {
		if err := s.bus.Publish(ctx, api.FindingsAttributed{
			EventID: s.newID(), TenantID: tenantID, RepositoryID: mr.RepositoryID,
			MergeRequestID: mergeRequestID, HeadRevision: rec.head, BaseRevision: rec.base,
			AttributedLow: rec.low, AttributedMedium: rec.medium,
			AttributedHigh: rec.high, AttributedCritical: rec.critical,
			OccurredAt: s.now().UTC(),
		}); err != nil {
			return attributionOutcome{}, err
		}
	}
	return attributionOutcome{record: rec}, nil
}

// latestAttribution returns the most recently computed materialized record
// for a merge request, whatever triple produced it: the stale fallback a
// read serves when the current comparison cannot be answered (SPEC-0028
// non-functional).
func (s *Service) latestAttribution(tenantID, mergeRequestID string) (*attributionRecord, bool) {
	prefix := tenantID + "\x00" + mergeRequestID + "\x00"
	s.attrMu.Lock()
	defer s.attrMu.Unlock()
	var best *attributionRecord
	for key, rec := range s.attributions {
		if len(key) < len(prefix) || key[:len(prefix)] != prefix {
			continue
		}
		if best == nil || rec.computed.After(best.computed) {
			best = rec
		}
	}
	return best, best != nil
}

func attributionKey(tenantID, mergeRequestID, head, base string) string {
	return tenantID + "\x00" + mergeRequestID + "\x00" + head + "\x00" + base
}

// ListMergeRequestFindings pages the findings attributable to one merge
// request (SPEC-0028). The order of operations is the security statement:
// the merge request must exist in this context's own event-fed projection —
// unknown and cross-tenant are the same coarse denial (SPEC-0001); a
// caller-supplied repository must match the projection's, but an EMPTY one
// is accepted because the repository is server-derived state of the
// projection (SPEC-0026 AC6); the PDP decides findings.read on the merge
// request with server-derived context; and the comparison is a server fact,
// materialized per (MR, head, base) triple. An UNAVAILABLE comparison is
// reported with its reason and an empty list, never as "no findings"
// (SPEC-0028 AC7).
func (s *Service) ListMergeRequestFindings(ctx context.Context, req api.MergeRequestFindingsRequest) (api.MergeRequestFindingsPage, error) {
	if !validTenantContext(req.Context) || req.MergeRequestID == "" {
		return api.MergeRequestFindingsPage{}, api.ErrDenied
	}
	if req.AttributionFilter != api.AttributionStatusUnspecified && !req.AttributionFilter.Valid() {
		return api.MergeRequestFindingsPage{}, api.ErrMalformed
	}
	mr, ok := s.projectionFor(req.TenantID, req.MergeRequestID)
	if !ok || (req.RepositoryID != "" && mr.RepositoryID != req.RepositoryID) {
		return api.MergeRequestFindingsPage{}, api.ErrDenied
	}
	attrs := map[string]string{"repository": mr.RepositoryID}
	if req.ScannerClassFilter != "" {
		attrs["scanner_class"] = string(req.ScannerClassFilter)
	}
	if req.SeverityFilter != "" {
		attrs["severity"] = string(req.SeverityFilter)
	}
	if !s.allowed(ctx, req.Context, "findings.read", "merge_request", req.MergeRequestID, attrs) {
		return api.MergeRequestFindingsPage{}, api.ErrDenied
	}

	outcome, err := s.computeAttribution(ctx, req.TenantID, req.MergeRequestID, req.ActorID)
	if err != nil || outcome.record == nil {
		// The current comparison cannot be answered. A materialized record
		// from an earlier triple is served as stale — never as current
		// (SPEC-0028 non-functional); with none, an infrastructure failure
		// is a coarse denial and a known-unavailable comparison is an
		// honest UNAVAILABLE summary.
		if rec, ok := s.latestAttribution(req.TenantID, req.MergeRequestID); ok {
			return s.renderMergeRequestPage(ctx, req, rec, true)
		}
		if err != nil {
			return api.MergeRequestFindingsPage{}, api.ErrDenied
		}
		return api.MergeRequestFindingsPage{
			Views: []api.MergeRequestFindingView{},
			Summary: api.AttributionSummary{
				Status:            api.AttributionUnavailable,
				UnavailableReason: outcome.reason,
				HeadRevision:      mr.HeadRevision,
			},
		}, nil
	}
	stale := recordStale(outcome.record, mr)
	return s.renderMergeRequestPage(ctx, req, outcome.record, stale)
}

// recordStale reports whether a served record lags the projection it was
// computed for: a head that moved since materialization makes the record
// stale rather than current.
func recordStale(rec *attributionRecord, mr mergeRequestProjection) bool {
	return rec.head != mr.HeadRevision
}

// renderMergeRequestPage filters, pages, and renders one materialized
// record. Triage travels as view state: each rendered finding carries the
// latest triage record on its identity, if one exists (SPEC-0028 AC5).
func (s *Service) renderMergeRequestPage(ctx context.Context, req api.MergeRequestFindingsRequest, rec *attributionRecord, stale bool) (api.MergeRequestFindingsPage, error) {
	views := make([]attributedView, 0, len(rec.views))
	for _, v := range rec.views {
		if req.ScannerClassFilter != "" && v.finding.ScannerClass != req.ScannerClassFilter {
			continue
		}
		if req.SeverityFilter != "" && v.finding.Severity != req.SeverityFilter {
			continue
		}
		if req.AttributionFilter != api.AttributionStatusUnspecified && v.attribution != req.AttributionFilter {
			continue
		}
		views = append(views, v)
	}

	limit := req.PageSize
	if limit <= 0 {
		limit = api.DefaultPageSize
	}
	if limit > api.MaxPageSize {
		limit = api.MaxPageSize
	}
	afterID := ""
	if req.PageToken != "" {
		cursor, ok := s.decodeMRCursor(req.PageToken, req)
		if !ok {
			// A forged, stale, or cross-tenant cursor yields no content —
			// never an error that distinguishes it from an empty page
			// (SPEC-0025). The summary still names the comparison.
			views = nil
		} else {
			afterID = cursor.AfterID
		}
	}
	if afterID != "" {
		i := sort.Search(len(views), func(i int) bool { return views[i].finding.ID > afterID })
		views = views[i:]
	}

	page := api.MergeRequestFindingsPage{Views: []api.MergeRequestFindingView{}}
	if len(views) > limit {
		page.NextPageToken = s.encodeMRCursor(req, views[limit-1].finding.ID)
		views = views[:limit]
	}
	for _, v := range views {
		view := api.MergeRequestFindingView{
			Finding:      v.finding,
			HeadLocation: v.finding.Location,
			Attribution:  v.attribution,
		}
		if rec.status == api.AttributionUnavailable {
			view.Attribution = api.AttributionUnavailable
			view.UnavailableReason = rec.reason
		}
		triage, found, err := s.store.GetTriage(ctx, req.TenantID, v.finding.ID, 0)
		if err != nil {
			return api.MergeRequestFindingsPage{}, api.ErrDenied
		}
		if found {
			record := triage
			view.Triage = &record
		}
		page.Views = append(page.Views, view)
	}
	page.Summary = api.AttributionSummary{
		Status:            rec.status,
		UnavailableReason: rec.reason,
		HeadRevision:      rec.head,
		MergeBaseRevision: rec.base,
		Stale:             stale,
		AttributedLow:     rec.low, AttributedMedium: rec.medium,
		AttributedHigh: rec.high, AttributedCritical: rec.critical,
	}
	return page, nil
}

// mrCursor is the signed payload of a merge-request findings page token. It
// binds the cursor to the tenant, the repository, the merge request, and the
// exact filters that issued it: a token issued for one listing is inert
// under another (SPEC-0025).
type mrCursor struct {
	TenantID     string
	Repository   string
	MergeRequest string
	Class        api.ScannerClass
	Severity     api.Severity
	Attribution  api.AttributionStatus
	AfterID      string
}

func (s *Service) encodeMRCursor(req api.MergeRequestFindingsRequest, lastID string) string {
	c := mrCursor{
		TenantID: req.TenantID, Repository: req.RepositoryID, MergeRequest: req.MergeRequestID,
		Class: req.ScannerClassFilter, Severity: req.SeverityFilter,
		Attribution: req.AttributionFilter, AfterID: lastID,
	}
	payload, err := json.Marshal(c)
	if err != nil {
		return "" // unencodable means no next page; never a partial token
	}
	return signToken(payload, s.cursorKey[:])
}

func (s *Service) decodeMRCursor(token string, req api.MergeRequestFindingsRequest) (mrCursor, bool) {
	payload, ok := verifyToken(token, s.cursorKey[:])
	if !ok {
		return mrCursor{}, false
	}
	var c mrCursor
	if err := json.Unmarshal(payload, &c); err != nil {
		return mrCursor{}, false
	}
	if c.TenantID != req.TenantID || c.Repository != req.RepositoryID ||
		c.MergeRequest != req.MergeRequestID || c.Class != req.ScannerClassFilter ||
		c.Severity != req.SeverityFilter || c.Attribution != req.AttributionFilter ||
		c.AfterID == "" {
		return mrCursor{}, false
	}
	return c, true
}
