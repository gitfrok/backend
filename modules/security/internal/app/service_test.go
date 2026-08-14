package app_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	policyapi "github.com/gitfrok/backend/modules/policy/api"
	"github.com/gitfrok/backend/modules/security/api"
	"github.com/gitfrok/backend/modules/security/internal/app"
	platformaudit "github.com/gitfrok/backend/platform/audit"
	"github.com/gitfrok/backend/platform/bus"
)

// fakePDP answers every question the same way and records what it was asked,
// so the tests can assert the service's decision requests carry
// server-derived context (SPEC-0025 AC4).
type fakePDP struct {
	allow    bool
	err      error
	requests []policyapi.Request
}

func (f *fakePDP) Decide(_ context.Context, req policyapi.Request) (policyapi.Decision, error) {
	f.requests = append(f.requests, req)
	if f.err != nil {
		return policyapi.Decision{}, f.err
	}
	return policyapi.Decision{Allowed: f.allow, DecisionID: "dec-1", PolicyRevision: "rev-1"}, nil
}

// harness wires the service over the memory store and a real in-process bus
// with collectors for every event and the audit record.
type harness struct {
	svc        *app.Service
	pdp        *fakePDP
	store      *app.MemoryStore
	bus        bus.Bus
	opened     []api.FindingOpened
	resolved   []api.FindingResolved
	scans      []api.ScanIngested
	attributed []api.FindingsAttributed
	audits     []platformaudit.FindingsScanIngested
	// failAuditOnce makes the NEXT audit delivery fail, then clears itself:
	// the stand-in for "the audit sink failed after the ingest committed"
	// (SPEC-0025 AC5 backfill path).
	failAuditOnce bool
	// failScanEvents fails every ScanIngested delivery: the stand-in for a
	// domain-event publish failing after the audit record landed.
	failScanEvents bool
	// witnessErr makes the trail witness unable to answer: the replay guard
	// must then fall back to the claim marker.
	witnessErr error
}

// trailWitness is the replay guard's audit-trail stand-in: it reports
// exactly the audit records the harness's sink collected — the in-test
// counterpart of the plane's trail read (wave-2 N5).
type trailWitness struct{ h *harness }

func (w trailWitness) IngestAuditRecorded(_ context.Context, _, _, scanID, requestID string, _ time.Time) (bool, error) {
	if w.h.witnessErr != nil {
		return false, w.h.witnessErr
	}
	for _, a := range w.h.audits {
		if a.ScanID == scanID && a.RequestID == requestID {
			return true, nil
		}
	}
	return false, nil
}

func newHarness(allow bool) *harness {
	pdp := &fakePDP{allow: allow}
	store := app.NewMemoryStore()
	events := bus.NewInProcess()
	h := &harness{pdp: pdp, store: store, bus: events}
	events.Subscribe(api.EventFindingOpened, func(_ context.Context, e bus.Event) error {
		h.opened = append(h.opened, e.(api.FindingOpened))
		return nil
	})
	events.Subscribe(api.EventFindingResolved, func(_ context.Context, e bus.Event) error {
		h.resolved = append(h.resolved, e.(api.FindingResolved))
		return nil
	})
	events.Subscribe(api.EventScanIngested, func(_ context.Context, e bus.Event) error {
		if h.failScanEvents {
			return errors.New("scan event sink unavailable")
		}
		h.scans = append(h.scans, e.(api.ScanIngested))
		return nil
	})
	events.Subscribe(api.EventFindingsAttributed, func(_ context.Context, e bus.Event) error {
		h.attributed = append(h.attributed, e.(api.FindingsAttributed))
		return nil
	})
	events.Subscribe(platformaudit.EventAudit, func(_ context.Context, e bus.Event) error {
		if a, ok := e.(platformaudit.FindingsScanIngested); ok {
			if h.failAuditOnce {
				h.failAuditOnce = false
				return errors.New("audit sink unavailable")
			}
			h.audits = append(h.audits, a)
		}
		return nil
	})
	h.svc = app.New(store, pdp, events,
		app.WithIDs(sequenceIDs()),
		app.WithClock(func() time.Time { return time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC) }),
		app.WithAuditWitness(trailWitness{h}),
	)
	return h
}

func sequenceIDs() func() string {
	n := 0
	return func() string {
		n++
		return "evt-" + string(rune('a'+n-1))
	}
}

var baseTime = time.Date(2026, 8, 14, 10, 0, 0, 0, time.UTC)

func validContext() api.Context {
	return api.Context{TenantID: "t-1", RepositoryID: "repo-1", ActorID: "actor-1", RequestID: "req-1"}
}

func sastScan(startOffset time.Duration) api.Scan {
	return api.Scan{
		ScannerClass: api.ScannerClassSAST,
		ToolName:     "semgrep",
		ToolVersion:  "1.99.0",
		StartedAt:    baseTime.Add(startOffset),
		EndedAt:      baseTime.Add(startOffset + time.Minute),
	}
}

func rawFinding(rule, path, content string) api.RawFinding {
	return api.RawFinding{
		RuleID:              rule,
		Severity:            api.SeverityHigh,
		Location:            api.Location{ArtifactPath: path, EnclosingContent: content},
		Provenance:          []byte(`{"native":"payload"}`),
		ProvenanceMediaType: "application/json",
	}
}

func singleChunk(scan api.Scan, reqID string, findings ...api.RawFinding) api.IngestChunk {
	return api.IngestChunk{
		Context:    validContext(),
		Revision:   "rev-abc",
		Scan:       scan,
		Findings:   findings,
		ChunkIndex: 0,
		FinalChunk: true,
	}
}

// Ingest completes and emits once.
func TestIngestCompletesAndEmits(t *testing.T) {
	h := newHarness(true)
	res, err := h.svc.IngestScanResults(context.Background(),
		singleChunk(sastScan(0), "req-1", rawFinding("py-eval", "app.py", "def handler():")))
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if !res.Completed || res.Replayed || res.FindingsRecorded != 1 || res.ScanID == "" {
		t.Fatalf("unexpected result: %+v", res)
	}
	if len(h.opened) != 1 || len(h.scans) != 1 || len(h.resolved) != 0 {
		t.Fatalf("emissions: opened=%d scans=%d resolved=%d", len(h.opened), len(h.scans), len(h.resolved))
	}
	if len(h.audits) != 1 {
		t.Fatalf("expected exactly one audit record, got %d", len(h.audits))
	}
	a := h.audits[0]
	if a.Action() != platformaudit.ActionFindingsScanIngested || a.TenantID != "t-1" ||
		a.RepositoryID != "repo-1" || a.ScanID != res.ScanID || a.RequestID != "req-1" ||
		a.PolicyDecisionID != "dec-1" || a.FindingsRecorded != 1 {
		t.Fatalf("audit record mismatch: %+v", a)
	}
	if h.scans[0].ScanID != res.ScanID || h.scans[0].FindingCount != 1 || h.scans[0].Revision != "rev-abc" {
		t.Fatalf("ScanIngested mismatch: %+v", h.scans[0])
	}
}

// Idempotency per (tenant, scan, request ID): a replay reports the recorded
// outcome and emits no event and no second audit record (SPEC-0025 AC1).
func TestReplayIsSilent(t *testing.T) {
	h := newHarness(true)
	chunk := singleChunk(sastScan(0), "req-1", rawFinding("py-eval", "app.py", "def handler():"))
	if _, err := h.svc.IngestScanResults(context.Background(), chunk); err != nil {
		t.Fatalf("first ingest: %v", err)
	}
	res, err := h.svc.IngestScanResults(context.Background(), chunk)
	if err != nil {
		t.Fatalf("replay ingest: %v", err)
	}
	if !res.Replayed || !res.Completed || res.FindingsRecorded != 1 {
		t.Fatalf("expected a replayed recorded outcome, got %+v", res)
	}
	if len(h.opened) != 1 || len(h.scans) != 1 || len(h.audits) != 1 {
		t.Fatalf("replay must emit nothing new: opened=%d scans=%d audits=%d",
			len(h.opened), len(h.scans), len(h.audits))
	}
}

// Chunk visibility: nothing of a multi-chunk batch is readable until the
// final chunk completes (SPEC-0025).
func TestChunkVisibilityOnlyAfterFinalChunk(t *testing.T) {
	h := newHarness(true)
	scan := sastScan(0)
	ctx := validContext()

	first := api.IngestChunk{Context: ctx, Revision: "rev-abc", Scan: scan,
		Findings: []api.RawFinding{rawFinding("rule-a", "a.py", "fn-a")}, ChunkIndex: 0}
	res, err := h.svc.IngestScanResults(context.Background(), first)
	if err != nil {
		t.Fatalf("chunk 0: %v", err)
	}
	if res.Completed || len(h.opened) != 0 || len(h.scans) != 0 || len(h.audits) != 0 {
		t.Fatalf("a non-final chunk must be invisible and emit nothing: %+v", res)
	}

	// The scan's finding is not readable yet.
	page, err := h.svc.ListFindings(context.Background(), api.ListRequest{Context: ctx})
	if err != nil || len(page.Findings) != 0 {
		t.Fatalf("partial batch must not be readable: page=%+v err=%v", page, err)
	}

	second := first
	second.RequestID = "req-2"
	second.Findings = []api.RawFinding{rawFinding("rule-b", "b.py", "fn-b")}
	second.ChunkIndex = 1
	second.FinalChunk = true
	res, err = h.svc.IngestScanResults(context.Background(), second)
	if err != nil || !res.Completed {
		t.Fatalf("final chunk: %+v err=%v", res, err)
	}
	if len(h.opened) != 2 || len(h.scans) != 1 {
		t.Fatalf("final chunk must emit the batch: opened=%d scans=%d", len(h.opened), len(h.scans))
	}
	page, err = h.svc.ListFindings(context.Background(), api.ListRequest{Context: ctx})
	if err != nil || len(page.Findings) != 2 {
		t.Fatalf("completed batch must be readable: got %d findings, err=%v", len(page.Findings), err)
	}
}

// OPEN/RESOLVED by set comparison, resolved-not-deleted (SPEC-0024 AC9):
// scan 2 no longer reporting scan 1's finding resolves it, and the resolved
// finding remains retrievable with its identity and history.
func TestResolveNotDelete(t *testing.T) {
	h := newHarness(true)
	ctx := context.Background()

	scan1 := sastScan(0)
	both := []api.RawFinding{
		rawFinding("rule-a", "a.py", "fn-a"),
		rawFinding("rule-b", "b.py", "fn-b"),
	}
	res1, err := h.svc.IngestScanResults(ctx, singleChunk(scan1, "req-1", both...))
	if err != nil {
		t.Fatalf("scan 1: %v", err)
	}

	scan2 := sastScan(time.Hour) // same tool, later run → a different scan
	res2, err := h.svc.IngestScanResults(ctx, singleChunk(scan2, "req-2", both[0]))
	if err != nil {
		t.Fatalf("scan 2: %v", err)
	}
	if res2.ScanID == res1.ScanID {
		t.Fatalf("two scans must not share a scan record")
	}
	if len(h.resolved) != 1 || len(h.opened) != 2 {
		t.Fatalf("expected 2 opens and 1 resolution, got opened=%d resolved=%d", len(h.opened), len(h.resolved))
	}

	// The resolved finding is still retrievable — resolved, not deleted.
	resolvedID := h.resolved[0].FindingID
	f, err := h.svc.GetFinding(ctx, validContext(), resolvedID)
	if err != nil {
		t.Fatalf("resolved finding must remain retrievable: %v", err)
	}
	if f.Lifecycle != api.LifecycleResolved || f.FirstSeenScanID != res1.ScanID {
		t.Fatalf("lifecycle/history mismatch: %+v", f)
	}
	// The still-reported finding saw scan 2.
	for _, o := range h.opened {
		if o.RuleID == "rule-a" {
			got, err := h.svc.GetFinding(ctx, validContext(), o.FindingID)
			if err != nil || got.Lifecycle != api.LifecycleOpen || got.LastSeenScanID != res2.ScanID {
				t.Fatalf("still-reported finding mismatch: %+v err=%v", got, err)
			}
		}
	}

	// A third scan not reporting it again resolves nothing twice.
	res3, err := h.svc.IngestScanResults(ctx, singleChunk(sastScan(2*time.Hour), "req-3", both[0]))
	if err != nil || !res3.Completed {
		t.Fatalf("scan 3: %+v err=%v", res3, err)
	}
	if len(h.resolved) != 1 {
		t.Fatalf("a finding must not be resolved twice, got %d resolution events", len(h.resolved))
	}
}

// Identity is stable across scans and dedups: scan 2 re-reporting the same
// defect yields the same finding ID, no duplicate (SPEC-0024 AC2/AC7).
func TestIdentityDedupAcrossScans(t *testing.T) {
	h := newHarness(true)
	ctx := context.Background()
	finding := rawFinding("rule-a", "a.py", "fn-a")

	if _, err := h.svc.IngestScanResults(ctx, singleChunk(sastScan(0), "req-1", finding)); err != nil {
		t.Fatalf("scan 1: %v", err)
	}
	if _, err := h.svc.IngestScanResults(ctx, singleChunk(sastScan(time.Hour), "req-2", finding)); err != nil {
		t.Fatalf("scan 2: %v", err)
	}
	if len(h.opened) != 1 {
		t.Fatalf("the same defect must open once, got %d opens", len(h.opened))
	}
	page, err := h.svc.ListFindings(ctx, api.ListRequest{Context: validContext()})
	if err != nil || len(page.Findings) != 1 {
		t.Fatalf("expected exactly one stored finding, got %d (err=%v)", len(page.Findings), err)
	}
	if page.Findings[0].FirstSeenScanID == page.Findings[0].LastSeenScanID {
		t.Fatalf("second scan must advance LastSeenScanID: %+v", page.Findings[0])
	}
}

// Provenance round-trips byte-for-byte with its media type (SPEC-0025 AC6).
func TestProvenanceRoundTrip(t *testing.T) {
	h := newHarness(true)
	ctx := context.Background()
	payload := []byte{0x00, 0xff, '{', '"', 'x', '"', ':', '1', '}', 0x00}
	raw := rawFinding("rule-a", "a.py", "fn-a")
	raw.Provenance = payload
	raw.ProvenanceMediaType = "application/json"

	if _, err := h.svc.IngestScanResults(ctx, singleChunk(sastScan(0), "req-1", raw)); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	page, err := h.svc.ListFindings(ctx, api.ListRequest{Context: validContext()})
	if err != nil || len(page.Findings) != 1 {
		t.Fatalf("list: %v", err)
	}
	got := page.Findings[0]
	if !bytes.Equal(got.Provenance, payload) || got.ProvenanceMediaType != "application/json" {
		t.Fatalf("provenance did not round-trip byte-for-byte: %q %q", got.Provenance, got.ProvenanceMediaType)
	}
}

// The PDP decides with server-derived context; a denial refuses the whole
// ingest and stores nothing (SPEC-0025 AC4).
func TestPDPDenialRefusesWholeIngest(t *testing.T) {
	h := newHarness(false)
	res, err := h.svc.IngestScanResults(context.Background(),
		singleChunk(sastScan(0), "req-1", rawFinding("rule-a", "a.py", "fn-a")))
	if !errors.Is(err, api.ErrDenied) {
		t.Fatalf("expected coarse denial, got %+v / %v", res, err)
	}
	if len(h.pdp.requests) != 1 {
		t.Fatalf("expected exactly one PDP request, got %d", len(h.pdp.requests))
	}
	req := h.pdp.requests[0]
	if req.Action != "findings.ingest" || req.Resource.Type != "repository" || req.Resource.ID != "repo-1" {
		t.Fatalf("decision request mismatch: %+v", req)
	}
	if req.Context["scanner_class"] != "SAST" || req.Context["tool_name"] != "semgrep" || req.Context["revision"] != "rev-abc" {
		t.Fatalf("decision must carry server-derived context: %+v", req.Context)
	}
	page, listErr := h.svc.ListFindings(context.Background(), api.ListRequest{Context: validContext()})
	if listErr == nil && len(page.Findings) != 0 {
		t.Fatalf("a denied ingest must store nothing")
	}
	if len(h.opened) != 0 || len(h.audits) != 0 {
		t.Fatalf("a denied ingest must emit nothing")
	}
}

// A PDP error is a refusal, not a pass-through (ADR-0006).
func TestPDPErrorIsRefusal(t *testing.T) {
	h := newHarness(true)
	h.pdp.err = errors.New("pdp unavailable")
	if _, err := h.svc.IngestScanResults(context.Background(),
		singleChunk(sastScan(0), "req-1", rawFinding("rule-a", "a.py", "fn-a"))); !errors.Is(err, api.ErrDenied) {
		t.Fatalf("expected denial on PDP error, got %v", err)
	}
}

// Boundary validation rejects malformed requests whole (SPEC-0025 AC6),
// before any decision or write.
func TestMalformedRejectedWhole(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*api.IngestChunk)
	}{
		{"unknown scanner class", func(c *api.IngestChunk) { c.Scan.ScannerClass = "FUZZY" }},
		{"empty tool name", func(c *api.IngestChunk) { c.Scan.ToolName = "" }},
		{"zero scan start", func(c *api.IngestChunk) { c.Scan.StartedAt = time.Time{} }},
		{"negative chunk index", func(c *api.IngestChunk) { c.ChunkIndex = -1 }},
		{"empty rule id", func(c *api.IngestChunk) { c.Findings[0].RuleID = "" }},
		{"unknown severity", func(c *api.IngestChunk) { c.Findings[0].Severity = "MEH" }},
		{"oversized provenance", func(c *api.IngestChunk) {
			c.Findings[0].Provenance = make([]byte, api.MaxProvenanceBytes+1)
		}},
		{"provenance without media type", func(c *api.IngestChunk) { c.Findings[0].ProvenanceMediaType = "" }},
		{"media type without provenance", func(c *api.IngestChunk) { c.Findings[0].Provenance = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(true)
			chunk := singleChunk(sastScan(0), "req-1", rawFinding("rule-a", "a.py", "fn-a"))
			tc.mutate(&chunk)
			if _, err := h.svc.IngestScanResults(context.Background(), chunk); !errors.Is(err, api.ErrMalformed) {
				t.Fatalf("expected ErrMalformed, got %v", err)
			}
			if len(h.pdp.requests) != 0 {
				t.Fatalf("a malformed request must be rejected before any PDP decision")
			}
		})
	}
}

// An incomplete verified context is a coarse denial (SPEC-0025).
func TestIncompleteContextDenied(t *testing.T) {
	for name, mutate := range map[string]func(*api.Context){
		"no tenant":     func(c *api.Context) { c.TenantID = "" },
		"no repository": func(c *api.Context) { c.RepositoryID = "" },
		"no actor":      func(c *api.Context) { c.ActorID = "" },
		"no request id": func(c *api.Context) { c.RequestID = "" },
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(true)
			chunk := singleChunk(sastScan(0), "req-1", rawFinding("rule-a", "a.py", "fn-a"))
			mutate(&chunk.Context)
			if _, err := h.svc.IngestScanResults(context.Background(), chunk); !errors.Is(err, api.ErrDenied) {
				t.Fatalf("expected denial, got %v", err)
			}
		})
	}
}

// Reads: GetFinding scopes to the tenant and the PDP; ListFindings filters
// and pages with signed cursors bound to the issuing filters.
func TestReadSurface(t *testing.T) {
	h := newHarness(true)
	ctx := context.Background()
	findings := []api.RawFinding{
		rawFinding("rule-a", "a.py", "fn-a"),
		rawFinding("rule-b", "b.py", "fn-b"),
		rawFinding("rule-c", "c.py", "fn-c"),
	}
	if _, err := h.svc.IngestScanResults(ctx, singleChunk(sastScan(0), "req-1", findings...)); err != nil {
		t.Fatalf("ingest: %v", err)
	}

	// Cross-tenant and unknown IDs are the same coarse denial.
	if _, err := h.svc.GetFinding(ctx, api.Context{TenantID: "t-2", RepositoryID: "repo-1", ActorID: "actor-1", RequestID: "req-x"}, h.opened[0].FindingID); !errors.Is(err, api.ErrDenied) {
		t.Fatalf("cross-tenant read must deny, got %v", err)
	}
	if _, err := h.svc.GetFinding(ctx, validContext(), "no-such-finding"); !errors.Is(err, api.ErrDenied) {
		t.Fatalf("unknown finding must deny, got %v", err)
	}

	// Paging: size-2 pages over 3 findings, cursor round-trip.
	page1, err := h.svc.ListFindings(ctx, api.ListRequest{Context: validContext(), PageSize: 2})
	if err != nil || len(page1.Findings) != 2 || page1.NextPageToken == "" {
		t.Fatalf("page 1: %+v err=%v", page1, err)
	}
	page2, err := h.svc.ListFindings(ctx, api.ListRequest{Context: validContext(), PageSize: 2, PageToken: page1.NextPageToken})
	if err != nil || len(page2.Findings) != 1 || page2.NextPageToken != "" {
		t.Fatalf("page 2: %+v err=%v", page2, err)
	}
	seen := map[string]bool{}
	for _, f := range append(page1.Findings, page2.Findings...) {
		if seen[f.ID] {
			t.Fatalf("duplicate finding across pages: %s", f.ID)
		}
		seen[f.ID] = true
	}

	// A forged or replayed-under-other-filters token yields no content.
	empty, err := h.svc.ListFindings(ctx, api.ListRequest{
		Context: validContext(), PageSize: 2, PageToken: page1.NextPageToken,
		SeverityFilter: api.SeverityCritical, // different filters → token inert
	})
	if err != nil || len(empty.Findings) != 0 || empty.NextPageToken != "" {
		t.Fatalf("a token under other filters must yield nothing: %+v err=%v", empty, err)
	}

	// Repository filter naming another repository is a coarse denial.
	if _, err := h.svc.ListFindings(ctx, api.ListRequest{Context: validContext(), RepositoryFilter: "repo-2"}); !errors.Is(err, api.ErrDenied) {
		t.Fatalf("foreign repository filter must deny, got %v", err)
	}
}

// Severity and scanner-class filters narrow the listing.
func TestListFilters(t *testing.T) {
	h := newHarness(true)
	ctx := context.Background()
	low := rawFinding("rule-low", "l.py", "fn-l")
	low.Severity = api.SeverityLow
	if _, err := h.svc.IngestScanResults(ctx, singleChunk(sastScan(0), "req-1",
		rawFinding("rule-a", "a.py", "fn-a"), low)); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	page, err := h.svc.ListFindings(ctx, api.ListRequest{Context: validContext(), SeverityFilter: api.SeverityLow})
	if err != nil || len(page.Findings) != 1 || page.Findings[0].RuleID != "rule-low" {
		t.Fatalf("severity filter: %+v err=%v", page, err)
	}
	page, err = h.svc.ListFindings(ctx, api.ListRequest{Context: validContext(), ScannerClassFilter: api.ScannerClassSecrets})
	if err != nil || len(page.Findings) != 0 {
		t.Fatalf("scanner class filter: %+v err=%v", page, err)
	}
}

// A finding lives in exactly one repository: a principal scoped to repo
// repo-1 cannot read the finding or its triage in repo-2 of the same tenant
// — cross-repository reads are the same coarse denial as absence
// (SPEC-0001, phase-2 review H3).
func TestGetFindingAndTriageAreRepositoryScoped(t *testing.T) {
	h := newHarness(true)
	ctx := context.Background()

	chunk := singleChunk(sastScan(0), "req-r2", rawFinding("rule-r2", "r2.py", "fn-r2"))
	chunk.Context.RepositoryID = "repo-2"
	res, err := h.svc.IngestScanResults(ctx, chunk)
	if err != nil || !res.Completed {
		t.Fatalf("ingest into repo-2: %+v err=%v", res, err)
	}
	findingID := h.opened[0].FindingID

	repo1 := validContext()
	if _, err := h.svc.GetFinding(ctx, repo1, findingID); !errors.Is(err, api.ErrDenied) {
		t.Fatalf("a repo-1 principal must not read repo-2's finding, got %v", err)
	}
	if _, _, err := h.svc.GetTriage(ctx, repo1, findingID, 0); !errors.Is(err, api.ErrDenied) {
		t.Fatalf("a repo-1 principal must not read repo-2's triage, got %v", err)
	}

	repo2 := validContext()
	repo2.RepositoryID = "repo-2"
	if _, err := h.svc.GetFinding(ctx, repo2, findingID); err != nil {
		t.Fatalf("the finding's own repository must read it: %v", err)
	}
	if _, found, err := h.svc.GetTriage(ctx, repo2, findingID, 0); err != nil || found {
		t.Fatalf("triage read in-scope: found=%v err=%v", found, err)
	}
}

// SPEC-0025 AC5 — exactly one audit record per accepted ingest, including
// the replay path: when the first attempt commits but its audit publish
// fails, the replay backfills the missing record (phase-2 review M10).
func TestAuditBackfillsWhenTheFirstAttemptLostIt(t *testing.T) {
	h := newHarness(true)
	chunk := singleChunk(sastScan(0), "req-1", rawFinding("py-eval", "app.py", "def handler():"))
	chunk.RequestID = "req-1"

	h.failAuditOnce = true
	if _, err := h.svc.IngestScanResults(context.Background(), chunk); err == nil {
		t.Fatalf("a failed audit publish must fail the ingest")
	}
	if len(h.audits) != 0 {
		t.Fatalf("the failed publish must append nothing, got %d", len(h.audits))
	}

	// The redelivery replays the committed outcome and backfills the one
	// record — exactly one in total, never two.
	res, err := h.svc.IngestScanResults(context.Background(), chunk)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if !res.Replayed || !res.Completed {
		t.Fatalf("expected a replayed recorded outcome, got %+v", res)
	}
	if len(h.audits) != 1 {
		t.Fatalf("the replay must backfill exactly one audit record, got %d", len(h.audits))
	}
	// The backfill appends the audit record only. Domain-event delivery is
	// the first attempt's responsibility; recovering a lost event stream is
	// out of AC5's scope.
	if len(h.opened) != 0 || len(h.scans) != 0 {
		t.Fatalf("the backfill must emit no domain events: opened=%d scans=%d", len(h.opened), len(h.scans))
	}

	// A further replay is silent again: the claim marker landed.
	if _, err := h.svc.IngestScanResults(context.Background(), chunk); err != nil {
		t.Fatalf("second replay: %v", err)
	}
	if len(h.audits) != 1 {
		t.Fatalf("a marked replay must append nothing, got %d", len(h.audits))
	}
}

// The audit record lands before the domain events: when a later event
// publish fails after commit, the committed ingest still has its one audit
// record, and the retry's replay appends no second one (phase-2 review M10).
func TestAuditSurvivesALaterEventFailure(t *testing.T) {
	h := newHarness(true)
	chunk := singleChunk(sastScan(0), "req-1", rawFinding("py-eval", "app.py", "def handler():"))
	chunk.RequestID = "req-1"

	h.failScanEvents = true
	if _, err := h.svc.IngestScanResults(context.Background(), chunk); err == nil {
		t.Fatalf("a failed domain-event publish must fail the ingest")
	}
	if len(h.audits) != 1 {
		t.Fatalf("the audit record must survive the later event failure, got %d", len(h.audits))
	}

	h.failScanEvents = false
	res, err := h.svc.IngestScanResults(context.Background(), chunk)
	if err != nil || !res.Replayed {
		t.Fatalf("replay: %+v err=%v", res, err)
	}
	if len(h.audits) != 1 {
		t.Fatalf("a marked replay must append no second audit record, got %d", len(h.audits))
	}
}

// A list cursor is bound to the issuing principal: the same tenant's second
// actor replaying the token gets no content — a cursor is not transferable
// (phase-2 review L17).
func TestListCursorIsBoundToTheIssuingActor(t *testing.T) {
	h := newHarness(true)
	ctx := context.Background()
	if _, err := h.svc.IngestScanResults(ctx, singleChunk(sastScan(0), "req-1",
		rawFinding("rule-a", "a.py", "fn-a"), rawFinding("rule-b", "b.py", "fn-b"))); err != nil {
		t.Fatalf("ingest: %v", err)
	}

	page1, err := h.svc.ListFindings(ctx, api.ListRequest{Context: validContext(), PageSize: 1})
	if err != nil || page1.NextPageToken == "" {
		t.Fatalf("page 1 must carry a next token: %+v err=%v", page1, err)
	}

	other := validContext()
	other.ActorID = "actor-2"
	page2, err := h.svc.ListFindings(ctx, api.ListRequest{Context: other, PageSize: 1, PageToken: page1.NextPageToken})
	if err != nil || len(page2.Findings) != 0 || page2.NextPageToken != "" {
		t.Fatalf("another actor's replay of the token must yield nothing: %+v err=%v", page2, err)
	}

	own, err := h.svc.ListFindings(ctx, api.ListRequest{Context: validContext(), PageSize: 1, PageToken: page1.NextPageToken})
	if err != nil || len(own.Findings) != 1 {
		t.Fatalf("the issuing actor's own token must still page: %+v err=%v", own, err)
	}
}

// Wave-2 N2 — the store keys ingest-audit claim markers by "audit:"+request
// ID, so a caller request ID carrying that prefix shares the marker's key
// namespace. The boundary refuses the shape whole, before any decision or
// write: malformed for ingest, denied for the tenant-wide reads.
func TestReservedRequestIDPrefixIsRefused(t *testing.T) {
	h := newHarness(true)
	chunk := singleChunk(sastScan(0), "req-1", rawFinding("py-eval", "app.py", "def handler():"))
	chunk.RequestID = "audit:req-1"
	if _, err := h.svc.IngestScanResults(context.Background(), chunk); !errors.Is(err, api.ErrMalformed) {
		t.Fatalf("a reserved-namespace request ID must be refused as malformed, got %v", err)
	}
	if len(h.audits) != 0 || len(h.opened) != 0 || len(h.scans) != 0 {
		t.Fatalf("a refused request must write and emit nothing: audits=%d opened=%d scans=%d",
			len(h.audits), len(h.opened), len(h.scans))
	}

	summary := api.SummaryRequest{Context: api.Context{
		TenantID: "t-1", ActorID: "actor-1", RequestID: "audit:req-1",
	}}
	if _, err := h.svc.GetFindingsSummary(context.Background(), summary); !errors.Is(err, api.ErrDenied) {
		t.Fatalf("a reserved-namespace summary request ID must be denied, got %v", err)
	}
}

// Wave-2 N2, attack 1 — suppressed audit record: an ingest squatted under
// "audit:R" used to plant a scan_chunks row matching R's marker key, so R's
// backfill would see "already recorded" and stay silent forever. The
// boundary now refuses the squatting shape, so the real ingest's lost audit
// publish still backfills its one record.
func TestAuditNamespaceCannotSuppressABackfill(t *testing.T) {
	h := newHarness(true)
	ctx := context.Background()

	squat := singleChunk(sastScan(0), "req-1", rawFinding("squat", "s.py", "fn"))
	squat.RequestID = "audit:req-1"
	if _, err := h.svc.IngestScanResults(ctx, squat); !errors.Is(err, api.ErrMalformed) {
		t.Fatalf("the squatting ingest must be refused, got %v", err)
	}

	chunk := singleChunk(sastScan(0), "req-1", rawFinding("py-eval", "app.py", "def handler():"))
	chunk.RequestID = "req-1"
	h.failAuditOnce = true
	if _, err := h.svc.IngestScanResults(ctx, chunk); err == nil {
		t.Fatalf("a failed audit publish must fail the ingest")
	}
	res, err := h.svc.IngestScanResults(ctx, chunk)
	if err != nil || !res.Replayed {
		t.Fatalf("replay: %+v err=%v", res, err)
	}
	if len(h.audits) != 1 {
		t.Fatalf("the lost publish must still backfill exactly one record, got %d", len(h.audits))
	}
}

// Wave-2 N2, attack 2 — forged replay: once R completes with audit record,
// a replay crafted under "audit:R" used to sit in the marker namespace and
// answer as if it were the recorded outcome. The boundary refuses it; the
// recorded audit count is untouched.
func TestAuditNamespaceCannotForgeAReplay(t *testing.T) {
	h := newHarness(true)
	ctx := context.Background()
	chunk := singleChunk(sastScan(0), "req-1", rawFinding("py-eval", "app.py", "def handler():"))
	chunk.RequestID = "req-1"
	if _, err := h.svc.IngestScanResults(ctx, chunk); err != nil {
		t.Fatalf("ingest: %v", err)
	}

	forged := chunk
	forged.RequestID = "audit:req-1"
	if _, err := h.svc.IngestScanResults(ctx, forged); !errors.Is(err, api.ErrMalformed) {
		t.Fatalf("a forged replay in the marker namespace must be refused, got %v", err)
	}
	if len(h.audits) != 1 {
		t.Fatalf("the forged replay must append nothing, got %d", len(h.audits))
	}
}

// Wave-2 N5 — the claim marker commits WITH the chunk: when the audit
// publish fails after the commit, the marker already exists, so a replay
// whose witness cannot answer falls back to the marker and appends nothing
// (the claim no longer lags the commit). A healthy witness still sees the
// genuinely absent record and backfills exactly one.
func TestAuditMarkerCommitsWithTheChunk(t *testing.T) {
	h := newHarness(true)
	ctx := context.Background()
	chunk := singleChunk(sastScan(0), "req-1", rawFinding("py-eval", "app.py", "def handler():"))
	chunk.RequestID = "req-1"

	h.failAuditOnce = true
	if _, err := h.svc.IngestScanResults(ctx, chunk); err == nil {
		t.Fatalf("a failed audit publish must fail the ingest")
	}
	if len(h.audits) != 0 {
		t.Fatalf("the failed publish must append nothing, got %d", len(h.audits))
	}

	// Witness down: the replay falls back to the claim marker. Pre-N5 the
	// marker lagged behind the publish, so this replay would have
	// backfilled here; now the marker rode in the chunk's own transaction
	// and the fallback sees it.
	h.witnessErr = errors.New("trail unavailable")
	if _, err := h.svc.IngestScanResults(ctx, chunk); err != nil {
		t.Fatalf("marker-fallback replay: %v", err)
	}
	if len(h.audits) != 0 {
		t.Fatalf("the marker must have committed with the chunk; the fallback must append nothing, got %d", len(h.audits))
	}

	// Witness healthy: the trail shows the record genuinely absent, so the
	// replay backfills — exactly one in total.
	h.witnessErr = nil
	if _, err := h.svc.IngestScanResults(ctx, chunk); err != nil {
		t.Fatalf("witnessed replay: %v", err)
	}
	if len(h.audits) != 1 {
		t.Fatalf("the witness must backfill the genuinely absent record exactly once, got %d", len(h.audits))
	}

	// Marked and witnessed: a further replay is silent.
	if _, err := h.svc.IngestScanResults(ctx, chunk); err != nil {
		t.Fatalf("final replay: %v", err)
	}
	if len(h.audits) != 1 {
		t.Fatalf("a recorded replay must append nothing, got %d", len(h.audits))
	}
}
