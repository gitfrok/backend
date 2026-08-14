package app

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/gitfrok/backend/modules/security/api"
	"github.com/gitfrok/backend/modules/security/internal/domain"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
	platformaudit "github.com/gitfrok/backend/platform/audit"
	"github.com/gitfrok/backend/platform/bus"
	"github.com/gitfrok/backend/platform/ids"
)

// cursorKeyBytes is the HMAC key length for signed list cursors.
const cursorKeyBytes = 32

// Service is the Security/Findings application service (SPEC-0024,
// SPEC-0025). It is the only place an ingest request meets the PDP, the only
// place identities are computed, and the only place events and audit records
// are emitted — the store persists, the gRPC adapter adapts, and neither
// decides.
type Service struct {
	store     Store
	pdp       policyapi.DecisionPoint
	bus       bus.Bus
	newID     func() string
	now       func() time.Time
	cursorKey [cursorKeyBytes]byte
}

// Option configures the service for tests and composition.
type Option func(*Service)

// WithIDs replaces the event-ID source (tests pin it).
func WithIDs(newID func() string) Option { return func(s *Service) { s.newID = newID } }

// WithClock replaces the clock (tests pin it).
func WithClock(now func() time.Time) Option { return func(s *Service) { s.now = now } }

// WithCursorKey pins the cursor signing key; two services sharing a key
// accept each other's cursors.
func WithCursorKey(key [cursorKeyBytes]byte) Option {
	return func(s *Service) { s.cursorKey = key }
}

// New builds the service. A nil store or PDP is a composition error: without
// a PDP there is no authorization answer (invariant 2), and without a store
// there is no persistence — both are refused here rather than discovered on
// the first request.
func New(store Store, pdp policyapi.DecisionPoint, events bus.Bus, opts ...Option) *Service {
	if store == nil {
		panic("security: no store — findings need persistence")
	}
	if pdp == nil {
		panic("security: no PDP — every ingest and read needs a decision (invariant 2)")
	}
	s := &Service{store: store, pdp: pdp, bus: events, newID: ids.NewULID, now: time.Now}
	for _, opt := range opts {
		opt(s)
	}
	if s.cursorKey == ([cursorKeyBytes]byte{}) {
		if _, err := rand.Read(s.cursorKey[:]); err != nil {
			panic("security: no entropy for cursor signing: " + err.Error())
		}
	}
	return s
}

// IngestScanResults ingests one chunk of a completed scan's batch
// (SPEC-0025). The order of operations is the security statement:
//
//  1. validate the request context and the boundary bounds — a malformed
//     request is rejected whole, before any decision or write;
//  2. ask the PDP with server-derived context — no caller-asserted outcome;
//  3. compute identities server-side — no adapter can assert one;
//  4. hand the chunk to the store, which is serializable per scan and
//     idempotent per request ID;
//  5. only after a successful, non-replayed completion, emit events and the
//     one audit record (SPEC-0025 AC1/AC5).
func (s *Service) IngestScanResults(ctx context.Context, chunk api.IngestChunk) (api.IngestResult, error) {
	if !validContext(chunk.Context) || chunk.Revision == "" {
		return api.IngestResult{}, api.ErrDenied
	}
	if err := validateChunk(chunk); err != nil {
		return api.IngestResult{}, err
	}

	// The PDP decides with server-derived context: scanner class, tool
	// identity, and revision are facts from this request's validated scan
	// descriptor, never claims a caller can dress up as something else
	// (SPEC-0025 vocabulary table).
	decision, err := s.pdp.Decide(ctx, policyapi.Request{
		TenantID: chunk.TenantID,
		Subject: policyapi.Subject{
			ID: chunk.ActorID, TenantID: chunk.TenantID,
			Roles: append([]string(nil), chunk.ActorRoles...),
		},
		Action:   "findings.ingest",
		Resource: policyapi.Resource{Type: "repository", ID: chunk.RepositoryID},
		Context: map[string]string{
			"scanner_class": string(chunk.Scan.ScannerClass),
			"tool_name":     chunk.Scan.ToolName,
			"revision":      chunk.Revision,
		},
	})
	if err != nil || !decision.Allowed {
		// The PDP records its own denial on the immutable denial path
		// (ADR-0007); this service adds nothing and reveals nothing.
		return api.IngestResult{}, api.ErrDenied
	}

	// Identity is server-computed per SPEC-0024, before anything reaches the
	// store. The input set is closed: no revision, no scan run, no line
	// number, no tool version, no provenance.
	prepared := make([]PreparedFinding, 0, len(chunk.Findings))
	for _, raw := range chunk.Findings {
		prepared = append(prepared, PreparedFinding{
			Identity: domain.Identity(domain.IdentityInput{
				TenantID:     chunk.TenantID,
				RepositoryID: chunk.RepositoryID,
				ScannerClass: domain.ScannerClass(chunk.Scan.ScannerClass),
				ToolName:     chunk.Scan.ToolName,
				RuleID:       raw.RuleID,
				Location: domain.Location{
					ArtifactPath:     raw.Location.ArtifactPath,
					EnclosingContent: raw.Location.EnclosingContent,
					Component:        raw.Location.Component,
					ComponentVersion: raw.Location.ComponentVersion,
				},
			}),
			Raw: raw,
		})
	}

	outcome, err := s.store.IngestChunk(ctx, IngestParams{
		TenantID:     chunk.TenantID,
		RepositoryID: chunk.RepositoryID,
		Revision:     chunk.Revision,
		Scan:         chunk.Scan,
		ScanID:       scanID(chunk),
		ChunkIndex:   chunk.ChunkIndex,
		RequestID:    chunk.RequestID,
		FinalChunk:   chunk.FinalChunk,
		Findings:     prepared,
	})
	if err != nil {
		return api.IngestResult{}, api.ErrDenied
	}

	result := api.IngestResult{
		ScanID:           outcome.ScanID,
		FindingsRecorded: outcome.FindingsRecorded,
		Completed:        outcome.Completed,
		Replayed:         outcome.Replayed,
	}
	// A replay reports the recorded outcome and creates no event and no
	// second audit record of the same ingest (SPEC-0025 AC1). A non-final
	// chunk is invisible to readers and emits nothing.
	if outcome.Replayed || !outcome.Completed {
		return result, nil
	}

	now := s.now().UTC()
	for _, f := range outcome.Opened {
		if err := s.bus.Publish(ctx, api.FindingOpened{
			EventID: s.newID(), FindingID: f.ID, TenantID: f.TenantID, RepositoryID: f.RepositoryID,
			ScanID: outcome.ScanID, ScannerClass: f.ScannerClass, ToolName: f.ToolName,
			RuleID: f.RuleID, Severity: f.Severity, OccurredAt: now,
		}); err != nil {
			return api.IngestResult{}, fmt.Errorf("security: publish FindingOpened: %w", err)
		}
	}
	for _, f := range outcome.Resolved {
		if err := s.bus.Publish(ctx, api.FindingResolved{
			EventID: s.newID(), FindingID: f.ID, TenantID: f.TenantID, RepositoryID: f.RepositoryID,
			ScanID: outcome.ScanID, ScannerClass: f.ScannerClass, ToolName: f.ToolName,
			RuleID: f.RuleID, Severity: f.Severity, OccurredAt: now,
		}); err != nil {
			return api.IngestResult{}, fmt.Errorf("security: publish FindingResolved: %w", err)
		}
	}
	if err := s.bus.Publish(ctx, api.ScanIngested{
		EventID: s.newID(), TenantID: chunk.TenantID, RepositoryID: chunk.RepositoryID,
		ScanID: outcome.ScanID, ScannerClass: chunk.Scan.ScannerClass,
		ToolName: chunk.Scan.ToolName, ToolVersion: chunk.Scan.ToolVersion,
		Revision: chunk.Revision, FindingCount: int64(len(chunk.Findings)), OccurredAt: now,
	}); err != nil {
		return api.IngestResult{}, fmt.Errorf("security: publish ScanIngested: %w", err)
	}

	// AC5: an accepted ingest appends exactly one immutable audit record —
	// tenant, actor, repository resource, action, outcome, request ID, and
	// decision ID. It is published on the audit bus; the audit sink makes it
	// durable. This is the ONLY emission point, and the replay early-return
	// above is what keeps it exactly-once.
	if s.bus != nil {
		if err := s.bus.Publish(ctx, platformaudit.FindingsScanIngested{
			TenantID: chunk.TenantID, ActorID: chunk.ActorID, RepositoryID: chunk.RepositoryID,
			ScanID: outcome.ScanID, RequestID: chunk.RequestID,
			PolicyDecisionID: decision.DecisionID, FindingsRecorded: result.FindingsRecorded,
			OccurredAt: now,
		}); err != nil {
			return api.IngestResult{}, fmt.Errorf("security: audit ingest: %w", err)
		}
	}
	return result, nil
}

// GetFinding returns one finding. The PDP decides first — resource type
// "finding", per the SPEC-0025 vocabulary — and the read itself is
// tenant-scoped by the store. Not-found, cross-tenant, and unauthorized are
// the same coarse denial (SPEC-0001).
func (s *Service) GetFinding(ctx context.Context, c api.Context, findingID string) (api.Finding, error) {
	if !validContext(c) || findingID == "" {
		return api.Finding{}, api.ErrDenied
	}
	if !s.allowed(ctx, c, "findings.read", "finding", findingID, map[string]string{}) {
		return api.Finding{}, api.ErrDenied
	}
	f, err := s.store.GetFinding(ctx, c.TenantID, findingID)
	if err != nil {
		return api.Finding{}, api.ErrDenied
	}
	return f, nil
}

// ListFindings pages a tenant-scoped, filtered listing (SPEC-0025). The
// listing is always scoped to the verified context's repository: a filter
// naming any other repository is a coarse denial, which is what stops a
// listing from enumerating repositories the caller cannot name.
func (s *Service) ListFindings(ctx context.Context, req api.ListRequest) (api.ListPage, error) {
	if !validContext(req.Context) {
		return api.ListPage{}, api.ErrDenied
	}
	if req.RepositoryFilter != "" && req.RepositoryFilter != req.RepositoryID {
		return api.ListPage{}, api.ErrDenied
	}
	attrs := map[string]string{}
	if req.ScannerClassFilter != "" {
		attrs["scanner_class"] = string(req.ScannerClassFilter)
	}
	if req.SeverityFilter != "" {
		attrs["severity"] = string(req.SeverityFilter)
	}
	if req.LifecycleFilter != "" {
		attrs["lifecycle"] = string(req.LifecycleFilter)
	}
	if !s.allowed(ctx, req.Context, "findings.read", "repository", req.RepositoryID, attrs) {
		return api.ListPage{}, api.ErrDenied
	}

	limit := req.PageSize
	if limit <= 0 {
		limit = api.DefaultPageSize
	}
	if limit > api.MaxPageSize {
		limit = api.MaxPageSize
	}

	filter := ListFilter{
		RepositoryID: req.RepositoryID,
		ScannerClass: req.ScannerClassFilter,
		Severity:     req.SeverityFilter,
		Lifecycle:    req.LifecycleFilter,
		Limit:        limit + 1, // one extra row tells us a next page exists
	}
	if req.PageToken != "" {
		cursor, ok := s.decodeCursor(req.PageToken, req)
		if !ok {
			// A forged, stale, or cross-tenant cursor yields no content —
			// never an error that distinguishes it from an empty list
			// (SPEC-0025).
			return api.ListPage{}, nil
		}
		filter.AfterID = cursor.AfterID
	}

	rows, err := s.store.ListFindings(ctx, req.TenantID, filter)
	if err != nil {
		return api.ListPage{}, api.ErrDenied
	}

	page := api.ListPage{}
	if len(rows) > limit {
		page.Findings = rows[:limit]
		page.NextPageToken = s.encodeCursor(req, rows[limit-1].ID)
	} else {
		page.Findings = rows
	}
	if page.Findings == nil {
		page.Findings = []api.Finding{}
	}
	return page, nil
}

// allowed asks the PDP. Any error is a refusal: a decision that was not
// reached denies (ADR-0006).
func (s *Service) allowed(ctx context.Context, principal api.Context, action, resourceType, resourceID string, attributes map[string]string) bool {
	decision, err := s.pdp.Decide(ctx, policyapi.Request{
		TenantID: principal.TenantID,
		Subject: policyapi.Subject{
			ID: principal.ActorID, TenantID: principal.TenantID,
			Roles: append([]string(nil), principal.ActorRoles...),
		},
		Action:   action,
		Resource: policyapi.Resource{Type: resourceType, ID: resourceID},
		Context:  attributes,
	})
	return err == nil && decision.Allowed
}

// validContext is the verified-identity check every operation applies. An
// incomplete context is a coarse denial rather than a partial call
// (SPEC-0025).
func validContext(c api.Context) bool {
	return c.TenantID != "" && c.RepositoryID != "" && c.ActorID != "" && c.RequestID != ""
}

// validateChunk applies the boundary bounds: a malformed request is rejected
// whole, before any decision or write, without partial ingest (SPEC-0025
// AC6).
func validateChunk(chunk api.IngestChunk) error {
	if !chunk.Scan.ScannerClass.Valid() || chunk.Scan.ToolName == "" || chunk.Scan.StartedAt.IsZero() {
		return api.ErrMalformed
	}
	if chunk.ChunkIndex < 0 || len(chunk.Findings) > api.MaxFindingsPerChunk {
		return api.ErrMalformed
	}
	for _, raw := range chunk.Findings {
		if raw.RuleID == "" || !validSeverity(raw.Severity) {
			return api.ErrMalformed
		}
		if len(raw.Provenance) > api.MaxProvenanceBytes {
			return api.ErrMalformed
		}
		// Provenance round-trips only with its media type: a blob without
		// one, or a media type without a blob, is rejected at the boundary.
		if (len(raw.Provenance) == 0) != (raw.ProvenanceMediaType == "") {
			return api.ErrMalformed
		}
	}
	return nil
}

func validSeverity(s api.Severity) bool {
	switch s {
	case api.SeverityLow, api.SeverityMedium, api.SeverityHigh, api.SeverityCritical:
		return true
	}
	return false
}

// ScannerClass.Valid mirrors domain.ScannerClass.Valid without importing the
// domain's string constants into the api boundary check; the api constants
// are the same one-of-five values.
func init() {
	for _, c := range []api.ScannerClass{
		api.ScannerClassSAST, api.ScannerClassDependency, api.ScannerClassSecrets,
		api.ScannerClassContainer, api.ScannerClassDAST,
	} {
		if !domain.ScannerClass(c).Valid() {
			panic("security: api scanner class drift from domain: " + c)
		}
	}
}

// scanID derives the scan record's opaque identity server-side. It is a
// deterministic function of the scan descriptor, so a redelivered chunk of
// the same scan lands on the same record — and two different scans (even of
// the same repository by the same tool) never share one. The revision is
// deliberately not an input: identity is invariant to it, and two scans of
// the same revision by the same tool at different times are two scans.
func scanID(chunk api.IngestChunk) string {
	h := sha256.New()
	for _, field := range []string{
		chunk.TenantID, chunk.RepositoryID,
		string(chunk.Scan.ScannerClass), chunk.Scan.ToolName,
		chunk.Scan.StartedAt.UTC().Format(time.RFC3339Nano),
		chunk.Scan.EndedAt.UTC().Format(time.RFC3339Nano),
	} {
		io.WriteString(h, field)
		io.WriteString(h, "\x00")
	}
	return "scan-" + hex.EncodeToString(h.Sum(nil))[:32]
}

// cursor is the signed payload of a list page token. It binds the cursor to
// the tenant and the exact filters that issued it: a token issued for one
// listing is inert under another (SPEC-0025).
type cursor struct {
	TenantID   string
	Repository string
	Class      api.ScannerClass
	Severity   api.Severity
	Lifecycle  api.Lifecycle
	AfterID    string
}

func (s *Service) encodeCursor(req api.ListRequest, lastID string) string {
	c := cursor{
		TenantID: req.TenantID, Repository: req.RepositoryID,
		Class: req.ScannerClassFilter, Severity: req.SeverityFilter,
		Lifecycle: req.LifecycleFilter, AfterID: lastID,
	}
	payload, err := json.Marshal(c)
	if err != nil {
		return "" // unencodable means no next page; never a partial token
	}
	mac := hmac.New(sha256.New, s.cursorKey[:])
	mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (s *Service) decodeCursor(token string, req api.ListRequest) (cursor, bool) {
	payloadB64, macB64, ok := splitToken(token)
	if !ok {
		return cursor{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return cursor{}, false
	}
	sig, err := base64.RawURLEncoding.DecodeString(macB64)
	if err != nil {
		return cursor{}, false
	}
	mac := hmac.New(sha256.New, s.cursorKey[:])
	mac.Write(payload)
	if !hmac.Equal(mac.Sum(nil), sig) {
		return cursor{}, false
	}
	var c cursor
	if err := json.Unmarshal(payload, &c); err != nil {
		return cursor{}, false
	}
	// Bound to the tenant and the filters that issued it.
	if c.TenantID != req.TenantID || c.Repository != req.RepositoryID ||
		c.Class != req.ScannerClassFilter || c.Severity != req.SeverityFilter ||
		c.Lifecycle != req.LifecycleFilter || c.AfterID == "" {
		return cursor{}, false
	}
	return c, true
}

func splitToken(token string) (payload, mac string, ok bool) {
	for i := range len(token) {
		if token[i] == '.' {
			if i == 0 || i == len(token)-1 {
				return "", "", false
			}
			return token[:i], token[i+1:], true
		}
	}
	return "", "", false
}
