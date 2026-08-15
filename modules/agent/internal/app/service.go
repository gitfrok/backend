// Package app is the Agent context's application layer: the enrolment handshake, connection
// admission, certificate rotation decisions, the operator surface, and every audit emission
// point the surface has (SPEC-0038 AC7). It composes the domain with ports — PDP, bus,
// certificate issuer, stores — and never touches infrastructure itself (invariant 16).
package app

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/gitfrok/backend/modules/agent/api"
	"github.com/gitfrok/backend/modules/agent/internal/domain"
	identityapi "github.com/gitfrok/backend/modules/identity/api"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
	platformaudit "github.com/gitfrok/backend/platform/audit"
	"github.com/gitfrok/backend/platform/bus"
	"github.com/gitfrok/backend/platform/ids"
	"github.com/gitfrok/backend/platform/tenancy"
)

// The operator action vocabulary this surface asks the PDP about (invariant 2). The rules
// themselves live in governance/policies; adding them there is a governance change, not a
// change here.
const (
	actionTokenIssue      = "agent.enrolment_token.issue"
	actionTokenRevoke     = "agent.enrolment_token.revoke"
	actionDataPlaneRevoke = "agent.dataplane.revoke"
	actionDataPlaneRead   = "agent.dataplane.read"
)

// Coarse refusal prose for the wire's `detail` field. Never echoes the token, never names
// a cause more finely than the refusal enum already does (SPEC-0038 AC2, AC9).
const (
	detailInvalid = "enrolment refused: the token is not valid"
	detailSpent   = "enrolment refused: the token has already been used"
	detailExpired = "enrolment refused: the token has expired"
	detailRevoked = "enrolment refused: the token was revoked"
	detailDenied  = "enrolment refused"
)

// TokenStore is the persistence port for enrolment tokens.
type TokenStore interface {
	PutToken(ctx context.Context, t domain.Token) error
	TokenByHash(ctx context.Context, hash [32]byte) (domain.Token, bool, error)
	TokenByID(ctx context.Context, tenantID, tokenID string) (domain.Token, bool, error)
	TokensByTenant(ctx context.Context, tenantID string) ([]domain.Token, error)
	ClaimToken(ctx context.Context, hash [32]byte, dataPlaneID string, now time.Time) (domain.Token, bool, error)
	RevokeToken(ctx context.Context, tenantID, tokenID string, now time.Time) error
	// ReleaseClaim un-spends a token whose enrolment failed at certificate
	// issuance (SPEC-0042 AC6), keeping its recorded data-plane ID so the
	// retry re-binds to the SAME identity — one token never mints two data
	// planes (ADR-0060). Unknown or another tenant's token is the shared
	// not-found sentinel.
	ReleaseClaim(ctx context.Context, tenantID, tokenID string) error
}

// RegistryStore is the persistence port for the data-plane registry.
type RegistryStore interface {
	PutDataPlane(ctx context.Context, d domain.DataPlane) error
	DataPlane(ctx context.Context, tenantID, id string) (domain.DataPlane, bool, error)
	DataPlanesByTenant(ctx context.Context, tenantID string) ([]domain.DataPlane, error)
	MarkSeen(ctx context.Context, tenantID, id string, now time.Time) error
	SetCertificate(ctx context.Context, tenantID, id, certID string, expiresAt time.Time) error
	RevokeDataPlane(ctx context.Context, tenantID, id string, now time.Time) error
}

// Service is the composed application service. One instance owns both halves of the api
// surface — Operator and Gateway — because they share the stores, the issuer and the audit
// emission points.
type Service struct {
	pdp      policyapi.DecisionPoint
	events   bus.Bus
	issuer   api.CertificateIssuer
	tokens   TokenStore
	registry RegistryStore
	cfg      api.Config
	logf     func(format string, args ...any)
	// gate is the residency enforcement port consulted at enrolment (T-0033,
	// SPEC-0040 AC2); nil until the composition root attaches one. Reads and
	// writes go through mu: attachment is post-construction.
	gate api.PlacementGate

	mu      sync.Mutex
	streams map[api.Identity]*streamSession
}

// SetPlacementGate attaches the residency gate post-construction (the Attach* pattern):
// the Residency context is composed after the agent surface, and the module graph stays
// acyclic because the gate is a port in this context's own terms (invariant 14).
func (s *Service) SetPlacementGate(g api.PlacementGate) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gate = g
}

// New wires the service. A nil PDP, bus or issuer is refused: an agent surface without a
// decision point would authorize nothing and admit everything by silence, which is the
// failure mode invariant 2 exists to make impossible.
func New(pdp policyapi.DecisionPoint, events bus.Bus, issuer api.CertificateIssuer, tokens TokenStore, registry RegistryStore, cfg api.Config, logf func(format string, args ...any)) *Service {
	if pdp == nil {
		panic("agent: no PDP — every operator action needs a decision (invariant 2)")
	}
	if events == nil || issuer == nil || tokens == nil || registry == nil {
		panic("agent: bus, certificate issuer and stores are all required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Service{pdp: pdp, events: events, issuer: issuer, tokens: tokens, registry: registry, cfg: cfg, logf: logf, streams: make(map[api.Identity]*streamSession)}
}

// Compile-time proof that one service carries both halves of the surface.
var _ api.Operator = (*Service)(nil)
var _ api.Gateway = (*Service)(nil)

// --- Operator surface ---------------------------------------------------------------

// IssueEnrolmentToken mints one single-use, tenant-scoped, time-bounded token (SPEC-0038
// AC1). The secret is returned exactly once; only its hash is stored, and neither ever
// appears in a log line, an error, or an audit record (AC2).
func (s *Service) IssueEnrolmentToken(ctx context.Context, tenantID, actorID string, lifetime time.Duration) (api.EnrolmentToken, string, error) {
	if err := s.authorize(ctx, tenantID, actionTokenIssue, "enrolment_token", ""); err != nil {
		return api.EnrolmentToken{}, "", err
	}
	if lifetime <= 0 || lifetime > s.cfg.TokenMaxLifetime {
		lifetime = s.cfg.TokenMaxLifetime
	}
	secret, err := domain.GenerateSecret()
	if err != nil {
		return api.EnrolmentToken{}, "", err
	}
	now := s.cfg.Now()
	tok := domain.Token{
		ID: ids.NewULID(), TenantID: tenantID, IssuedBy: actorID,
		TokenHash: domain.HashSecret(secret),
		IssuedAt:  now, ExpiresAt: now.Add(lifetime),
	}
	if err := s.tokens.PutToken(ctx, tok); err != nil {
		return api.EnrolmentToken{}, "", err
	}
	if err := s.publish(ctx, platformaudit.AgentTokenIssued{
		TenantID: tenantID, ActorID: actorID, TokenID: tok.ID,
		ExpiresAt: tok.ExpiresAt, OccurredAt: now,
	}); err != nil {
		return api.EnrolmentToken{}, "", err
	}
	return api.EnrolmentToken{
		ID: tok.ID, TenantID: tok.TenantID, IssuedBy: tok.IssuedBy,
		IssuedAt: tok.IssuedAt, ExpiresAt: tok.ExpiresAt,
	}, secret, nil
}

// RevokeEnrolmentToken revokes an unspent token and audits the act.
func (s *Service) RevokeEnrolmentToken(ctx context.Context, tenantID, actorID, tokenID string) error {
	if err := s.authorize(ctx, tenantID, actionTokenRevoke, "enrolment_token", tokenID); err != nil {
		return err
	}
	now := s.cfg.Now()
	if err := s.tokens.RevokeToken(ctx, tenantID, tokenID, now); err != nil {
		return mapStoreErr(err)
	}
	return s.publish(ctx, platformaudit.AgentTokenRevoked{
		TenantID: tenantID, ActorID: actorID, TokenID: tokenID, OccurredAt: now,
	})
}

// RevokeDataPlane revokes a data plane's identity: the next connection is refused, any live
// stream is ended, and nothing in the customer's cluster is touched (ADR-0060 §5).
func (s *Service) RevokeDataPlane(ctx context.Context, tenantID, actorID, dataPlaneID string) error {
	if err := s.authorize(ctx, tenantID, actionDataPlaneRevoke, "data_plane", dataPlaneID); err != nil {
		return err
	}
	now := s.cfg.Now()
	if err := s.registry.RevokeDataPlane(ctx, tenantID, dataPlaneID, now); err != nil {
		return mapStoreErr(err)
	}
	if err := s.publish(ctx, platformaudit.AgentDataPlaneRevoked{
		TenantID: tenantID, ActorID: actorID, DataPlaneID: dataPlaneID, OccurredAt: now,
	}); err != nil {
		return err
	}
	// End any live stream for the revoked identity. The revocation itself is the audit
	// record; the closed stream is the enforcement.
	s.endStreams(api.Identity{TenantID: tenantID, DataPlaneID: dataPlaneID})
	return nil
}

// GetDataPlane reads one registry record with its derived status. A missing or another
// tenant's ID yields ErrNotFound — one coarse shape (SPEC-0038 AC9).
func (s *Service) GetDataPlane(ctx context.Context, tenantID, actorID, dataPlaneID string) (api.DataPlane, error) {
	if err := s.authorize(ctx, tenantID, actionDataPlaneRead, "data_plane", dataPlaneID); err != nil {
		return api.DataPlane{}, err
	}
	d, ok, err := s.registry.DataPlane(ctx, tenantID, dataPlaneID)
	if err != nil {
		return api.DataPlane{}, err
	}
	if !ok {
		return api.DataPlane{}, api.ErrNotFound
	}
	return s.toAPI(d), nil
}

// Fleet is the operator's AC8 view: data planes with derived status, and unspent tokens as
// never-connected rows. Stale reads stale — never healthy.
func (s *Service) Fleet(ctx context.Context, tenantID, actorID string) ([]api.FleetView, error) {
	if err := s.authorize(ctx, tenantID, actionDataPlaneRead, "data_plane", ""); err != nil {
		return nil, err
	}
	now := s.cfg.Now()
	planes, err := s.registry.DataPlanesByTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]api.FleetView, 0, len(planes))
	for _, d := range planes {
		out = append(out, api.FleetView{Status: s.deriveStatus(d, now), Plane: s.toAPI(d)})
	}
	tokens, err := s.tokens.TokensByTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	for _, t := range tokens {
		// An unspent, unrevoked, unexpired token is a provisioned data plane that never
		// connected. Everything else is visible through its own lifecycle records.
		if !t.Spent() && !t.Revoked() && now.Before(t.ExpiresAt) {
			out = append(out, api.FleetView{Status: api.StatusNeverConnected, TokenID: t.ID})
		}
	}
	return out, nil
}

// --- Gateway surface ----------------------------------------------------------------

// Enrol runs the first-Connect handshake (ADR-0060 §1). The token is spent BEFORE the
// certificate is issued; if issuance then fails, the claim is released but keeps its
// recorded data-plane ID, so the retry completes the SAME identity — one token never
// mints two data planes (SPEC-0042 AC6, SPEC-0038 AC1).
func (s *Service) Enrol(ctx context.Context, req api.EnrolRequest) (api.Enrolment, error) {
	now := s.cfg.Now()
	if req.Token == "" {
		// Unattributable: no tenant exists for a shapeless presentation, so there is no
		// scope to audit under (the bus carries only tenant-scoped records). The refusal
		// itself is coarse and carries nothing of the presenter.
		s.logf("agent: enrolment refused: token not valid")
		return api.Enrolment{}, &api.EnrolmentRefused{Reason: api.RefusalTokenInvalid}
	}
	hash := domain.HashSecret(req.Token)
	tok, ok, err := s.tokens.TokenByHash(ctx, hash)
	if err != nil {
		return api.Enrolment{}, err
	}
	if !ok {
		// Unknown token: indistinguishable from a malformed one and from another
		// tenant's (SPEC-0038 AC9). Also unattributable — see above.
		s.logf("agent: enrolment refused: token not valid")
		return api.Enrolment{}, &api.EnrolmentRefused{Reason: api.RefusalTokenInvalid}
	}
	// From here the tenant is known — bind it into ctx so every store write and
	// audit emission below runs under the token's own tenancy.
	ctx = tenancy.WithTenant(ctx, tenancy.ID(tok.TenantID))
	if reason := tok.PresentOutcome(now); reason != "" {
		if err := s.publish(ctx, platformaudit.AgentEnrolment{
			TenantID: tok.TenantID, TokenID: tok.ID, Reason: string(reason),
			Outcome: "DENIED", OccurredAt: now,
		}); err != nil {
			return api.Enrolment{}, err
		}
		return api.Enrolment{}, &api.EnrolmentRefused{Reason: reason}
	}

	// A retry after a released claim (AC6) re-binds the SAME identity: the
	// recorded data plane wins over minting a new one (ADR-0060).
	dataPlaneID := tok.DataPlaneID
	if dataPlaneID == "" {
		dataPlaneID = ids.NewULID()
	}

	// Residency gate BEFORE token spend: a placement refused at the declared boundary
	// costs the tenant nothing — the token stays presentable so the operator can retry
	// from an allowed placement (T-0033, SPEC-0040 AC2). The gate is consulted under the
	// token's own tenancy scope, and every gate error is one coarse DENIED enrolment: an
	// explicit residency refusal and an unreachable gate are indistinguishable from
	// outside (SPEC-0001). No gate attached means the tenant has declared no residency
	// constraints — placement is admitted unwitnessed.
	s.mu.Lock()
	gate := s.gate
	s.mu.Unlock()
	if gate != nil {
		gctx := tenancy.WithTenant(ctx, tenancy.ID(tok.TenantID))
		if err := gate.CheckPlacement(gctx, tok.TenantID, dataPlaneID, req.Cloud, req.Region); err != nil {
			if perr := s.publish(ctx, platformaudit.AgentEnrolment{
				TenantID: tok.TenantID, DataPlaneID: dataPlaneID, TokenID: tok.ID,
				Reason: "residency_placement_refused", Outcome: "DENIED", OccurredAt: now,
			}); perr != nil {
				return api.Enrolment{}, perr
			}
			s.logf("agent: enrolment refused: residency placement")
			return api.Enrolment{}, &api.EnrolmentRefused{Reason: api.RefusalDenied}
		}
	}

	// Spend first. From this line on the token is spent whatever happens next —
	// until an issuance failure releases the claim (AC6), keeping the identity.
	if claimed, ok, err := s.tokens.ClaimToken(ctx, hash, dataPlaneID, now); err != nil {
		return api.Enrolment{}, err
	} else if !ok {
		// The claim refused — and the row itself says WHY. Re-read and name
		// the true cause: a revoked or expired token is an operator-visible
		// state, and token_spent is reserved for the true single-use race.
		reason := api.RefusalTokenSpent
		fresh, found, lerr := s.tokens.TokenByHash(ctx, hash)
		if lerr != nil {
			return api.Enrolment{}, lerr
		}
		if found {
			if r := fresh.PresentOutcome(now); r != "" {
				reason = r
			}
		}
		if err := s.publish(ctx, platformaudit.AgentEnrolment{
			TenantID: tok.TenantID, TokenID: tok.ID, Reason: string(reason),
			Outcome: "DENIED", OccurredAt: now,
		}); err != nil {
			return api.Enrolment{}, err
		}
		return api.Enrolment{}, &api.EnrolmentRefused{Reason: reason}
	} else if claimed.DataPlaneID != "" {
		// The claim's recorded identity is authoritative: it is the one this
		// token has ever minted (ADR-0060).
		dataPlaneID = claimed.DataPlaneID
	}

	id := api.Identity{TenantID: tok.TenantID, DataPlaneID: dataPlaneID}
	plane := domain.DataPlane{
		ID: dataPlaneID, TenantID: tok.TenantID,
		Cloud: req.Cloud, Region: req.Region,
		AgentVersion: req.AgentVersion, K8sVersion: req.K8sVersion,
		Capabilities: slices.Clone(req.Capabilities),
		EnrolledAt:   now, LastSeenAt: now,
	}
	if err := s.registry.PutDataPlane(ctx, plane); err != nil {
		return api.Enrolment{}, err
	}
	cert, err := s.issuer.Issue(ctx, id, now, s.cfg.CertLifetime, s.cfg.ClockSkewLeeway)
	if err != nil {
		// Issuance failed AFTER the spend (SPEC-0042 AC6, locked decision):
		// audit the failure, then RELEASE the claim — keeping its recorded
		// data-plane ID so the presenter's retry re-binds to the SAME identity.
		// One token never mints two data planes (ADR-0060); no runbook ritual
		// is needed because the retry IS the recovery. The registry record
		// stays — visible as never connected until the retry completes it.
		return api.Enrolment{}, s.failAfterSpend(ctx, tok, dataPlaneID, now, "certificate_issuance_failed")
	}
	if err := s.registry.SetCertificate(ctx, tok.TenantID, dataPlaneID, cert.CertificateID, cert.ExpiresAt); err != nil {
		return api.Enrolment{}, s.failAfterSpend(ctx, tok, dataPlaneID, now, "certificate_record_failed")
	}
	if err := s.publish(ctx, platformaudit.AgentEnrolment{
		TenantID: tok.TenantID, DataPlaneID: dataPlaneID, TokenID: tok.ID,
		Outcome: "ALLOWED", OccurredAt: now,
	}); err != nil {
		return api.Enrolment{}, s.failAfterSpend(ctx, tok, dataPlaneID, now, "enrolment_audit_failed")
	}
	if err := s.publish(ctx, platformaudit.AgentCertificateIssued{
		TenantID: tok.TenantID, DataPlaneID: dataPlaneID, CertificateID: cert.CertificateID,
		ExpiresAt: cert.ExpiresAt, OccurredAt: now,
	}); err != nil {
		return api.Enrolment{}, s.failAfterSpend(ctx, tok, dataPlaneID, now, "certificate_audit_failed")
	}
	return api.Enrolment{Identity: id, Certificate: cert, HeartbeatInterval: s.cfg.HeartbeatInterval}, nil
}

// failAfterSpend is the AC6 recovery shape applied to the WHOLE post-spend
// tail: whatever fails after the token was spent — issuance, the certificate
// record, either audit emission — audits one coarse DENIED enrolment, then
// RELEASES the claim. A failed release is logged, not converted into a
// second outcome: the refusal is already audited, and the operator-visible
// shape is unchanged — retry, and if the release was lost, re-issue. The
// claim's recorded data-plane ID survives the release (the claim CASE guard
// preserves it), so the retry re-binds the SAME identity: one token never
// mints two data planes (ADR-0060), and the retry IS the recovery.
func (s *Service) failAfterSpend(ctx context.Context, tok domain.Token, dataPlaneID string, now time.Time, reason string) error {
	if perr := s.publish(ctx, platformaudit.AgentEnrolment{
		TenantID: tok.TenantID, DataPlaneID: dataPlaneID, TokenID: tok.ID,
		Reason: reason, Outcome: "DENIED", OccurredAt: now,
	}); perr != nil {
		return perr
	}
	if rerr := s.tokens.ReleaseClaim(ctx, tok.TenantID, tok.ID); rerr != nil {
		s.logf("agent: release claim failed after %s: %v", reason, rerr)
	}
	s.logf("agent: enrolment failed after token spent: %s; claim released", reason)
	return &api.EnrolmentRefused{Reason: api.RefusalDenied}
}

// AdmitPeerCertificates is the handshake-time admission for certificate-authenticated
// connections (SPEC-0038 AC5). Every refusal it makes is audited; an untrusted chain is
// not, because nothing about it is attributable to a tenant.
func (s *Service) AdmitPeerCertificates(ctx context.Context, rawCerts [][]byte) (api.Identity, error) {
	now := s.cfg.Now()
	leafDER, validity, err := s.issuer.VerifyChain(rawCerts, now)
	if err != nil {
		return api.Identity{}, err
	}
	id, _, err := s.issuer.Inspect(leafDER)
	if err != nil {
		return api.Identity{}, err
	}
	// The leaf names the tenant: every record below is written under it.
	ctx = tenancy.WithTenant(ctx, tenancy.ID(id.TenantID))
	// Both non-valid states refuse. They are audited apart because they mean different
	// things to whoever reads the trail: a rotation that did not happen, versus a clock
	// the customer's cluster cannot be trusted on (SPEC-0038 non-functional).
	switch validity {
	case api.ValidityExpired:
		s.refuseConnection(ctx, id, "certificate_expired", now)
		return api.Identity{}, api.ErrNotFound
	case api.ValidityNotYetValid:
		s.refuseConnection(ctx, id, "certificate_not_yet_valid", now)
		return api.Identity{}, api.ErrNotFound
	}
	d, ok, err := s.registry.DataPlane(ctx, id.TenantID, id.DataPlaneID)
	if err != nil {
		return api.Identity{}, err
	}
	if !ok {
		s.refuseConnection(ctx, id, "unknown_identity", now)
		return api.Identity{}, api.ErrNotFound
	}
	if d.Revoked() {
		s.refuseConnection(ctx, id, "revoked", now)
		return api.Identity{}, api.ErrRevoked
	}
	return id, nil
}

// IdentityOf names the identity a presented leaf certificate carries, for a stream already
// admitted at the handshake.
func (s *Service) IdentityOf(leafDER []byte) (api.Identity, error) {
	id, _, err := s.issuer.Inspect(leafDER)
	return id, err
}

// OpenStream registers an admitted stream and opens its rotation session.
func (s *Service) OpenStream(ctx context.Context, id api.Identity) (api.StreamSession, error) {
	// The admitted identity names the tenant its registry writes run under.
	ctx = tenancy.WithTenant(ctx, tenancy.ID(id.TenantID))
	d, ok, err := s.registry.DataPlane(ctx, id.TenantID, id.DataPlaneID)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, api.ErrNotFound
	}
	if d.Revoked() {
		return nil, api.ErrRevoked
	}
	now := s.cfg.Now()
	if err := s.registry.MarkSeen(ctx, id.TenantID, id.DataPlaneID, now); err != nil {
		return nil, err
	}
	ss := &streamSession{
		svc: s, id: id, done: make(chan struct{}),
		currentID: d.CurrentCertificateID, currentExpiry: d.CertificateExpiresAt,
		retryInterval: s.cfg.RotationRetryInterval,
	}
	s.mu.Lock()
	s.streams[id] = ss
	s.mu.Unlock()
	return ss, nil
}

// TokenTenant resolves the tenant a token was issued for, without spending it — the AC3
// detection seam, never an admission seam.
func (s *Service) TokenTenant(ctx context.Context, token string) (string, bool) {
	if token == "" {
		return "", false
	}
	tok, ok, err := s.tokens.TokenByHash(ctx, domain.HashSecret(token))
	if err != nil || !ok {
		return "", false
	}
	return tok.TenantID, true
}

// RefusedIdentityOverride appends the AC3 record: a payload claimed another tenant on a
// certified stream; the message was ignored at the time.
func (s *Service) RefusedIdentityOverride(ctx context.Context, id api.Identity, claimedTenant, messageID string) error {
	return s.publish(ctx, platformaudit.AgentIdentityOverrideRefused{
		TenantID: id.TenantID, DataPlaneID: id.DataPlaneID,
		ClaimedTenant: claimedTenant, MessageID: messageID, OccurredAt: s.cfg.Now(),
	})
}

// RefusedLapsed appends the two records a lapsed stream produces (SPEC-0038 AC4): the
// rotation that never completed, and the connection that ends rather than extend an
// expired certificate.
func (s *Service) RefusedLapsed(ctx context.Context, id api.Identity) error {
	now := s.cfg.Now()
	if err := s.publish(ctx, platformaudit.AgentCertificateRotation{
		TenantID: id.TenantID, DataPlaneID: id.DataPlaneID,
		Reason: "lapsed", Outcome: "DENIED", OccurredAt: now,
	}); err != nil {
		return err
	}
	return s.refuseConnection(ctx, id, "certificate_lapsed", now)
}

// --- shared machinery ---------------------------------------------------------------

// authorize is the one route from every operator action to the PDP (invariant 2). It
// mirrors the identity module's lifecycle gate: the context tenant, the claimed tenant and
// the principal's tenant must all agree before policy is even asked.
func (s *Service) authorize(ctx context.Context, requestedTenant, action, resourceType, resourceID string) error {
	tenant, err := tenancy.Require(ctx)
	if err != nil {
		return err
	}
	principal, err := identityapi.RequirePrincipal(ctx)
	if err != nil {
		return err
	}
	if string(tenant) != requestedTenant || principal.TenantID != requestedTenant {
		return api.ErrTenantMismatch
	}
	decision, err := s.pdp.Decide(ctx, policyapi.Request{
		TenantID: requestedTenant,
		Subject:  policyapi.Subject{ID: principal.ActorID, TenantID: principal.TenantID, Roles: slices.Clone(principal.Roles)},
		Action:   action,
		Resource: policyapi.Resource{Type: resourceType, ID: resourceID},
	})
	if err != nil || !decision.Allowed {
		return api.ErrAuthorizationDenied
	}
	return nil
}

// refuseConnection appends the one record every refused connection leaves (SPEC-0038 AC7).
func (s *Service) refuseConnection(ctx context.Context, id api.Identity, reason string, now time.Time) error {
	return s.publish(ctx, platformaudit.AgentConnectionRefused{
		TenantID: id.TenantID, DataPlaneID: id.DataPlaneID, Reason: reason, OccurredAt: now,
	})
}

// publish carries one audit event to the bus. A failure is returned to the caller: an
// unaudited security act is reported, never swallowed (ADR-0007).
func (s *Service) publish(ctx context.Context, e bus.Event) error { return s.events.Publish(ctx, e) }

// deriveStatus is the AC8 derivation with the live-stream fact the domain cannot see.
func (s *Service) deriveStatus(d domain.DataPlane, now time.Time) api.DataPlaneStatus {
	s.mu.Lock()
	_, active := s.streams[api.Identity{TenantID: d.TenantID, DataPlaneID: d.ID}]
	s.mu.Unlock()
	return domain.DeriveStatus(d, active, now, s.cfg.StaleAfter)
}

func (s *Service) toAPI(d domain.DataPlane) api.DataPlane {
	return api.DataPlane{
		ID: d.ID, TenantID: d.TenantID, Cloud: d.Cloud, Region: d.Region,
		AgentVersion: d.AgentVersion, K8sVersion: d.K8sVersion,
		Capabilities: slices.Clone(d.Capabilities),
		EnrolledAt:   d.EnrolledAt, LastSeenAt: d.LastSeenAt,
		CurrentCertificateID: d.CurrentCertificateID, CertificateExpiresAt: d.CertificateExpiresAt,
		RevokedAt: d.RevokedAt, Status: s.deriveStatus(d, s.cfg.Now()),
	}
}

// endStreams closes every live session for id — the enforcement half of a revocation.
func (s *Service) endStreams(id api.Identity) {
	s.mu.Lock()
	ss, ok := s.streams[id]
	s.mu.Unlock()
	if ok {
		ss.terminate()
	}
}

// removeStream unregisters a closed session.
func (s *Service) removeStream(id api.Identity) {
	s.mu.Lock()
	delete(s.streams, id)
	s.mu.Unlock()
}

// The store sentinels live in domain so adapters can report them without importing app;
// the app layer re-exports them so ports keep one documented vocabulary.
var (
	ErrStoreNotFound = domain.ErrStoreNotFound
	ErrTokenSpent    = domain.ErrTokenSpent
)

// mapStoreErr maps store errors onto the api surface's coarse shapes.
func mapStoreErr(err error) error {
	switch {
	case errors.Is(err, ErrStoreNotFound):
		return api.ErrNotFound
	default:
		return err
	}
}
