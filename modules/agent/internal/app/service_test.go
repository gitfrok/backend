package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gitfrok/backend/modules/agent/api"
	"github.com/gitfrok/backend/modules/agent/internal/adapters/memory"
	"github.com/gitfrok/backend/modules/agent/internal/domain"
	identityapi "github.com/gitfrok/backend/modules/identity/api"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
	platformaudit "github.com/gitfrok/backend/platform/audit"
	"github.com/gitfrok/backend/platform/bus"
	"github.com/gitfrok/backend/platform/tenancy"
)

// --- test doubles -------------------------------------------------------------------

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock(t time.Time) *fakeClock { return &fakeClock{t: t} }
func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}
func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// captureBus records every published event; it delivers to no subscriber.
type captureBus struct {
	mu     sync.Mutex
	events []bus.Event
}

func (b *captureBus) Publish(_ context.Context, e bus.Event) error {
	if e.Tenant() == "" {
		return errors.New("captureBus: event has no tenant")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.events = append(b.events, e)
	return nil
}
func (b *captureBus) Subscribe(string, bus.Handler) {}

func (b *captureBus) of(action string) []bus.Event {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []bus.Event
	for _, e := range b.events {
		if a, ok := e.(interface{ Action() string }); ok && a.Action() == action {
			out = append(out, e)
		}
	}
	return out
}

// render flattens an event for secrecy scanning.
func (b *captureBus) render() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return fmt.Sprintf("%+v", b.events)
}

type stubPDP struct {
	allow bool
	last  policyapi.Request
}

func (p *stubPDP) Decide(_ context.Context, req policyapi.Request) (policyapi.Decision, error) {
	p.last = req
	return policyapi.Decision{Allowed: p.allow}, nil
}

// failingRegistry is a registry whose SetCertificate can be made to fail —
// the post-spend registry-outage shape the AC6 extension covers.
type failingRegistry struct {
	*memory.Store
	failSetCertificate bool
}

func (r *failingRegistry) SetCertificate(ctx context.Context, tenantID, id, certID string, expiresAt time.Time) error {
	if r.failSetCertificate {
		return errors.New("registry: unavailable")
	}
	return r.Store.SetCertificate(ctx, tenantID, id, certID, expiresAt)
}

// flakyBus forwards to a captureBus but fails the publish of ONE action —
// the audit-outage shape for the post-spend tail tests.
type flakyBus struct {
	inner      *captureBus
	failAction string
}

func (b *flakyBus) Publish(ctx context.Context, e bus.Event) error {
	if a, ok := e.(interface{ Action() string }); ok && a.Action() == b.failAction {
		return errors.New("bus: unavailable")
	}
	return b.inner.Publish(ctx, e)
}
func (b *flakyBus) Subscribe(topic string, h bus.Handler) { b.inner.Subscribe(topic, h) }

// racedTokens simulates the claim losing its race mid-Enrol: the pre-claim
// lookup serves the pristine token, the atomic claim refuses, and the
// post-claim re-read serves the row as the winner (or the revocation or the
// expiry) left it — which is exactly the state the refusal must name.
type racedTokens struct {
	*memory.Store
	post    domain.Token
	flipped bool
}

func (s *racedTokens) TokenByHash(ctx context.Context, hash [32]byte) (domain.Token, bool, error) {
	if s.flipped {
		return s.post, true, nil
	}
	return s.Store.TokenByHash(ctx, hash)
}

func (s *racedTokens) ClaimToken(_ context.Context, _ [32]byte, _ string, _ time.Time) (domain.Token, bool, error) {
	s.flipped = true
	return domain.Token{}, false, nil
}

// wiredService composes one Service over caller-chosen doubles with the
// harness's clock and knobs — the post-spend recovery tests need stores and
// buses the stock harness does not own.
func wiredService(h *harness, tokens TokenStore, registry RegistryStore, b bus.Bus) *Service {
	cfg := api.Config{
		CertLifetime:          time.Hour,
		RotationLead:          20 * time.Minute,
		RotationRetryInterval: time.Minute,
		StaleAfter:            5 * time.Minute,
		TokenMaxLifetime:      24 * time.Hour,
		HeartbeatInterval:     30 * time.Second,
		ClockSkewLeeway:       5 * time.Minute,
		Now:                   h.clock.now,
	}
	return New(h.pdp, b, h.issuer, tokens, registry, cfg, func(f string, a ...any) {
		fmt.Fprintf(h.logs, f+"\n", a...)
	})
}

// fakeIssuer mints certificates named "leaf:<id>". Chain trust and expiry are test knobs.
type fakeIssuer struct {
	mu        sync.Mutex
	next      int
	failIssue bool
	idents    map[string]api.Identity
	expiries  map[string]time.Time
	issued    []api.IssuedCertificate
	chainErr  error
	expired   bool
	// validity is the window classification a trusted chain reports when expired is
	// not set — the not-yet-valid case the real CA can now report (SPEC-0038 AC5).
	validity api.Validity
}

func newFakeIssuer() *fakeIssuer {
	return &fakeIssuer{idents: map[string]api.Identity{}, expiries: map[string]time.Time{}}
}

func (f *fakeIssuer) Issue(_ context.Context, id api.Identity, now time.Time, lifetime, _ time.Duration) (api.IssuedCertificate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failIssue {
		return api.IssuedCertificate{}, errors.New("issuer: unavailable")
	}
	f.next++
	certID := fmt.Sprintf("cert-%d", f.next)
	exp := now.Add(lifetime)
	f.idents[certID] = id
	f.expiries[certID] = exp
	cert := api.IssuedCertificate{CertificateID: certID, PEM: []byte("leaf:" + certID), ExpiresAt: exp}
	f.issued = append(f.issued, cert)
	return cert, nil
}

func (f *fakeIssuer) Inspect(leafDER []byte) (api.Identity, time.Time, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id, ok := f.idents[strings.TrimPrefix(string(leafDER), "leaf:")]
	if !ok {
		return api.Identity{}, time.Time{}, errors.New("fakeIssuer: not one of ours")
	}
	return id, f.expiries[strings.TrimPrefix(string(leafDER), "leaf:")], nil
}

func (f *fakeIssuer) VerifyChain(rawCerts [][]byte, _ time.Time) ([]byte, api.Validity, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.chainErr != nil {
		return nil, api.ValidNow, f.chainErr
	}
	if len(rawCerts) == 0 {
		return nil, api.ValidNow, errors.New("fakeIssuer: no certificates")
	}
	if f.expired {
		return rawCerts[0], api.ValidityExpired, nil
	}
	return rawCerts[0], f.validity, nil
}

// harness wires the service on the in-memory composition with test knobs exposed.
type harness struct {
	svc    *Service
	bus    *captureBus
	pdp    *stubPDP
	issuer *fakeIssuer
	clock  *fakeClock
	logs   *strings.Builder
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	clock := newClock(time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC))
	h := &harness{
		bus:    &captureBus{},
		pdp:    &stubPDP{allow: true},
		issuer: newFakeIssuer(),
		clock:  clock,
		logs:   &strings.Builder{},
	}
	cfg := api.Config{
		CertLifetime:          time.Hour,
		RotationLead:          20 * time.Minute,
		RotationRetryInterval: time.Minute,
		StaleAfter:            5 * time.Minute,
		TokenMaxLifetime:      24 * time.Hour,
		HeartbeatInterval:     30 * time.Second,
		ClockSkewLeeway:       5 * time.Minute,
		Now:                   clock.now,
	}
	h.svc = New(h.pdp, h.bus, h.issuer, memory.New(), memory.New(), cfg, func(f string, a ...any) {
		fmt.Fprintf(h.logs, f+"\n", a...)
	})
	return h
}

// operatorCtx scopes ctx to tenant with an owner principal.
func operatorCtx(tenant, actor string) context.Context {
	ctx := tenancy.WithTenant(context.Background(), tenancy.ID(tenant))
	return identityapi.WithPrincipal(ctx, identityapi.Principal{TenantID: tenant, ActorID: actor, Roles: []string{"owner"}})
}

// issueToken issues a token through the operator surface and returns the secret.
func (h *harness) issueToken(t *testing.T, tenant string) (api.EnrolmentToken, string) {
	t.Helper()
	tok, secret, err := h.svc.IssueEnrolmentToken(operatorCtx(tenant, "op-1"), tenant, "op-1", time.Hour)
	if err != nil {
		t.Fatalf("IssueEnrolmentToken: %v", err)
	}
	return tok, secret
}

func refusedReason(t *testing.T, err error) api.RefusalReason {
	t.Helper()
	var refused *api.EnrolmentRefused
	if !errors.As(err, &refused) {
		t.Fatalf("expected EnrolmentRefused, got %v", err)
	}
	return refused.Reason
}

// --- AC1: single use, including the spent-then-failed path ---------------------------

func TestEnrolSingleUse(t *testing.T) {
	h := newHarness(t)
	_, secret := h.issueToken(t, "acme")

	ctx := context.Background()
	first, err := h.svc.Enrol(ctx, api.EnrolRequest{Token: secret, Cloud: "GKE", Region: "eu-west1"})
	if err != nil {
		t.Fatalf("first Enrol: %v", err)
	}
	if first.TenantID != "acme" || first.DataPlaneID == "" {
		t.Fatalf("enrolment identity = %+v", first.Identity)
	}

	// The second presentation is refused — and audited as spent.
	_, err = h.svc.Enrol(ctx, api.EnrolRequest{Token: secret})
	if got := refusedReason(t, err); got != api.RefusalTokenSpent {
		t.Fatalf("second Enrol reason = %q, want TOKEN_SPENT", got)
	}
	if got := len(h.bus.of(platformaudit.ActionAgentEnrolment)); got != 2 {
		t.Fatalf("enrolment audit records = %d, want 2 (one per attempt)", got)
	}

	// Exactly one data-plane identity was minted (AC1, AC7).
	fleet, err := h.svc.Fleet(operatorCtx("acme", "op-1"), "acme", "op-1")
	if err != nil {
		t.Fatalf("Fleet: %v", err)
	}
	planes := 0
	for _, v := range fleet {
		if v.Plane.ID != "" {
			planes++
		}
	}
	if planes != 1 {
		t.Fatalf("data planes minted = %d, want exactly 1", planes)
	}
}

// AC6 (SPEC-0042, locked decision): an issuance failure AFTER the spend
// releases the claim — keeping its recorded data-plane ID — so the presenter's
// retry completes the SAME identity. One token never mints two data planes
// (ADR-0060), and no runbook ritual stands between the failure and the retry.
func TestEnrolIssuanceFailureReleasesClaimKeepingIdentity(t *testing.T) {
	h := newHarness(t)
	_, secret := h.issueToken(t, "acme")
	h.issuer.failIssue = true // the first attempt fails AFTER the token is spent

	ctx := context.Background()
	_, err := h.svc.Enrol(ctx, api.EnrolRequest{Token: secret, Cloud: "GKE", Region: "eu-west1"})
	if got := refusedReason(t, err); got != api.RefusalDenied {
		t.Fatalf("failed Enrol reason = %q, want the coarse DENIED", got)
	}
	// The failure is audited under its own reason.
	failed := h.bus.of(platformaudit.ActionAgentEnrolment)
	if len(failed) != 1 {
		t.Fatalf("enrolment audit records = %d, want 1 for the failed attempt", len(failed))
	}
	if ev := failed[0].(platformaudit.AgentEnrolment); ev.Reason != "certificate_issuance_failed" || ev.Outcome != "DENIED" {
		t.Fatalf("failure record = %+v, want DENIED/certificate_issuance_failed", ev)
	}

	// The partial enrolment's record remains, uncertified — visible as never
	// connected — and it names the identity the retry must re-bind. (The
	// released token is presentable again, so it reads as its own
	// never-connected row too: the fleet shows both halves of the retry.)
	fleet, err := h.svc.Fleet(operatorCtx("acme", "op-1"), "acme", "op-1")
	if err != nil {
		t.Fatalf("Fleet: %v", err)
	}
	var partialID string
	for _, v := range fleet {
		if v.Plane.ID != "" {
			if v.Status != api.StatusNeverConnected {
				t.Fatalf("partial plane status = %s, want NEVER_CONNECTED", v.Status)
			}
			partialID = v.Plane.ID
		}
	}
	if partialID == "" {
		t.Fatalf("fleet after failed enrolment = %+v, want the partial plane row", fleet)
	}

	h.issuer.failIssue = false
	// The retry is admitted — and it completes the SAME identity, not a new one.
	enrolment, err := h.svc.Enrol(ctx, api.EnrolRequest{Token: secret, Cloud: "GKE", Region: "eu-west1"})
	if err != nil {
		t.Fatalf("retry Enrol after released claim: %v", err)
	}
	if enrolment.DataPlaneID != partialID {
		t.Fatalf("retry minted %q — the released claim's identity %q was not re-bound (ADR-0060)",
			enrolment.DataPlaneID, partialID)
	}

	// No second identity is reachable anywhere: one plane, one certificate.
	fleet, _ = h.svc.Fleet(operatorCtx("acme", "op-1"), "acme", "op-1")
	if len(fleet) != 1 || fleet[0].Status != api.StatusConnected || fleet[0].Plane.ID != partialID {
		t.Fatalf("fleet after retry = %+v, want the SAME plane CONNECTED", fleet)
	}
	if got := len(h.issuer.issued); got != 1 {
		t.Fatalf("certificates issued = %d, want exactly 1 (the retry's)", got)
	}

	// The successful enrolment spent the token again: single use holds.
	_, err = h.svc.Enrol(ctx, api.EnrolRequest{Token: secret})
	if got := refusedReason(t, err); got != api.RefusalTokenSpent {
		t.Fatalf("post-success replay reason = %q, want TOKEN_SPENT", got)
	}
}

// AC6's refusal side: a claim released by issuance failure is re-spendable,
// but a token revoked while released stays revoked — the operator's act wins
// over the retry (PresentOutcome ordering: revoked > spent > expired).
func TestEnrolReleasedClaimStillHonoursRevocation(t *testing.T) {
	h := newHarness(t)
	tok, secret := h.issueToken(t, "acme")
	h.issuer.failIssue = true
	if _, err := h.svc.Enrol(context.Background(), api.EnrolRequest{Token: secret}); err == nil {
		t.Fatal("first Enrol should fail on issuer outage")
	}
	// Operator revokes while the claim is released.
	if err := h.svc.RevokeEnrolmentToken(operatorCtx("acme", "op-1"), "acme", "op-1", tok.ID); err != nil {
		t.Fatalf("RevokeEnrolmentToken: %v", err)
	}
	h.issuer.failIssue = false
	_, err := h.svc.Enrol(context.Background(), api.EnrolRequest{Token: secret})
	if got := refusedReason(t, err); got != api.RefusalTokenRevoked {
		t.Fatalf("retry after revocation = %q, want TOKEN_REVOKED", got)
	}
}

// AC6 extended to the WHOLE post-spend tail: a registry failure AFTER a
// successful issuance must not leave the token spent. The claim is released,
// the failure audited, and the retry completes the SAME identity.
func TestEnrolRegistryFailureAfterIssuanceReleasesClaim(t *testing.T) {
	h := newHarness(t)
	reg := &failingRegistry{Store: memory.New(), failSetCertificate: true}
	svc := wiredService(h, memory.New(), reg, h.bus)
	_, secret, err := svc.IssueEnrolmentToken(operatorCtx("acme", "op-1"), "acme", "op-1", time.Hour)
	if err != nil {
		t.Fatalf("IssueEnrolmentToken: %v", err)
	}
	ctx := context.Background()

	_, err = svc.Enrol(ctx, api.EnrolRequest{Token: secret, Cloud: "GKE", Region: "eu-west1"})
	if got := refusedReason(t, err); got != api.RefusalDenied {
		t.Fatalf("failed Enrol reason = %q, want the coarse DENIED", got)
	}
	// The failure is audited under its own reason.
	recs := h.bus.of(platformaudit.ActionAgentEnrolment)
	if len(recs) != 1 {
		t.Fatalf("enrolment audit records = %d, want 1 for the failed attempt", len(recs))
	}
	if ev := recs[0].(platformaudit.AgentEnrolment); ev.Reason != "certificate_record_failed" || ev.Outcome != "DENIED" {
		t.Fatalf("failure record = %+v, want DENIED/certificate_record_failed", ev)
	}

	// The partial enrolment names the identity the retry must re-bind.
	fleet, err := svc.Fleet(operatorCtx("acme", "op-1"), "acme", "op-1")
	if err != nil {
		t.Fatalf("Fleet: %v", err)
	}
	var partialID string
	for _, v := range fleet {
		if v.Plane.ID != "" {
			partialID = v.Plane.ID
		}
	}
	if partialID == "" {
		t.Fatalf("fleet after failed enrolment = %+v, want the partial plane row", fleet)
	}

	// Registry recovers: the retry is admitted and re-binds the SAME identity.
	reg.failSetCertificate = false
	enrolment, err := svc.Enrol(ctx, api.EnrolRequest{Token: secret, Cloud: "GKE", Region: "eu-west1"})
	if err != nil {
		t.Fatalf("retry Enrol after released claim: %v", err)
	}
	if enrolment.DataPlaneID != partialID {
		t.Fatalf("retry minted %q — the released claim's identity %q was not re-bound (ADR-0060)",
			enrolment.DataPlaneID, partialID)
	}
	// Single use holds after the recovered retry.
	if _, err := svc.Enrol(ctx, api.EnrolRequest{Token: secret}); refusedReason(t, err) != api.RefusalTokenSpent {
		t.Fatalf("post-success replay = %v, want TOKEN_SPENT", err)
	}
}

// AC6 extended to the audit tail: a publish failure after issuance AND the
// certificate record releases the claim the same way — the token is not left
// spent because the bus was down.
func TestEnrolAuditFailureAfterIssuanceReleasesClaim(t *testing.T) {
	h := newHarness(t)
	inner := &captureBus{}
	fb := &flakyBus{inner: inner, failAction: platformaudit.ActionAgentCertificateIssued}
	svc := wiredService(h, memory.New(), memory.New(), fb)
	_, secret, err := svc.IssueEnrolmentToken(operatorCtx("acme", "op-1"), "acme", "op-1", time.Hour)
	if err != nil {
		t.Fatalf("IssueEnrolmentToken: %v", err)
	}
	ctx := context.Background()

	_, err = svc.Enrol(ctx, api.EnrolRequest{Token: secret, Cloud: "GKE", Region: "eu-west1"})
	if got := refusedReason(t, err); got != api.RefusalDenied {
		t.Fatalf("failed Enrol reason = %q, want the coarse DENIED", got)
	}
	// The DENIED recovery record reached the bus under its own reason.
	recs := inner.of(platformaudit.ActionAgentEnrolment)
	var denied *platformaudit.AgentEnrolment
	for _, e := range recs {
		ev := e.(platformaudit.AgentEnrolment)
		if ev.Outcome == "DENIED" {
			denied = &ev
		}
	}
	if denied == nil || denied.Reason != "certificate_audit_failed" {
		t.Fatalf("DENIED record = %+v, want reason certificate_audit_failed", denied)
	}
	partialID := denied.DataPlaneID
	if partialID == "" {
		t.Fatal("DENIED record carries no data-plane identity — the claim was not attributed")
	}

	// Bus recovers: the retry is admitted and re-binds the SAME identity.
	fb.failAction = ""
	enrolment, err := svc.Enrol(ctx, api.EnrolRequest{Token: secret, Cloud: "GKE", Region: "eu-west1"})
	if err != nil {
		t.Fatalf("retry Enrol after released claim: %v", err)
	}
	if enrolment.DataPlaneID != partialID {
		t.Fatalf("retry minted %q — the released claim's identity %q was not re-bound (ADR-0060)",
			enrolment.DataPlaneID, partialID)
	}
}

// A refused claim names its TRUE cause: the re-read row distinguishes a
// revocation and an expiry from the one true single-use race — each audited
// under its own reason (SPEC-0042 finding 4).
func TestEnrolClaimFailureNamesItsCause(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*domain.Token, time.Time)
		want   api.RefusalReason
	}{
		{"revoked while claiming", func(t *domain.Token, now time.Time) { t.RevokedAt = now }, api.RefusalTokenRevoked},
		{"expired while claiming", func(t *domain.Token, now time.Time) { t.ExpiresAt = now.Add(-time.Minute) }, api.RefusalTokenExpired},
		{"true single-use race", func(t *domain.Token, now time.Time) { t.SpentAt = now }, api.RefusalTokenSpent},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			tokens := &racedTokens{Store: memory.New()}
			svc := wiredService(h, tokens, memory.New(), h.bus)
			_, secret, err := svc.IssueEnrolmentToken(operatorCtx("acme", "op-1"), "acme", "op-1", time.Hour)
			if err != nil {
				t.Fatalf("IssueEnrolmentToken: %v", err)
			}
			// The post-claim row: the stored token as the winner left it.
			stored, ok, err := tokens.Store.TokenByHash(context.Background(), domain.HashSecret(secret))
			if err != nil || !ok {
				t.Fatalf("stored token: ok=%t err=%v", ok, err)
			}
			tc.mutate(&stored, h.clock.now())
			tokens.post = stored

			_, err = svc.Enrol(context.Background(), api.EnrolRequest{Token: secret})
			if got := refusedReason(t, err); got != tc.want {
				t.Fatalf("refusal reason = %q, want %q", got, tc.want)
			}
			// And the audit trail names the same cause.
			recs := h.bus.of(platformaudit.ActionAgentEnrolment)
			if len(recs) != 1 {
				t.Fatalf("enrolment audit records = %d, want exactly 1", len(recs))
			}
			if ev := recs[0].(platformaudit.AgentEnrolment); ev.Reason != string(tc.want) || ev.Outcome != "DENIED" {
				t.Fatalf("audit record = %+v, want DENIED/%s", ev, tc.want)
			}
		})
	}
}

func TestEnrolRefusesExpiredToken(t *testing.T) {
	h := newHarness(t)
	_, secret := h.issueToken(t, "acme")
	h.clock.advance(2 * time.Hour) // token lived one hour

	_, err := h.svc.Enrol(context.Background(), api.EnrolRequest{Token: secret})
	if got := refusedReason(t, err); got != api.RefusalTokenExpired {
		t.Fatalf("reason = %q, want TOKEN_EXPIRED", got)
	}
	if got := len(h.bus.of(platformaudit.ActionAgentEnrolment)); got != 1 {
		t.Fatalf("enrolment audit records = %d, want exactly 1", got)
	}
}

func TestEnrolRefusesRevokedToken(t *testing.T) {
	h := newHarness(t)
	tok, secret := h.issueToken(t, "acme")
	if err := h.svc.RevokeEnrolmentToken(operatorCtx("acme", "op-1"), "acme", "op-1", tok.ID); err != nil {
		t.Fatalf("RevokeEnrolmentToken: %v", err)
	}
	_, err := h.svc.Enrol(context.Background(), api.EnrolRequest{Token: secret})
	if got := refusedReason(t, err); got != api.RefusalTokenRevoked {
		t.Fatalf("reason = %q, want TOKEN_REVOKED", got)
	}
}

func TestEnrolUnknownTokenIsCoarseAndUnattributed(t *testing.T) {
	h := newHarness(t)
	_, err := h.svc.Enrol(context.Background(), api.EnrolRequest{Token: "not-a-real-token"})
	if got := refusedReason(t, err); got != api.RefusalTokenInvalid {
		t.Fatalf("reason = %q, want TOKEN_INVALID", got)
	}
	// Unattributable refusals carry no tenant, so they leave no tenant-scoped record —
	// the same precedent the bus itself sets for unscoped events.
	if got := len(h.bus.of(platformaudit.ActionAgentEnrolment)); got != 0 {
		t.Fatalf("enrolment audit records = %d, want 0 for an unattributable token", got)
	}
	// And the refusal message is coarse.
	if msg := err.Error(); strings.Contains(msg, "not-a-real-token") {
		t.Fatalf("refusal echoes the presented token: %q", msg)
	}
}

// --- AC4: rotation timing -------------------------------------------------------------

func enrolAndOpen(t *testing.T, h *harness) (api.Enrolment, api.StreamSession) {
	t.Helper()
	_, secret := h.issueToken(t, "acme")
	e, err := h.svc.Enrol(context.Background(), api.EnrolRequest{Token: secret})
	if err != nil {
		t.Fatalf("Enrol: %v", err)
	}
	ss, err := h.svc.OpenStream(context.Background(), e.Identity)
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	return e, ss
}

func TestRotationTimingAndAck(t *testing.T) {
	h := newHarness(t)
	e, ss := enrolAndOpen(t, h)
	defer ss.Close(context.Background())

	// Rotation is due one lead before expiry — not at expiry, not on demand.
	wantDue := e.Certificate.ExpiresAt.Add(-20 * time.Minute)
	if got := ss.RotationDueAt(); !got.Equal(wantDue) {
		t.Fatalf("RotationDueAt = %v, want %v", got, wantDue)
	}

	h.clock.advance(40 * time.Minute) // now inside the lead window
	next, err := ss.Rotate(context.Background())
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	// The agent applies it: the rotation is audited exactly once, the registry follows.
	if err := ss.AckRotation(context.Background(), next.CertificateID, true, ""); err != nil {
		t.Fatalf("AckRotation: %v", err)
	}
	recs := h.bus.of(platformaudit.ActionAgentCertificateRotation)
	if len(recs) != 1 {
		t.Fatalf("rotation audit records = %d, want exactly 1", len(recs))
	}
	dp, err := h.svc.GetDataPlane(operatorCtx("acme", "op-1"), "acme", "op-1", e.DataPlaneID)
	if err != nil {
		t.Fatalf("GetDataPlane: %v", err)
	}
	if dp.CurrentCertificateID != next.CertificateID {
		t.Fatalf("registry certificate = %q, want %q", dp.CurrentCertificateID, next.CertificateID)
	}
	// The next rotation is scheduled off the NEW certificate.
	if got, want := ss.RotationDueAt(), next.ExpiresAt.Add(-20*time.Minute); !got.Equal(want) {
		t.Fatalf("RotationDueAt after rotation = %v, want %v", got, want)
	}
}

func TestRotationFailureRetryAndLapse(t *testing.T) {
	h := newHarness(t)
	e, ss := enrolAndOpen(t, h)
	defer ss.Close(context.Background())

	h.clock.advance(40 * time.Minute)
	next, err := ss.Rotate(context.Background())
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	// Clock skew on the customer cluster is a first-class failure: the agent reports it,
	// the control plane records it and retries — it does not extend the certificate.
	if err := ss.AckRotation(context.Background(), next.CertificateID, false, "CLOCK_SKEW"); err != nil {
		t.Fatalf("AckRotation: %v", err)
	}
	denied := h.bus.of(platformaudit.ActionAgentCertificateRotation)
	if len(denied) != 1 {
		t.Fatalf("rotation audit records = %d, want 1", len(denied))
	}
	if ev := denied[0].(platformaudit.AgentCertificateRotation); ev.Outcome != "DENIED" || ev.Reason != "CLOCK_SKEW" {
		t.Fatalf("rotation record = %+v, want DENIED/CLOCK_SKEW", ev)
	}
	// The retry is paced, not immediate.
	if got, want := ss.RotationDueAt(), h.clock.now().Add(time.Minute); !got.Equal(want) {
		t.Fatalf("retry due = %v, want %v", got, want)
	}

	// The certificate expires without an applied rotation: the session lapses and the
	// connection is refused rather than extended (AC4).
	h.clock.advance(2 * time.Hour)
	if !ss.Lapsed(h.clock.now()) {
		t.Fatal("session must be lapsed after the certificate expired")
	}
	if _, err := ss.Rotate(context.Background()); err == nil {
		t.Fatal("a lapsed session must not be re-issued")
	}
	if err := h.svc.RefusedLapsed(context.Background(), e.Identity); err != nil {
		t.Fatalf("RefusedLapsed: %v", err)
	}
	if got := len(h.bus.of(platformaudit.ActionAgentConnectionRefused)); got != 1 {
		t.Fatalf("connection-refused records = %d, want 1", got)
	}
}

// --- admission (AC5, AC6) -------------------------------------------------------------

func TestAdmissionRefusalsAreAudited(t *testing.T) {
	h := newHarness(t)
	e, ss := enrolAndOpen(t, h)
	ss.Close(context.Background())

	ctx := context.Background()
	// Revocation: the same certificate, refused on the next connection.
	if err := h.svc.RevokeDataPlane(operatorCtx("acme", "op-1"), "acme", "op-1", e.DataPlaneID); err != nil {
		t.Fatalf("RevokeDataPlane: %v", err)
	}
	if _, err := h.svc.AdmitPeerCertificates(ctx, [][]byte{e.Certificate.PEM}); !errors.Is(err, api.ErrRevoked) {
		t.Fatalf("admission after revoke = %v, want ErrRevoked", err)
	}

	// Expiry: trusted chain, expired certificate — audited, refused.
	h.issuer.expired = true
	if _, err := h.svc.AdmitPeerCertificates(ctx, [][]byte{e.Certificate.PEM}); !errors.Is(err, api.ErrNotFound) {
		t.Fatalf("admission of expired cert = %v, want coarse refusal", err)
	}
	h.issuer.expired = false

	// Unknown identity: a well-formed certificate the registry does not know.
	rogue, err := h.issuer.Issue(ctx, api.Identity{TenantID: "acme", DataPlaneID: "ghost"}, h.clock.now(), time.Hour, 0)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := h.svc.AdmitPeerCertificates(ctx, [][]byte{rogue.PEM}); !errors.Is(err, api.ErrNotFound) {
		t.Fatalf("admission of unknown identity = %v, want coarse refusal", err)
	}

	refusals := h.bus.of(platformaudit.ActionAgentConnectionRefused)
	if len(refusals) != 3 {
		t.Fatalf("connection-refused records = %d, want 3 (one per refusal)", len(refusals))
	}
	// AC9: the revoked, expired and unknown refusals are the same coarse shape at the
	// API boundary — all returned either ErrNotFound or ErrRevoked, never a fine reason.
}

// --- AC8: fleet visibility -------------------------------------------------------------

func TestFleetStatusLifecycle(t *testing.T) {
	h := newHarness(t)
	op := operatorCtx("acme", "op-1")

	tok, secret := h.issueToken(t, "acme")
	fleet, err := h.svc.Fleet(op, "acme", "op-1")
	if err != nil {
		t.Fatalf("Fleet: %v", err)
	}
	if len(fleet) != 1 || fleet[0].Status != api.StatusNeverConnected || fleet[0].TokenID != tok.ID {
		t.Fatalf("fleet before enrolment = %+v, want one NEVER_CONNECTED token row", fleet)
	}
	if fleet[0].Status.Healthy() {
		t.Fatal("a never-connected data plane must not render healthy")
	}

	e, err := h.svc.Enrol(context.Background(), api.EnrolRequest{Token: secret})
	if err != nil {
		t.Fatalf("Enrol: %v", err)
	}
	fleet, _ = h.svc.Fleet(op, "acme", "op-1")
	if len(fleet) != 1 || fleet[0].Status != api.StatusConnected {
		t.Fatalf("fleet after enrolment = %+v, want CONNECTED", fleet)
	}

	// Silence past the staleness window: stale — distinguishable, and never healthy.
	h.clock.advance(6 * time.Minute)
	fleet, _ = h.svc.Fleet(op, "acme", "op-1")
	if fleet[0].Status != api.StatusStale {
		t.Fatalf("fleet after silence = %+v, want STALE", fleet[0].Status)
	}
	if fleet[0].Status.Healthy() || fleet[0].Status == api.StatusConnected {
		t.Fatal("a stale data plane must never render healthy or connected")
	}

	// An established stream reads connected again.
	ss, err := h.svc.OpenStream(context.Background(), e.Identity)
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	fleet, _ = h.svc.Fleet(op, "acme", "op-1")
	if fleet[0].Status != api.StatusConnected {
		t.Fatalf("fleet with live stream = %+v, want CONNECTED", fleet[0].Status)
	}

	// Revocation wins over the live stream.
	if err := h.svc.RevokeDataPlane(op, "acme", "op-1", e.DataPlaneID); err != nil {
		t.Fatalf("RevokeDataPlane: %v", err)
	}
	fleet, _ = h.svc.Fleet(op, "acme", "op-1")
	if fleet[0].Status != api.StatusRevoked {
		t.Fatalf("fleet after revocation = %+v, want REVOKED", fleet[0].Status)
	}
	select {
	case <-ss.Done():
	default:
		t.Fatal("revocation must end the live stream")
	}
	ss.Close(context.Background())
}

// --- AC9: coarse isolation on the operator surface -------------------------------------

func TestCrossTenantReadsAreNotFound(t *testing.T) {
	h := newHarness(t)
	_, secret := h.issueToken(t, "acme")
	e, err := h.svc.Enrol(context.Background(), api.EnrolRequest{Token: secret})
	if err != nil {
		t.Fatalf("Enrol: %v", err)
	}

	// Tenant beta asking for acme's data plane gets the same shape as for a record that
	// does not exist anywhere.
	_, errCross := h.svc.GetDataPlane(operatorCtx("beta", "op-2"), "beta", "op-2", e.DataPlaneID)
	_, errMissing := h.svc.GetDataPlane(operatorCtx("beta", "op-2"), "beta", "op-2", "no-such-plane")
	if !errors.Is(errCross, api.ErrNotFound) || !errors.Is(errMissing, api.ErrNotFound) {
		t.Fatalf("cross-tenant read = %v, missing read = %v; both must be ErrNotFound", errCross, errMissing)
	}
	if errCross.Error() != errMissing.Error() {
		t.Fatalf("refusal shapes differ: %q vs %q", errCross, errMissing)
	}
}

// --- authorization ---------------------------------------------------------------------

func TestOperatorActionsRequirePolicyAllowance(t *testing.T) {
	h := newHarness(t)
	h.pdp.allow = false
	if _, _, err := h.svc.IssueEnrolmentToken(operatorCtx("acme", "op-1"), "acme", "op-1", time.Hour); !errors.Is(err, api.ErrAuthorizationDenied) {
		t.Fatalf("denied PDP = %v, want ErrAuthorizationDenied", err)
	}
	if h.pdp.last.Action != actionTokenIssue {
		t.Fatalf("PDP asked about %q, want %q", h.pdp.last.Action, actionTokenIssue)
	}
}

func TestOperatorActionsRequireMatchingTenants(t *testing.T) {
	h := newHarness(t)
	// Principal of beta asking about acme's tokens: refused before policy is asked.
	if _, _, err := h.svc.IssueEnrolmentToken(operatorCtx("beta", "op-1"), "acme", "op-1", time.Hour); !errors.Is(err, api.ErrTenantMismatch) {
		t.Fatalf("mismatched tenant = %v, want ErrTenantMismatch", err)
	}
	// No tenant in context at all: refused.
	if _, _, err := h.svc.IssueEnrolmentToken(context.Background(), "acme", "op-1", time.Hour); err == nil {
		t.Fatal("unscoped request must be refused")
	}
}

// --- AC3: identity attribution ----------------------------------------------------------

func TestTokenTenantDetectsCrossTenantClaim(t *testing.T) {
	h := newHarness(t)
	_, secretA := h.issueToken(t, "acme")

	if tenant, ok := h.svc.TokenTenant(context.Background(), secretA); !ok || tenant != "acme" {
		t.Fatalf("TokenTenant = %q,%v; want acme,true", tenant, ok)
	}
	if _, ok := h.svc.TokenTenant(context.Background(), "garbage"); ok {
		t.Fatal("an unknown token must not resolve")
	}

	// The override act appends exactly one audit record.
	id := api.Identity{TenantID: "beta", DataPlaneID: "dp-x"}
	if err := h.svc.RefusedIdentityOverride(context.Background(), id, "acme", "msg-1"); err != nil {
		t.Fatalf("RefusedIdentityOverride: %v", err)
	}
	recs := h.bus.of(platformaudit.ActionAgentIdentityOverrideRefused)
	if len(recs) != 1 {
		t.Fatalf("override records = %d, want 1", len(recs))
	}
	if ev := recs[0].(platformaudit.AgentIdentityOverrideRefused); ev.TenantID != "beta" || ev.ClaimedTenant != "acme" {
		t.Fatalf("override record = %+v", ev)
	}
}

// --- AC2: secrecy -----------------------------------------------------------------------

func TestTokenSecretNeverLeaks(t *testing.T) {
	h := newHarness(t)
	tok, secret := h.issueToken(t, "acme")
	ctx := context.Background()

	// Spend it successfully...
	if _, err := h.svc.Enrol(ctx, api.EnrolRequest{Token: secret}); err != nil {
		t.Fatalf("Enrol: %v", err)
	}
	// ...and exercise every refusal path with copies of it.
	_, errSpent := h.svc.Enrol(ctx, api.EnrolRequest{Token: secret})
	h.clock.advance(48 * time.Hour)
	_, errLate := h.svc.Enrol(ctx, api.EnrolRequest{Token: secret})
	_ = h.svc.RevokeEnrolmentToken(operatorCtx("acme", "op-1"), "acme", "op-1", tok.ID)

	for name, surface := range map[string]string{
		"audit trail":  h.bus.render(),
		"spent error":  fmt.Sprintf("%v", errSpent),
		"late error":   fmt.Sprintf("%v", errLate),
		"service logs": h.logs.String(),
	} {
		if strings.Contains(surface, secret) {
			t.Fatalf("token secret appears in the %s", name)
		}
	}
	// The audit trail names the token by ID only.
	for _, e := range h.bus.of(platformaudit.ActionAgentEnrolment) {
		if ev := e.(platformaudit.AgentEnrolment); ev.TokenID != tok.ID {
			t.Fatalf("enrolment record token id = %q, want %q", ev.TokenID, tok.ID)
		}
	}
}

func TestTokenLifetimeIsCapped(t *testing.T) {
	h := newHarness(t)
	tok, _, err := h.svc.IssueEnrolmentToken(operatorCtx("acme", "op-1"), "acme", "op-1", 30*24*time.Hour)
	if err != nil {
		t.Fatalf("IssueEnrolmentToken: %v", err)
	}
	if got := tok.ExpiresAt.Sub(tok.IssuedAt); got != 24*time.Hour {
		t.Fatalf("token lifetime = %v, want capped at 24h", got)
	}
}
