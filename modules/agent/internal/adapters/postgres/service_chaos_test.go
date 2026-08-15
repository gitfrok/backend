package postgres_test

// SPEC-0042 AC1/AC2/AC6 at the COMPOSITION level: the whole control-plane
// half of the agent surface — app.Service plus its durable stores — is killed
// and rebuilt through internal/chaos over the same database. That is the
// kill -9 the specs speak of: no graceful shutdown, no state handoff; the
// restarted process has zero memory of its predecessor, and everything it
// still enforces was durable.

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/gitfrok/backend/internal/chaos"
	"github.com/gitfrok/backend/modules/agent/api"
	agentpg "github.com/gitfrok/backend/modules/agent/internal/adapters/postgres"
	"github.com/gitfrok/backend/modules/agent/internal/app"
	identityapi "github.com/gitfrok/backend/modules/identity/api"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
	"github.com/gitfrok/backend/platform/bus"
	"github.com/gitfrok/backend/platform/db"
	"github.com/gitfrok/backend/platform/tenancy"
)

// noopBus swallows audit emissions: these proofs are about the stores, and a
// dead bus must not mask a durability failure.
type noopBus struct{}

func (noopBus) Publish(context.Context, bus.Event) error { return nil }
func (noopBus) Subscribe(string, bus.Handler)            {}

// allowPDP lets every operator act through: authorization is proven by its
// own suite, not re-litigated here.
type allowPDP struct{}

func (allowPDP) Decide(context.Context, policyapi.Request) (policyapi.Decision, error) {
	return policyapi.Decision{Allowed: true}, nil
}

// scriptedIssuer is a per-incarnation CA stand-in with an outage knob. A new
// one is born on every restart — exactly like the dev CA — which is what
// makes these restarts honest: nothing certificate-side survives either.
type scriptedIssuer struct {
	mu   sync.Mutex
	fail bool
	n    int
}

func (i *scriptedIssuer) Issue(_ context.Context, id api.Identity, now time.Time, lifetime, _ time.Duration) (api.IssuedCertificate, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.fail {
		return api.IssuedCertificate{}, errors.New("scriptedIssuer: outage")
	}
	i.n++
	certID := fmt.Sprintf("cert-%d", i.n)
	return api.IssuedCertificate{
		CertificateID: certID,
		PEM:           []byte("leaf:" + id.DataPlaneID + ":" + certID),
		ExpiresAt:     now.Add(lifetime),
	}, nil
}

func (i *scriptedIssuer) Inspect([]byte) (api.Identity, time.Time, error) {
	return api.Identity{}, time.Time{}, errors.New("scriptedIssuer: not used in chaos proofs")
}

func (i *scriptedIssuer) VerifyChain([][]byte, time.Time) ([]byte, api.Validity, error) {
	return nil, api.ValidNow, errors.New("scriptedIssuer: not used in chaos proofs")
}

// planeState is one live composition: the service and the stores the proofs
// drive, plus the issuer knob they flip.
type planeState struct {
	svc    *app.Service
	stores *agentpg.Store
	issuer *scriptedIssuer
}

// chaosPlane builds the reusable harness over the FULL composition: fresh
// pool, fresh stores, fresh service and fresh CA per Start.
func chaosPlane(t *testing.T) *chaos.Plane[planeState] {
	t.Helper()
	return chaos.New(dsnOrSkip(t), func(dsn string) (planeState, *db.Pool, error) {
		pool, err := db.Open(context.Background(), dsn)
		if err != nil {
			return planeState{}, nil, err
		}
		stores := agentpg.New(pool)
		issuer := &scriptedIssuer{}
		svc := app.New(allowPDP{}, noopBus{}, issuer, stores, stores, api.Config{
			CertLifetime:          time.Hour,
			RotationLead:          20 * time.Minute,
			RotationRetryInterval: time.Minute,
			StaleAfter:            5 * time.Minute,
			TokenMaxLifetime:      24 * time.Hour,
			HeartbeatInterval:     30 * time.Second,
			ClockSkewLeeway:       5 * time.Minute,
			Now:                   time.Now,
		}, nil)
		return planeState{svc: svc, stores: stores, issuer: issuer}, pool, nil
	})
}

func opCtx(tenant tenancy.ID) context.Context {
	ctx := tenancy.WithTenant(context.Background(), tenant)
	return identityapi.WithPrincipal(ctx, identityapi.Principal{
		TenantID: string(tenant), ActorID: "op-1", Roles: []string{"owner"},
	})
}

func issue(t *testing.T, plane *chaos.Plane[planeState], tenant tenancy.ID) string {
	t.Helper()
	_, secret, err := plane.State.svc.IssueEnrolmentToken(opCtx(tenant), string(tenant), "op-1", time.Hour)
	if err != nil {
		t.Fatalf("IssueEnrolmentToken: %v", err)
	}
	return secret
}

func fleetPlaneIDs(t *testing.T, svc *app.Service, tenant tenancy.ID) []string {
	t.Helper()
	fleet, err := svc.Fleet(opCtx(tenant), string(tenant), "op-1")
	if err != nil {
		t.Fatalf("Fleet: %v", err)
	}
	var ids []string
	for _, v := range fleet {
		if v.Plane.ID != "" {
			ids = append(ids, v.Plane.ID)
		}
	}
	return ids
}

func fleetStatus(t *testing.T, svc *app.Service, tenant tenancy.ID, planeID string) api.DataPlaneStatus {
	t.Helper()
	fleet, err := svc.Fleet(opCtx(tenant), string(tenant), "op-1")
	if err != nil {
		t.Fatalf("Fleet: %v", err)
	}
	for _, v := range fleet {
		if v.Plane.ID == planeID {
			return v.Status
		}
	}
	t.Fatalf("plane %s not in fleet", planeID)
	return ""
}

// AC1: a SUCCESSFUL enrolment's spend outlives the control plane. The
// restarted composition refuses the replay — it has no memory of the first
// spend, so the refusal can only come from the database.
func TestAC1_App_SpendSurvivesKillRestart(t *testing.T) {
	plane := chaosPlane(t)
	if err := plane.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	tenant := tenantFor(t)
	secret := issue(t, plane, tenant)

	first, err := plane.State.svc.Enrol(context.Background(), api.EnrolRequest{Token: secret, Cloud: "GKE", Region: "eu-west1"})
	if err != nil {
		t.Fatalf("first Enrol: %v", err)
	}

	if err := plane.Restart(); err != nil {
		t.Fatalf("restart: %v", err)
	}

	_, err = plane.State.svc.Enrol(context.Background(), api.EnrolRequest{Token: secret})
	var refused *api.EnrolmentRefused
	if !errors.As(err, &refused) || refused.Reason != api.RefusalTokenSpent {
		t.Fatalf("replay after restart = %v, want TOKEN_SPENT", err)
	}
	// And the fleet the restarted process sees holds exactly the one identity
	// its predecessor minted.
	if ids := fleetPlaneIDs(t, plane.State.svc, tenant); len(ids) != 1 || ids[0] != first.DataPlaneID {
		t.Fatalf("fleet after restart = %v, want exactly [%s]", ids, first.DataPlaneID)
	}
}

// AC1 + AC6: a PARTIAL enrolment (issuance failed, claim released keeping its
// identity) survives the kill too — the restarted process lets the retry in
// and re-binds the SAME data-plane identity the dead process recorded.
func TestAC1_App_RetryAfterPartialEnrolmentRebindsAcrossRestart(t *testing.T) {
	plane := chaosPlane(t)
	if err := plane.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	tenant := tenantFor(t)
	secret := issue(t, plane, tenant)

	plane.State.issuer.fail = true
	_, err := plane.State.svc.Enrol(context.Background(), api.EnrolRequest{Token: secret, Cloud: "GKE", Region: "eu-west1"})
	var refused *api.EnrolmentRefused
	if !errors.As(err, &refused) || refused.Reason != api.RefusalDenied {
		t.Fatalf("partial Enrol = %v, want the coarse DENIED", err)
	}
	partial := fleetPlaneIDs(t, plane.State.svc, tenant)
	if len(partial) != 1 {
		t.Fatalf("partial enrolment fleet = %v, want the one uncertified plane", partial)
	}

	// kill -9: the CA dies with the process; the released claim and its
	// recorded identity do not.
	if err := plane.Restart(); err != nil {
		t.Fatalf("restart: %v", err)
	}

	retry, err := plane.State.svc.Enrol(context.Background(), api.EnrolRequest{Token: secret, Cloud: "GKE", Region: "eu-west1"})
	if err != nil {
		t.Fatalf("retry after restart: %v", err)
	}
	if retry.DataPlaneID != partial[0] {
		t.Fatalf("restart-retry minted %q, want the recorded identity %q (ADR-0060)", retry.DataPlaneID, partial[0])
	}
	if ids := fleetPlaneIDs(t, plane.State.svc, tenant); len(ids) != 1 || ids[0] != partial[0] {
		t.Fatalf("fleet after retry = %v, want exactly the SAME identity", ids)
	}
	// The retry spent the token: a THIRD presentation is refused.
	if _, err := plane.State.svc.Enrol(context.Background(), api.EnrolRequest{Token: secret}); !errors.As(err, &refused) || refused.Reason != api.RefusalTokenSpent {
		t.Fatalf("third presentation = %v, want TOKEN_SPENT", err)
	}
}

// AC1: a revocation issued before the kill still refuses after the restart.
func TestAC1_App_RevocationBeforeRestartStillRefuses(t *testing.T) {
	plane := chaosPlane(t)
	if err := plane.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	tenant := tenantFor(t)
	tok, secret, err := plane.State.svc.IssueEnrolmentToken(opCtx(tenant), string(tenant), "op-1", time.Hour)
	if err != nil {
		t.Fatalf("IssueEnrolmentToken: %v", err)
	}
	if err := plane.State.svc.RevokeEnrolmentToken(opCtx(tenant), string(tenant), "op-1", tok.ID); err != nil {
		t.Fatalf("RevokeEnrolmentToken: %v", err)
	}

	if err := plane.Restart(); err != nil {
		t.Fatalf("restart: %v", err)
	}

	_, err = plane.State.svc.Enrol(context.Background(), api.EnrolRequest{Token: secret})
	var refused *api.EnrolmentRefused
	if !errors.As(err, &refused) || refused.Reason != api.RefusalTokenRevoked {
		t.Fatalf("enrolment after restart = %v, want TOKEN_REVOKED", err)
	}
}

// AC2: the restarted control plane derives the fleet's statuses from durable
// liveness alone — its own uptime is zero, and the machine must say so.
func TestAC2_App_FleetRecomputedFromDurableLivenessAcrossRestart(t *testing.T) {
	plane := chaosPlane(t)
	if err := plane.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	tenant := tenantFor(t)
	secret := issue(t, plane, tenant)
	enrolment, err := plane.State.svc.Enrol(context.Background(), api.EnrolRequest{Token: secret, Cloud: "GKE", Region: "eu-west1"})
	if err != nil {
		t.Fatalf("Enrol: %v", err)
	}
	planeID := enrolment.DataPlaneID

	if got := fleetStatus(t, plane.State.svc, tenant, planeID); got != api.StatusConnected {
		t.Fatalf("before restart: %s, want CONNECTED", got)
	}
	if err := plane.Restart(); err != nil {
		t.Fatalf("restart: %v", err)
	}
	// The successor process never saw the enrolment; durable last_seen speaks.
	if got := fleetStatus(t, plane.State.svc, tenant, planeID); got != api.StatusConnected {
		t.Fatalf("after restart: %s, want CONNECTED", got)
	}

	// Silence past the window — backdated through the durable column, no
	// sleep — reads STALE on the restarted plane, and stays STALE after
	// another kill.
	if err := plane.State.stores.MarkSeen(context.Background(), string(tenant), planeID, time.Now().Add(-time.Hour)); err != nil {
		t.Fatalf("backdate liveness: %v", err)
	}
	if got := fleetStatus(t, plane.State.svc, tenant, planeID); got != api.StatusStale {
		t.Fatalf("silent plane: %s, want STALE", got)
	}
	if err := plane.Restart(); err != nil {
		t.Fatalf("restart 2: %v", err)
	}
	if got := fleetStatus(t, plane.State.svc, tenant, planeID); got != api.StatusStale {
		t.Fatalf("stale across restart: %s, want STALE", got)
	}

	// Revocation wins over everything, across the kill as well.
	if err := plane.State.svc.RevokeDataPlane(opCtx(tenant), string(tenant), "op-1", planeID); err != nil {
		t.Fatalf("RevokeDataPlane: %v", err)
	}
	if err := plane.Restart(); err != nil {
		t.Fatalf("restart 3: %v", err)
	}
	if got := fleetStatus(t, plane.State.svc, tenant, planeID); got != api.StatusRevoked {
		t.Fatalf("revoked after restart: %s, want REVOKED", got)
	}
	// And the revoked identity reads NEVER_CONNECTED for nothing: an
	// uncertified-by-revocation plane never renders healthy.
	if got := fleetStatus(t, plane.State.svc, tenant, planeID); got.Healthy() {
		t.Fatal("a revoked data plane must never render healthy")
	}
}
