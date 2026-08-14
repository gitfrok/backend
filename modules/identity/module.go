package identity

import (
	"context"
	"net/http"
	"slices"
	"time"

	identityv1 "github.com/gitfrok/backend/gen/proto/identity/v1"
	"github.com/gitfrok/backend/modules/identity/api"
	identitygrpc "github.com/gitfrok/backend/modules/identity/internal/adapters/grpc"
	identitymemory "github.com/gitfrok/backend/modules/identity/internal/adapters/memory"
	identitypg "github.com/gitfrok/backend/modules/identity/internal/adapters/postgres"
	identityapp "github.com/gitfrok/backend/modules/identity/internal/app"
	"github.com/gitfrok/backend/modules/identity/internal/domain"
	"github.com/gitfrok/backend/modules/identity/internal/oidc"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
	"github.com/gitfrok/backend/platform/bus"
	"github.com/gitfrok/backend/platform/db"
	"github.com/gitfrok/backend/platform/tenancy"
	"google.golang.org/grpc"
)

type service struct {
	domain *domain.Service
	pdp    policyapi.DecisionPoint
}

// NewInMemory assembles a test/development credential store. Lifecycle
// actions require the same PDP port as a durable deployment; nil is refused
// so an accidental unsecured composition cannot issue credentials.
func NewInMemory(key []byte, pdp policyapi.DecisionPoint) api.Authenticator {
	if pdp == nil {
		panic("identity: no PDP — credential lifecycle actions require authorization")
	}
	return service{domain: domain.NewService(key), pdp: pdp}
}

// NewPostgres assembles the durable Identity&Access credential store. The
// adapter owns the only pre-authentication resolver path; callers receive the
// same bounded Authenticator interface as the in-memory composition.
func NewPostgres(pool *db.Pool, activeKeyID string, keys map[string][]byte, pdp policyapi.DecisionPoint) api.Authenticator {
	return identitypg.New(pool, activeKeyID, keys, pdp)
}

func NewGRPCServer(auth api.Authenticator) *identitygrpc.Server { return identitygrpc.NewServer(auth) }

// NewAuditorGrantsInMemory assembles the auditor grant lifecycle on the
// in-memory store for dev planes and tests (T-0027, SPEC-0033). Lifecycle
// actions require the PDP port, the witness log AC4 appends to, and the
// bus the lifecycle events announce on; nil for any is refused. The
// composition root adapts the tenant's audit trail onto the witness port.
func NewAuditorGrantsInMemory(pdp policyapi.DecisionPoint, events bus.Bus, witness api.GrantWitness) api.AuditorGrants {
	return identityapp.New(pdp, events, witness, identitymemory.NewGrantStore())
}

// NewAuditorGrantsPostgres assembles the durable auditor grant lifecycle on
// the RLS-isolated identity schema (T-0027, SPEC-0033). Grant records stay
// tenant-scoped at the row level; state is derived at read time, so a
// revocation or an expiry takes effect on the next decision by construction.
func NewAuditorGrantsPostgres(pool *db.Pool, pdp policyapi.DecisionPoint, events bus.Bus, witness api.GrantWitness) api.AuditorGrants {
	return identityapp.New(pdp, events, witness, identitypg.NewGrantStore(pool))
}

// NewAuditorGrantGRPCServer exposes the grant surface over
// contracts/proto/identity/v1's AuditorGrantService. The adapter translates
// shapes only; authorization, idempotency and audit happen behind
// api.AuditorGrants, and every failure is the one coarse denial.
func NewAuditorGrantGRPCServer(grants api.AuditorGrants) identityv1.AuditorGrantServiceServer {
	return identitygrpc.NewGrantServer(grants)
}
func (s service) AuthenticatePAT(_ context.Context, token string) (api.Principal, bool) {
	p, ok := s.domain.AuthenticatePAT(token)
	return api.Principal{TenantID: p.TenantID, ActorID: p.ActorID, Roles: p.Roles}, ok
}
func (s service) AuthenticateSSHKey(_ context.Context, key, verifierKeyID string) (api.Principal, bool) {
	p, ok := s.domain.AuthenticateSSHKey(key, verifierKeyID)
	return api.Principal{TenantID: p.TenantID, ActorID: p.ActorID, Roles: p.Roles}, ok
}
func (s service) IssuePAT(ctx context.Context, t, a, l string, scopes, roles []string, expiresAt *time.Time) (api.PAT, string, error) {
	if err := s.authorizeLifecycle(ctx, t, "identity.pat.issue", a); err != nil {
		return api.PAT{}, "", err
	}
	p, tok, e := s.domain.IssuePAT(t, a, l, scopes, roles, expiresAt)
	return publicPAT(p), tok, e
}
func (s service) RevokePAT(ctx context.Context, t, a, id string) (api.PAT, error) {
	if err := s.authorizeLifecycle(ctx, t, "identity.pat.revoke", id); err != nil {
		return api.PAT{}, err
	}
	if err := s.domain.RevokePAT(t, a, id); err != nil {
		return api.PAT{}, err
	}
	for _, p := range s.domain.ListPATs(t, a) {
		if p.ID == id {
			return publicPAT(p), nil
		}
	}
	return api.PAT{}, nil
}
func (s service) ListPATs(ctx context.Context, t, a string) ([]api.PAT, error) {
	if err := s.authorizeLifecycle(ctx, t, "identity.pat.list", a); err != nil {
		return nil, err
	}
	ps := s.domain.ListPATs(t, a)
	out := make([]api.PAT, 0, len(ps))
	for _, p := range ps {
		out = append(out, publicPAT(p))
	}
	return out, nil
}
func (s service) authorizeLifecycle(ctx context.Context, requestedTenant, action, resourceID string) error {
	tenant, err := tenancy.Require(ctx)
	if err != nil {
		return err
	}
	principal, err := api.RequirePrincipal(ctx)
	if err != nil {
		return err
	}
	if string(tenant) != requestedTenant || principal.TenantID != requestedTenant {
		return api.ErrTenantMismatch
	}
	decision, err := s.pdp.Decide(ctx, policyapi.Request{
		TenantID: requestedTenant,
		Subject: policyapi.Subject{
			ID: principal.ActorID, TenantID: principal.TenantID, Roles: slices.Clone(principal.Roles),
		},
		Action:   action,
		Resource: policyapi.Resource{Type: "personal_access_token", ID: resourceID},
	})
	if err != nil || !decision.Allowed {
		return api.ErrAuthorizationDenied
	}
	return nil
}
func publicPAT(p domain.PAT) api.PAT {
	return api.PAT{ID: p.ID, TenantID: p.TenantID, ActorID: p.ActorID, Label: p.Label, Scopes: slices.Clone(p.Scopes), Roles: slices.Clone(p.Roles), CreatedAt: p.CreatedAt, ExpiresAt: p.ExpiresAt, RevokedAt: p.RevokedAt}
}

// OIDCConfig is the per-environment OIDC login configuration, restated here so
// cmd/ can supply it without naming a package under this module's internal/ tree
// (invariant 13: no production value is compiled in).
type OIDCConfig struct {
	Issuer        string
	ClientID      string
	ClientSecret  string
	RedirectURI   string
	RoleClaim     string
	AllowedRoles  []string
	TenantMapping map[string]string
	Leeway        time.Duration
}

// Validate reports whether this configuration could serve a login. cmd/ calls it
// before the doors open, so a half-configured deployment fails its rollout rather
// than denying every login for a reason nobody can see (ADR-0045).
func (c OIDCConfig) Validate() error { return c.verifier().Configured() }

// RegisterOIDCLogin builds the verifier and registers its gRPC door. It is one
// call rather than a constructor plus a registration because the server type it
// produces lives under this module's internal/ tree, which cmd/ cannot name.
func RegisterOIDCLogin(server *grpc.Server, config OIDCConfig, client *http.Client) error {
	verifierConfig := config.verifier()
	if err := verifierConfig.Configured(); err != nil {
		return err
	}
	identityv1.RegisterOIDCLoginServer(server,
		identitygrpc.NewOIDCServer(oidcLogin{verifier: oidc.New(verifierConfig, client)}))
	return nil
}

func (config OIDCConfig) verifier() oidc.Config {
	verifierConfig := oidc.Config{
		Issuer: config.Issuer, ClientID: config.ClientID, ClientSecret: config.ClientSecret,
		RedirectURI: config.RedirectURI, RoleClaim: config.RoleClaim,
		AllowedRoles:  slices.Clone(config.AllowedRoles),
		TenantMapping: config.TenantMapping, Leeway: config.Leeway,
	}
	return verifierConfig
}

// oidcLogin restates the verifier's principal as the module's own. The verifier
// deals in verified claims; api.Principal is what the rest of the process trusts,
// and keeping the two types distinct is what stops an unverified claim set being
// passed off as one.
type oidcLogin struct{ verifier *oidc.Verifier }

func (l oidcLogin) ExchangeCode(ctx context.Context, code, codeVerifier, redirectURI, nonce string) (api.Principal, bool) {
	verified, ok := l.verifier.ExchangeCode(ctx, code, codeVerifier, redirectURI, nonce)
	return api.Principal{TenantID: verified.TenantID, ActorID: verified.ActorID, Roles: verified.Roles}, ok
}

func (l oidcLogin) VerifyIDToken(ctx context.Context, idToken, nonce string) (api.Principal, bool) {
	verified, ok := l.verifier.VerifyIDToken(ctx, idToken, nonce)
	return api.Principal{TenantID: verified.TenantID, ActorID: verified.ActorID, Roles: verified.Roles}, ok
}
