package main

import (
	"fmt"
	"strings"

	"github.com/gitfrok/backend/modules/identity"
)

// OIDC login configuration. Every value is per-environment (invariant 13,
// ADR-0045): no issuer, client, audience, role vocabulary, or tenant mapping is
// compiled in, because a compiled-in one is a production value in a public repo.
const (
	oidcIssuerEnv        = "GITFROK_OIDC_ISSUER"
	oidcClientIDEnv      = "GITFROK_OIDC_CLIENT_ID"
	oidcClientSecretEnv  = "GITFROK_OIDC_CLIENT_SECRET"
	oidcRedirectURIEnv   = "GITFROK_OIDC_REDIRECT_URI"
	oidcRoleClaimEnv     = "GITFROK_OIDC_ROLE_CLAIM"
	oidcAllowedRolesEnv  = "GITFROK_OIDC_ALLOWED_ROLES"
	oidcTenantMappingEnv = "GITFROK_OIDC_TENANT_MAPPING"
)

// loadOIDCConfig reads the login configuration. An empty issuer means this
// environment has no OIDC login, which is a valid deployment — PATs and SSH keys
// still authenticate. Anything else missing is a misconfiguration, and it fails
// the rollout rather than denying every login for a reason nobody can see.
func loadOIDCConfig(getenv func(string) string) (identity.OIDCConfig, bool, error) {
	issuer := getenv(oidcIssuerEnv)
	if issuer == "" {
		return identity.OIDCConfig{}, false, nil
	}

	mapping, err := parseTenantMapping(getenv(oidcTenantMappingEnv))
	if err != nil {
		return identity.OIDCConfig{}, false, err
	}
	return identity.OIDCConfig{
		Issuer:        issuer,
		ClientID:      getenv(oidcClientIDEnv),
		ClientSecret:  getenv(oidcClientSecretEnv),
		RedirectURI:   getenv(oidcRedirectURIEnv),
		RoleClaim:     getenv(oidcRoleClaimEnv),
		AllowedRoles:  splitList(getenv(oidcAllowedRolesEnv)),
		TenantMapping: mapping,
	}, true, nil
}

// parseTenantMapping reads `resource-owner=tenant` pairs. The mapping is
// deployment-administered: an identity provider cannot mint tenants by asserting
// resource owners nobody registered (ADR-0045).
func parseTenantMapping(value string) (map[string]string, error) {
	mapping := map[string]string{}
	for _, pair := range splitList(value) {
		owner, tenant, found := strings.Cut(pair, "=")
		owner, tenant = strings.TrimSpace(owner), strings.TrimSpace(tenant)
		if !found || owner == "" || tenant == "" {
			return nil, fmt.Errorf("%s entry %q is not resource-owner=tenant", oidcTenantMappingEnv, pair)
		}
		if existing, duplicate := mapping[owner]; duplicate && existing != tenant {
			return nil, fmt.Errorf("%s maps %q to both %q and %q", oidcTenantMappingEnv, owner, existing, tenant)
		}
		mapping[owner] = tenant
	}
	return mapping, nil
}

func splitList(value string) []string {
	var out []string
	for entry := range strings.SplitSeq(value, ",") {
		if entry = strings.TrimSpace(entry); entry != "" {
			out = append(out, entry)
		}
	}
	return out
}
