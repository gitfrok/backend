package main

import (
	"testing"
)

func oidcEnv() map[string]string {
	return map[string]string{
		oidcIssuerEnv:        "https://issuer.gitsaas.test",
		oidcClientIDEnv:      "client-a",
		oidcClientSecretEnv:  "secret-a",
		oidcRedirectURIEnv:   "https://app.gitsaas.test/callback",
		oidcRoleClaimEnv:     "gitfrok:roles",
		oidcAllowedRolesEnv:  "owner, member, reader",
		oidcTenantMappingEnv: "org-a=tenant-a,org-b=tenant-b",
	}
}

func TestLoadOIDCConfigReadsTheEnvironment(t *testing.T) {
	config, enabled, err := loadOIDCConfig(getenvFrom(oidcEnv()))
	if err != nil {
		t.Fatalf("loadOIDCConfig: %v", err)
	}
	if !enabled {
		t.Fatal("a configured issuer did not enable OIDC login")
	}
	//arch:allow-inline-authz asserts the configured vocabulary was parsed, not who may do what
	if len(config.AllowedRoles) != 3 || config.AllowedRoles[1] != "member" {
		t.Fatalf("allowed roles = %v", config.AllowedRoles)
	}
	if config.TenantMapping["org-b"] != "tenant-b" {
		t.Fatalf("tenant mapping = %v", config.TenantMapping)
	}
	if err := config.Validate(); err != nil {
		t.Fatalf("a complete configuration was refused: %v", err)
	}
}

// A deployment with no identity provider is valid: PATs and SSH keys still
// authenticate, and no login surface is served.
func TestNoIssuerMeansNoOIDCLogin(t *testing.T) {
	_, enabled, err := loadOIDCConfig(getenvFrom(map[string]string{}))
	if err != nil {
		t.Fatalf("loadOIDCConfig: %v", err)
	}
	if enabled {
		t.Fatal("OIDC login was enabled with no issuer configured")
	}
}

// Anything else missing is a misconfiguration, and it must fail the rollout
// rather than deny every login for a reason nobody can see.
func TestAHalfConfiguredProviderFailsValidation(t *testing.T) {
	for _, missing := range []string{
		oidcClientIDEnv, oidcRedirectURIEnv, oidcRoleClaimEnv,
		oidcAllowedRolesEnv, oidcTenantMappingEnv,
	} {
		t.Run(missing, func(t *testing.T) {
			env := oidcEnv()
			delete(env, missing)
			config, enabled, err := loadOIDCConfig(getenvFrom(env))
			if err != nil {
				return // rejected while parsing, which is equally a refusal
			}
			if !enabled {
				t.Fatalf("dropping %s silently disabled OIDC login", missing)
			}
			if err := config.Validate(); err == nil {
				t.Fatalf("accepted a provider with no %s", missing)
			}
		})
	}
}

// The tenant mapping is deployment-administered, so a malformed or contradictory
// one is a rollout failure rather than a mapping someone has to guess at.
func TestAMalformedTenantMappingIsRefused(t *testing.T) {
	for name, value := range map[string]string{
		"no separator":  "org-a",
		"no tenant":     "org-a=",
		"no owner":      "=tenant-a",
		"contradictory": "org-a=tenant-a,org-a=tenant-b",
	} {
		t.Run(name, func(t *testing.T) {
			env := oidcEnv()
			env[oidcTenantMappingEnv] = value
			if _, _, err := loadOIDCConfig(getenvFrom(env)); err == nil {
				t.Fatalf("accepted a tenant mapping with %s", name)
			}
		})
	}
}

// Repeating the same pair is not a contradiction, and must not fail a rollout.
func TestARepeatedTenantMappingEntryIsAccepted(t *testing.T) {
	env := oidcEnv()
	env[oidcTenantMappingEnv] = "org-a=tenant-a,org-a=tenant-a"
	config, _, err := loadOIDCConfig(getenvFrom(env))
	if err != nil {
		t.Fatalf("loadOIDCConfig: %v", err)
	}
	if config.TenantMapping["org-a"] != "tenant-a" {
		t.Fatalf("tenant mapping = %v", config.TenantMapping)
	}
}
