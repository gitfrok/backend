package main

import (
	"strings"
	"testing"
	"time"

	"github.com/gitfrok/backend/platform/clouddriver"
)

func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

// TestAgentDisabledByDefault: with no gateway address the agent is off and no value is required.
func TestAgentDisabledByDefault(t *testing.T) {
	_, enabled, err := loadAgentClientConfig(envMap(nil))
	if err != nil || enabled {
		t.Fatalf("disabled agent = enabled=%v err=%v, want disabled with no error", enabled, err)
	}
}

// TestAgentRequiresInstallInputs: a configured agent without its install-time inputs refuses.
func TestAgentRequiresInstallInputs(t *testing.T) {
	base := map[string]string{agentGatewayAddrEnv: "agent.example:443"}
	for _, missing := range []string{
		enrolmentTokenEnv, cloudEnv, regionEnv, agentCABundleEnv, agentCredentialPathEnv,
	} {
		env := map[string]string{}
		for k, v := range base {
			env[k] = v
		}
		for _, set := range []string{enrolmentTokenEnv, cloudEnv, regionEnv, agentCABundleEnv, agentCredentialPathEnv} {
			if set != missing {
				env[set] = "value"
			}
		}
		env[cloudEnv] = "gke"
		if missing == cloudEnv {
			delete(env, cloudEnv)
		}
		_, enabled, err := loadAgentClientConfig(envMap(env))
		if err == nil || enabled {
			t.Fatalf("missing %s: enabled=%v err=%v, want a refusal", missing, enabled, err)
		}
		if !strings.Contains(err.Error(), missing) {
			t.Fatalf("refusal %q does not name the missing %s", err, missing)
		}
	}
}

// TestAgentConfigResolved: a full install resolves every field, deriving the server name.
func TestAgentConfigResolved(t *testing.T) {
	cfg, enabled, err := loadAgentClientConfig(envMap(map[string]string{
		agentGatewayAddrEnv:    "agent.gitsaas.example:8443",
		enrolmentTokenEnv:      "tok-123",
		cloudEnv:               "GKE",
		regionEnv:              "eu-west1",
		agentCABundleEnv:       "/etc/gitfrok/ca.pem",
		agentCredentialPathEnv: "/var/lib/gitfrok/agent/credential.pem",
		cloudSettingsEnv:       "gke.workloadIdentityServiceAccount=dp@acme.iam",
	}))
	if err != nil || !enabled {
		t.Fatalf("enabled agent = enabled=%v err=%v", enabled, err)
	}
	if cfg.provider != clouddriver.ProviderGKE {
		t.Fatalf("provider = %q, want gke (lowercased)", cfg.provider)
	}
	if cfg.serverName != "agent.gitsaas.example" {
		t.Fatalf("derived server name = %q", cfg.serverName)
	}
	if cfg.settings[clouddriver.SettingGKEWorkloadIdentitySA] != "dp@acme.iam" {
		t.Fatalf("cloud settings = %+v", cfg.settings)
	}
	if cfg.clockSkewLeeway != 5*time.Minute || cfg.heartbeatEvery != 30*time.Second {
		t.Fatalf("timing defaults = %v / %v", cfg.clockSkewLeeway, cfg.heartbeatEvery)
	}
}

// TestParseCloudSettings: well-formed entries parse; malformed ones refuse.
func TestParseCloudSettings(t *testing.T) {
	got, err := parseCloudSettings("a=1, b=2")
	if err != nil || got["a"] != "1" || got["b"] != "2" {
		t.Fatalf("parse = %+v/%v", got, err)
	}
	if got, err := parseCloudSettings(""); err != nil || len(got) != 0 {
		t.Fatalf("empty parse = %+v/%v, want empty map, no error", got, err)
	}
	if _, err := parseCloudSettings("novalue"); err == nil {
		t.Fatal("a key=value-less entry must be refused")
	}
}

func TestHostOf(t *testing.T) {
	for in, want := range map[string]string{
		"host:443":   "host",
		"host":       "host",
		"[::1]:8443": "::1",
	} {
		if got := hostOf(in); got != want {
			t.Fatalf("hostOf(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestRunAgentRefusesMissingDriverSetting: the install-time path refuses before dialing when a
// required per-cloud setting is absent — the driver seam's refusal reaches the real install.
func TestRunAgentRefusesMissingDriverSetting(t *testing.T) {
	cfg := agentClientConfig{
		gatewayAddr:    "agent.example:443",
		provider:       clouddriver.ProviderEKS,
		region:         "us-east-1",
		caBundlePath:   t.TempDir() + "/does-not-matter.pem",
		credentialPath: t.TempDir() + "/cred.pem",
		settings:       clouddriver.Settings{}, // eks.irsaRoleArn missing
	}
	err := runAgent(t.Context(), cfg, func(string, ...any) {})
	if err == nil {
		t.Fatal("runAgent must refuse a missing required driver setting")
	}
	if !strings.Contains(err.Error(), clouddriver.SettingEKSIRSARoleArn) {
		t.Fatalf("refusal %q does not name the missing setting", err)
	}
}
