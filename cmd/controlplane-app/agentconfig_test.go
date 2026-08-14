package main

import (
	"reflect"
	"testing"
	"time"
)

func env(vars map[string]string) func(string) string {
	return func(k string) string { return vars[k] }
}

func TestLoadAgentConfigDisabledByDefault(t *testing.T) {
	cfg, err := loadAgentConfig(env(map[string]string{}))
	if err != nil {
		t.Fatalf("loadAgentConfig: %v", err)
	}
	if cfg.grpcAddr != "" {
		t.Fatalf("gateway address = %q, want empty (door closed)", cfg.grpcAddr)
	}
}

func TestLoadAgentConfigDefaults(t *testing.T) {
	cfg, err := loadAgentConfig(env(map[string]string{agentGRPCAddrEnv: "localhost:8443"}))
	if err != nil {
		t.Fatalf("loadAgentConfig: %v", err)
	}
	for _, check := range []struct {
		name      string
		got, want time.Duration
	}{
		{"cert lifetime", cfg.enrolment.CertLifetime, time.Hour},
		{"rotation lead", cfg.enrolment.RotationLead, 20 * time.Minute},
		{"rotation retry", cfg.enrolment.RotationRetryInterval, time.Minute},
		{"staleness window", cfg.enrolment.StaleAfter, 5 * time.Minute},
		{"token max lifetime", cfg.enrolment.TokenMaxLifetime, 24 * time.Hour},
		{"heartbeat interval", cfg.enrolment.HeartbeatInterval, 30 * time.Second},
		{"clock skew leeway", cfg.enrolment.ClockSkewLeeway, 5 * time.Minute},
	} {
		if check.got != check.want {
			t.Fatalf("default %s = %v, want %v", check.name, check.got, check.want)
		}
	}
	if !reflect.DeepEqual(cfg.serverNames, []string{"localhost"}) {
		t.Fatalf("server names = %v, want [localhost]", cfg.serverNames)
	}
	if cfg.enrolment.Now == nil {
		t.Fatal("the clock must be wired")
	}
}

func TestLoadAgentConfigOverridesAndRefusals(t *testing.T) {
	// Overrides apply, comma-separated names split.
	cfg, err := loadAgentConfig(env(map[string]string{
		agentGRPCAddrEnv:     "0.0.0.0:9443",
		agentServerNamesEnv:  "cp.example.com, cp2.example.com",
		agentCertLifetimeEnv: "2h",
		agentStaleAfterEnv:   "10m",
	}))
	if err != nil {
		t.Fatalf("loadAgentConfig: %v", err)
	}
	if cfg.enrolment.CertLifetime != 2*time.Hour || cfg.enrolment.StaleAfter != 10*time.Minute {
		t.Fatalf("overrides not applied: %+v", cfg.enrolment)
	}
	if !reflect.DeepEqual(cfg.serverNames, []string{"cp.example.com", "cp2.example.com"}) {
		t.Fatalf("server names = %v", cfg.serverNames)
	}

	// Malformed timings fail the rollout rather than starting with unchosen values.
	if _, err := loadAgentConfig(env(map[string]string{agentGRPCAddrEnv: ":1", agentCertLifetimeEnv: "soon"})); err == nil {
		t.Fatal("a malformed duration must fail the rollout")
	}
	if _, err := loadAgentConfig(env(map[string]string{agentGRPCAddrEnv: ":1", agentStaleAfterEnv: "-5m"})); err == nil {
		t.Fatal("a non-positive duration must fail the rollout")
	}
	// A rotation lead that reaches past the certificate's lifetime is a configuration
	// the gateway could never honour.
	if _, err := loadAgentConfig(env(map[string]string{
		agentGRPCAddrEnv: ":1", agentCertLifetimeEnv: "10m", agentRotationLeadEnv: "20m",
	})); err == nil {
		t.Fatal("rotation lead longer than the certificate lifetime must fail the rollout")
	}
	if _, err := loadAgentConfig(env(map[string]string{agentGRPCAddrEnv: ":1", agentServerNamesEnv: " , "})); err == nil {
		t.Fatal("an empty server-name list must fail the rollout")
	}
}
