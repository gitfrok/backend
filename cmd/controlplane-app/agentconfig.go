package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/gitfrok/backend/modules/agent/api"
)

// The agent gateway's per-environment configuration (invariant 13): every timing on the
// enrolment surface is an env var with a dev-friendly default, never a compiled-in
// production value. The defaults are named here and mirrored into deploy/MVP-RUNBOOK.md.
const (
	// agentGRPCAddrEnv opens the AgentGateway door when set; an empty value means the
	// plane serves health only.
	agentGRPCAddrEnv = "GITFROK_AGENT_GRPC_ADDR"
	// agentServerNamesEnv lists the DNS names minted into the gateway's server
	// certificate, comma-separated.
	agentServerNamesEnv = "GITFROK_AGENT_SERVER_NAMES"
	// agentCertLifetimeEnv is how long an issued client certificate lives.
	agentCertLifetimeEnv = "GITFROK_AGENT_CERT_LIFETIME"
	// agentRotationLeadEnv is how long before expiry the next rotation is delivered.
	agentRotationLeadEnv = "GITFROK_AGENT_ROTATION_LEAD"
	// agentRotationRetryEnv paces re-delivery after a failed or unacknowledged rotation.
	agentRotationRetryEnv = "GITFROK_AGENT_ROTATION_RETRY"
	// agentStaleAfterEnv is the contact window after which a data plane reads as stale.
	agentStaleAfterEnv = "GITFROK_AGENT_STALE_AFTER"
	// agentTokenMaxLifetimeEnv caps the lifetime an operator may grant an enrolment token.
	agentTokenMaxLifetimeEnv = "GITFROK_AGENT_TOKEN_MAX_LIFETIME"
	// agentHeartbeatEnv is the heartbeat cadence communicated to the agent on enrolment.
	agentHeartbeatEnv = "GITFROK_AGENT_HEARTBEAT_INTERVAL"
	// agentSkewLeewayEnv backdates issued certificates' validity for skewed cluster clocks.
	agentSkewLeewayEnv = "GITFROK_AGENT_CLOCK_SKEW_LEEWAY"
)

type agentConfig struct {
	grpcAddr    string
	serverNames []string
	enrolment   api.Config
}

// loadAgentConfig reads the gateway configuration. An unset address is a valid answer:
// the door simply does not exist. A malformed value fails the rollout rather than starting
// a gateway with timings nobody chose.
func loadAgentConfig(getenv func(string) string) (agentConfig, error) {
	addr := getenv(agentGRPCAddrEnv)
	if addr == "" {
		return agentConfig{}, nil
	}

	certLifetime, err := envDuration(getenv, agentCertLifetimeEnv, "1h")
	if err != nil {
		return agentConfig{}, err
	}
	rotationLead, err := envDuration(getenv, agentRotationLeadEnv, "20m")
	if err != nil {
		return agentConfig{}, err
	}
	rotationRetry, err := envDuration(getenv, agentRotationRetryEnv, "1m")
	if err != nil {
		return agentConfig{}, err
	}
	staleAfter, err := envDuration(getenv, agentStaleAfterEnv, "5m")
	if err != nil {
		return agentConfig{}, err
	}
	tokenMax, err := envDuration(getenv, agentTokenMaxLifetimeEnv, "24h")
	if err != nil {
		return agentConfig{}, err
	}
	heartbeat, err := envDuration(getenv, agentHeartbeatEnv, "30s")
	if err != nil {
		return agentConfig{}, err
	}
	skewLeeway, err := envDuration(getenv, agentSkewLeewayEnv, "5m")
	if err != nil {
		return agentConfig{}, err
	}

	// Sanity the composition cannot recover from at request time: a rotation lead that
	// reaches past the certificate's whole lifetime would rotate at issuance.
	if rotationLead >= certLifetime {
		return agentConfig{}, fmt.Errorf("%s must be shorter than %s", agentRotationLeadEnv, agentCertLifetimeEnv)
	}

	names := []string{"localhost"}
	if raw := getenv(agentServerNamesEnv); raw != "" {
		names = nil
		for _, n := range strings.Split(raw, ",") {
			if n = strings.TrimSpace(n); n != "" {
				names = append(names, n)
			}
		}
		if len(names) == 0 {
			return agentConfig{}, fmt.Errorf("%s is set but names no server", agentServerNamesEnv)
		}
	}

	return agentConfig{
		grpcAddr:    addr,
		serverNames: names,
		enrolment: api.Config{
			CertLifetime:          certLifetime,
			RotationLead:          rotationLead,
			RotationRetryInterval: rotationRetry,
			StaleAfter:            staleAfter,
			TokenMaxLifetime:      tokenMax,
			HeartbeatInterval:     heartbeat,
			ClockSkewLeeway:       skewLeeway,
			Now:                   time.Now,
		},
	}, nil
}

func envDuration(getenv func(string) string, name, fallback string) (time.Duration, error) {
	raw := getenv(name)
	if raw == "" {
		raw = fallback
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%s=%q is not a duration: %w", name, raw, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("%s=%q must be positive", name, raw)
	}
	return d, nil
}
