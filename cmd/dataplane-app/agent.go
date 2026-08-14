// The data-plane agent's install-time self-registration (T-0031, SPEC-0039 AC1, ADR-0060).
//
// An install is only real if it self-registers: the chart carries a one-time enrolment token in
// at install time, and this file is where the data plane consumes it — selecting the per-cloud
// driver, dialing the control plane OUTBOUND, presenting the token once, and then serving the
// channel on the control-plane-issued credential. There is no inbound path; the agent is the
// only side that ever dials (ADR-0011).
//
// SECRECY (SPEC-0038 AC2): the token is read from the environment exactly once, handed to the
// agent client's bootstrap, and is never logged, never echoed into an error, and never written
// to the credential file. Nothing in this file names the token after it is presented.
package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"time"

	agentpb "github.com/gitfrok/backend/gen/proto/agent/v1"
	"github.com/gitfrok/backend/platform/agentclient"
	"github.com/gitfrok/backend/platform/clouddriver"
)

const (
	// agentGatewayAddrEnv is the control-plane AgentGateway endpoint the data plane dials
	// outbound. When empty, the agent is disabled and the plane serves its own doors only.
	agentGatewayAddrEnv = "GITFROK_AGENT_GATEWAY_ADDR"
	// agentServerNameEnv is the TLS name the gateway's server certificate must carry. When
	// unset it is derived from the gateway address host — never invented.
	agentServerNameEnv = "GITFROK_AGENT_SERVER_NAME"
	// enrolmentTokenEnv carries the one-time token the install supplies. It is consumed on the
	// first Connect and never persisted (SPEC-0038 AC2).
	enrolmentTokenEnv = "GITFROK_ENROLMENT_TOKEN"
	// cloudEnv names the provider this data plane runs on: gke, eks or aks. It drives driver
	// selection and the enrolment record's cloud.
	cloudEnv = "GITFROK_CLOUD"
	// regionEnv is the region this data plane runs in (G7 residency).
	regionEnv = "GITFROK_REGION"
	// agentCABundleEnv is the path to the pinned control-plane CA bundle used to verify the
	// gateway and every issued/rotated client certificate.
	agentCABundleEnv = "GITFROK_AGENT_CA_BUNDLE"
	// agentCredentialPathEnv is the file the agent stores its issued credential at. Only the
	// credential is ever written there — never the token.
	agentCredentialPathEnv = "GITFROK_AGENT_CREDENTIAL_PATH"
	// cloudSettingsEnv supplies the driver's required per-cloud settings as comma-separated
	// key=value pairs, e.g. "gke.workloadIdentityServiceAccount=dp@acme.iam".
	cloudSettingsEnv = "GITFROK_CLOUD_SETTINGS"
	// agentSkewLeewayEnv is the accepted clock skew when judging certificate validity windows.
	agentSkewLeewayEnv = "GITFROK_AGENT_CLOCK_SKEW_LEEWAY"
	// agentHeartbeatEnv paces keep-alive heartbeats on the established stream.
	agentHeartbeatEnv = "GITFROK_AGENT_HEARTBEAT_INTERVAL"
)

// agentClientConfig is the resolved install-time agent configuration.
type agentClientConfig struct {
	gatewayAddr     string
	serverName      string
	token           string
	provider        clouddriver.Provider
	region          string
	caBundlePath    string
	credentialPath  string
	settings        clouddriver.Settings
	clockSkewLeeway time.Duration
	heartbeatEvery  time.Duration
}

// loadAgentClientConfig resolves the agent configuration. An unset gateway address is a valid
// answer — the agent is simply disabled. A configured agent with any missing or malformed value
// is a rollout failure, never a half-wired connection (invariant 13).
func loadAgentClientConfig(getenv func(string) string) (agentClientConfig, bool, error) {
	addr := getenv(agentGatewayAddrEnv)
	if addr == "" {
		return agentClientConfig{}, false, nil
	}

	require := func(name string) (string, error) {
		v := getenv(name)
		if strings.TrimSpace(v) == "" {
			return "", fmt.Errorf("%s is required when %s is set", name, agentGatewayAddrEnv)
		}
		return v, nil
	}
	token, err := require(enrolmentTokenEnv)
	if err != nil {
		return agentClientConfig{}, false, err
	}
	cloud, err := require(cloudEnv)
	if err != nil {
		return agentClientConfig{}, false, err
	}
	region, err := require(regionEnv)
	if err != nil {
		return agentClientConfig{}, false, err
	}
	caBundle, err := require(agentCABundleEnv)
	if err != nil {
		return agentClientConfig{}, false, err
	}
	credPath, err := require(agentCredentialPathEnv)
	if err != nil {
		return agentClientConfig{}, false, err
	}

	serverName := getenv(agentServerNameEnv)
	if strings.TrimSpace(serverName) == "" {
		serverName = hostOf(addr)
		if serverName == "" {
			return agentClientConfig{}, false, fmt.Errorf(
				"could not derive a TLS server name from %s=%q; set %s", agentGatewayAddrEnv, addr, agentServerNameEnv)
		}
	}

	settings, err := parseCloudSettings(getenv(cloudSettingsEnv))
	if err != nil {
		return agentClientConfig{}, false, err
	}

	skew, err := agentDuration(getenv, agentSkewLeewayEnv, "5m")
	if err != nil {
		return agentClientConfig{}, false, err
	}
	heartbeat, err := agentDuration(getenv, agentHeartbeatEnv, "30s")
	if err != nil {
		return agentClientConfig{}, false, err
	}

	return agentClientConfig{
		gatewayAddr:     addr,
		serverName:      serverName,
		token:           token,
		provider:        clouddriver.Provider(strings.ToLower(cloud)),
		region:          region,
		caBundlePath:    caBundle,
		credentialPath:  credPath,
		settings:        settings,
		clockSkewLeeway: skew,
		heartbeatEvery:  heartbeat,
	}, true, nil
}

// parseCloudSettings turns "k1=v1,k2=v2" into a Settings map. An empty string yields an empty
// map; a malformed entry is an error.
func parseCloudSettings(raw string) (clouddriver.Settings, error) {
	settings := clouddriver.Settings{}
	if strings.TrimSpace(raw) == "" {
		return settings, nil
	}
	for _, pair := range strings.Split(raw, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		key, value, ok := strings.Cut(pair, "=")
		if !ok || strings.TrimSpace(key) == "" {
			return nil, fmt.Errorf("%s entry %q is not key=value", cloudSettingsEnv, pair)
		}
		settings[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	return settings, nil
}

// hostOf returns the host portion of an address that may carry a port.
func hostOf(addr string) string {
	if i := strings.LastIndex(addr, ":"); i > 0 && !strings.Contains(addr[i+1:], "]") {
		return strings.Trim(addr[:i], "[]")
	}
	return strings.Trim(addr, "[]")
}

func agentDuration(getenv func(string) string, name, fallback string) (time.Duration, error) {
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

// cloudProto maps the driver's provider onto the enrolment wire enum.
func cloudProto(p clouddriver.Provider) agentpb.Cloud {
	switch p {
	case clouddriver.ProviderGKE:
		return agentpb.Cloud_CLOUD_GKE
	case clouddriver.ProviderEKS:
		return agentpb.Cloud_CLOUD_EKS
	case clouddriver.ProviderAKS:
		return agentpb.Cloud_CLOUD_AKS
	default:
		return agentpb.Cloud_CLOUD_OTHER
	}
}

// loadTrustPool reads the pinned control-plane CA bundle. A missing or unusable bundle is a
// rollout failure: an agent that cannot pin the control plane's CA must not connect.
func loadTrustPool(path string) (*x509.CertPool, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("%s holds no usable PEM certificates", path)
	}
	return pool, nil
}

// runAgent performs the install-time self-registration and then serves the channel until ctx
// ends. It selects the per-cloud driver first: a missing required setting refuses the install
// before anything dials.
func runAgent(ctx context.Context, cfg agentClientConfig, logf func(string, ...any)) error {
	driver, err := clouddriver.Select(cfg.provider, cfg.settings)
	if err != nil {
		return err
	}
	roots, err := loadTrustPool(cfg.caBundlePath)
	if err != nil {
		return err
	}
	client, err := agentclient.New(agentclient.Config{
		GatewayAddr:     cfg.gatewayAddr,
		ServerName:      cfg.serverName,
		Roots:           roots,
		Store:           agentclient.NewFileCertStore(cfg.credentialPath),
		ClockSkewLeeway: cfg.clockSkewLeeway,
		HeartbeatEvery:  cfg.heartbeatEvery,
		Now:             time.Now,
		Logf:            logf,
	})
	if err != nil {
		return err
	}

	// Bootstrap consumes the token. From this point the data plane holds a control-plane
	// credential and the token is gone.
	if _, err := client.Bootstrap(ctx, agentclient.EnrolInput{
		Token:        cfg.token,
		Cloud:        cloudProto(cfg.provider),
		Region:       cfg.region,
		AgentVersion: buildAgentVersion(),
		K8sVersion:   os.Getenv("GITFROK_K8S_VERSION"),
		Capabilities: driver.Capabilities(),
	}); err != nil {
		return fmt.Errorf("self-registration failed: %w", err)
	}
	// Serve the channel on the stored credential until the process stops.
	return client.Connect(ctx)
}

// buildAgentVersion names the agent version reported at enrolment; it is injected at build time
// and defaults to a dev marker.
func buildAgentVersion() string {
	if v := os.Getenv("GITFROK_AGENT_VERSION"); v != "" {
		return v
	}
	return "0.1.0-dev"
}
