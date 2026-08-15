package agentclient

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"crypto/tls"

	agentpb "github.com/gitfrok/backend/gen/proto/agent/v1"
	"github.com/gitfrok/backend/modules/agent"
	agentapi "github.com/gitfrok/backend/modules/agent/api"
	identityapi "github.com/gitfrok/backend/modules/identity/api"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
	"github.com/gitfrok/backend/platform/bus"
	"github.com/gitfrok/backend/platform/clouddriver"
	"github.com/gitfrok/backend/platform/tenancy"
	ggrpc "google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// This test exercises the whole install-time path over a real gRPC server: helm-install input
// (an enrolment token plus the cloud driver's facts) → the data-plane agent bootstraps → it
// self-registers in the control-plane registry → it serves the channel and applies a rotation.
// It is the harness half of SPEC-0039 AC1; the live-cluster half is the phase exit, not this
// test (see the conformance matrix).

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}
func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type allowPDP struct{}

func (allowPDP) Decide(context.Context, policyapi.Request) (policyapi.Decision, error) {
	return policyapi.Decision{Allowed: true}, nil
}

// cpRig is the control plane under test, built only from the Agent module's public composition
// root — the same surface cmd/ uses.
type cpRig struct {
	svc   *agent.Service
	ca    *agent.DevCA
	clock *fakeClock
	logs  *strings.Builder
	addr  string
}

func newCPRig(t *testing.T) *cpRig {
	t.Helper()
	clock := &fakeClock{t: time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)}
	logs := &strings.Builder{}
	logf := func(format string, args ...any) { fmt.Fprintf(logs, format+"\n", args...) }

	ca, err := agent.NewDevCA("test-install-ca", time.Now)
	if err != nil {
		t.Fatalf("NewDevCA: %v", err)
	}
	cfg := agentapi.Config{
		CertLifetime:          time.Hour,
		RotationLead:          20 * time.Minute,
		RotationRetryInterval: time.Minute,
		StaleAfter:            5 * time.Minute,
		TokenMaxLifetime:      24 * time.Hour,
		HeartbeatInterval:     30 * time.Second,
		ClockSkewLeeway:       5 * time.Minute,
		Now:                   clock.Now,
	}
	svc := agent.New(allowPDP{}, bus.NewInProcess(), ca, cfg, logf)

	// The gateway's server certificate is dated on the wall clock: Go's TLS verifies it with
	// real time. Client certificates ride RequestClientCert and are admitted by the app layer on
	// the fake clock, exactly as in a real composition.
	serverCert, err := ca.IssueServer("agent-gateway", []string{"localhost"}, time.Now(), 24*time.Hour)
	if err != nil {
		t.Fatalf("server cert: %v", err)
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := ggrpc.NewServer(ggrpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequestClientCert,
	})))
	agentpb.RegisterAgentGatewayServer(server, agent.NewGRPCServer(svc, 5*time.Millisecond, clock.Now, logf))
	go func() { _ = server.Serve(lis) }()
	t.Cleanup(server.Stop)

	addr := "localhost" + lis.Addr().String()[strings.LastIndex(lis.Addr().String(), ":"):]
	return &cpRig{svc: svc, ca: ca, clock: clock, logs: logs, addr: addr}
}

func operatorCtx(tenant, actor string) context.Context {
	ctx := tenancy.WithTenant(context.Background(), tenancy.ID(tenant))
	return identityapi.WithPrincipal(ctx, identityapi.Principal{TenantID: tenant, ActorID: actor, Roles: []string{"owner"}})
}

// TestInstallSelfRegistersAndServe is the install-time path end to end.
func TestInstallSelfRegistersAndServe(t *testing.T) {
	cp := newCPRig(t)

	// Install-time input: an operator mints a one-time token, and the cloud driver supplies the
	// per-cloud facts the agent reports at enrolment.
	_, secret, err := cp.svc.IssueEnrolmentToken(operatorCtx("acme", "op-1"), "acme", "op-1", time.Hour)
	if err != nil {
		t.Fatalf("IssueEnrolmentToken: %v", err)
	}
	driver, err := clouddriver.Select(clouddriver.ProviderGKE, clouddriver.Settings{
		clouddriver.SettingGKEWorkloadIdentitySA: "dp@acme.iam",
	})
	if err != nil {
		t.Fatalf("driver select: %v", err)
	}

	// A listener standing in for the customer's cluster: the control plane must never connect to
	// it. The assertion at the end is the no-inbound-path tripwire (SPEC-0039 AC4 shape).
	clusterListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("cluster listener: %v", err)
	}
	defer clusterListener.Close()
	var inbound int
	var inboundMu sync.Mutex
	go func() {
		for {
			conn, err := clusterListener.Accept()
			if err != nil {
				return
			}
			inboundMu.Lock()
			inbound++
			inboundMu.Unlock()
			_ = conn.Close()
		}
	}()

	clientLogs := &strings.Builder{}
	store := &MemoryCertStore{}
	client, err := New(Config{
		GatewayAddr:     cp.addr,
		ServerName:      "localhost",
		Roots:           cp.ca.CAPool(),
		Store:           store,
		ClockSkewLeeway: 5 * time.Minute,
		HeartbeatEvery:  10 * time.Millisecond,
		Now:             cp.clock.Now,
		Logf:            func(format string, args ...any) { fmt.Fprintf(clientLogs, format+"\n", args...) },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Bootstrap: present the token once, store the issued credential.
	id, err := client.Bootstrap(context.Background(), EnrolInput{
		Token:        secret,
		Cloud:        agentpb.Cloud_CLOUD_GKE,
		Region:       "eu-west1",
		AgentVersion: "0.1.0",
		K8sVersion:   "1.31.0",
		Capabilities: driver.Capabilities(),
	})
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if id.TenantID != "acme" || id.DataPlaneID == "" {
		t.Fatalf("assigned identity = %q/%q", id.TenantID, id.DataPlaneID)
	}
	firstCertID := certIDFromStore(t, store)

	// Self-registration is a fact in the control-plane registry, not a client claim.
	dp, err := cp.svc.GetDataPlane(operatorCtx("acme", "op-1"), "acme", "op-1", id.DataPlaneID)
	if err != nil {
		t.Fatalf("GetDataPlane: %v", err)
	}
	if dp.Cloud != agentpb.Cloud_CLOUD_GKE.String() || dp.Region != "eu-west1" {
		t.Fatalf("registry cloud/region = %q/%q", dp.Cloud, dp.Region)
	}

	// Serve: reconnect on the stored credential and hold the channel open.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveErr := make(chan error, 1)
	go func() { serveErr <- client.Connect(ctx) }()

	// The stream admitted from the stored certificate reads CONNECTED in the fleet.
	waitFor(t, 5*time.Second, func() bool {
		fleet, err := cp.svc.Fleet(operatorCtx("acme", "op-1"), "acme", "op-1")
		return err == nil && len(fleet) == 1 && fleet[0].Status == agentapi.StatusConnected
	}, "data plane never reached CONNECTED")

	// Inside the rotation lead the control plane delivers the next certificate; the agent
	// applies it and the registry follows.
	cp.clock.advance(40 * time.Minute)
	waitFor(t, 5*time.Second, func() bool {
		dp, err := cp.svc.GetDataPlane(operatorCtx("acme", "op-1"), "acme", "op-1", id.DataPlaneID)
		return err == nil && dp.CurrentCertificateID != firstCertID && dp.CurrentCertificateID != ""
	}, "rotation never landed in the registry")

	cancel()
	<-serveErr

	// Anti-faking callouts ---------------------------------------------------------------
	// SPEC-0038 AC2: the one-time token appears in no log line, no error, and no file the
	// install writes back. The credential store holds only the issued certificate bundle.
	for name, hay := range map[string]string{
		"control-plane logs": cp.logs.String(),
		"agent logs":         clientLogs.String(),
	} {
		if strings.Contains(hay, secret) {
			t.Fatalf("enrolment token leaked into %s", name)
		}
	}
	stored, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("stored credential: %v", err)
	}
	if strings.Contains(string(stored), secret) {
		t.Fatal("enrolment token leaked into the persisted credential bundle")
	}

	// SPEC-0039 (AC4 shape): the control plane opened no inbound path to the customer cluster.
	inboundMu.Lock()
	got := inbound
	inboundMu.Unlock()
	if got != 0 {
		t.Fatalf("control plane made %d inbound connections to the customer cluster, want 0", got)
	}
}

// TestAC5_MultiPlaneNoInboundTripwire re-asserts the zero-inbound property for the
// MULTI-PLANE shape (SPEC-0045 AC5, extending SPEC-0039 AC4): two data planes of one
// tenant enrol, hold their channels open, read CONNECTED side by side — and the control
// plane still opens no connection toward either customer cluster. N planes change the
// registry's shape, never the boundary's direction.
func TestAC5_MultiPlaneNoInboundTripwire(t *testing.T) {
	cp := newCPRig(t)

	// One cluster stand-in per plane; every connection either accepts is an inbound
	// violation.
	var inbound int
	var inboundMu sync.Mutex
	clusterFor := func(name string) net.Listener {
		t.Helper()
		lis, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("cluster listener %s: %v", name, err)
		}
		t.Cleanup(func() { _ = lis.Close() })
		go func() {
			for {
				conn, err := lis.Accept()
				if err != nil {
					return
				}
				inboundMu.Lock()
				inbound++
				inboundMu.Unlock()
				_ = conn.Close()
			}
		}()
		return lis
	}
	_ = clusterFor("plane-1")
	_ = clusterFor("plane-2")

	planeIDs := make([]string, 0, 2)
	for _, region := range []string{"eu-west1", "us-east1"} {
		_, secret, err := cp.svc.IssueEnrolmentToken(operatorCtx("acme", "op-1"), "acme", "op-1", time.Hour)
		if err != nil {
			t.Fatalf("IssueEnrolmentToken: %v", err)
		}
		client, err := New(Config{
			GatewayAddr:     cp.addr,
			ServerName:      "localhost",
			Roots:           cp.ca.CAPool(),
			Store:           &MemoryCertStore{},
			ClockSkewLeeway: 5 * time.Minute,
			HeartbeatEvery:  10 * time.Millisecond,
			Now:             cp.clock.Now,
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		id, err := client.Bootstrap(context.Background(), EnrolInput{
			Token: secret, Cloud: agentpb.Cloud_CLOUD_GKE, Region: region,
			AgentVersion: "0.1.0", K8sVersion: "1.31.0",
		})
		if err != nil {
			t.Fatalf("Bootstrap %s: %v", region, err)
		}
		planeIDs = append(planeIDs, id.DataPlaneID)

		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		go func() { _ = client.Connect(ctx) }()
	}
	if planeIDs[0] == planeIDs[1] {
		t.Fatalf("two enrolments minted the same data-plane ID %q", planeIDs[0])
	}

	// BOTH planes read CONNECTED at the same time: the multi-plane shape serves.
	waitFor(t, 5*time.Second, func() bool {
		fleet, err := cp.svc.Fleet(operatorCtx("acme", "op-1"), "acme", "op-1")
		if err != nil || len(fleet) != 2 {
			return false
		}
		return fleet[0].Status == agentapi.StatusConnected && fleet[1].Status == agentapi.StatusConnected
	}, "the fleet never reached two CONNECTED planes")

	// The tripwire, extended to N: zero inbound connections to ANY customer cluster.
	inboundMu.Lock()
	got := inbound
	inboundMu.Unlock()
	if got != 0 {
		t.Fatalf("control plane made %d inbound connections to the customer clusters, want 0", got)
	}
}

// TestBootstrapRefusalIsCoarse: a spent or bogus token refuses with the coarse enum and leaks
// nothing.
func TestBootstrapRefusalIsCoarse(t *testing.T) {
	cp := newCPRig(t)
	client, err := New(Config{
		GatewayAddr:     cp.addr,
		ServerName:      "localhost",
		Roots:           cp.ca.CAPool(),
		Store:           &MemoryCertStore{},
		ClockSkewLeeway: 5 * time.Minute,
		Now:             cp.clock.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	const bogus = "bogus-token-value"
	_, err = client.Bootstrap(context.Background(), EnrolInput{Token: bogus, Cloud: agentpb.Cloud_CLOUD_EKS})
	var refused *EnrolmentRefused
	if !errors.As(err, &refused) {
		t.Fatalf("Bootstrap with a bogus token = %v, want an EnrolmentRefused", err)
	}
	if strings.Contains(err.Error(), bogus) {
		t.Fatal("refusal echoed the token")
	}
	if strings.Contains(cp.logs.String(), bogus) {
		t.Fatal("control-plane logs echoed the presented token")
	}
}

// certIDFromStore pulls the leaf's serial out of the stored bundle as a stand-in identifier so
// the test can tell two credentials apart without re-implementing the CA's ID scheme.
func certIDFromStore(t *testing.T, store CertStore) string {
	t.Helper()
	pemBundle, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("load stored credential: %v", err)
	}
	leaf, _, err := parseBundle(pemBundle)
	if err != nil {
		t.Fatalf("parse stored credential: %v", err)
	}
	return leaf.SerialNumber.String()
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("%s", msg)
}
