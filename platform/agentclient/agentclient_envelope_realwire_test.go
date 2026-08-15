package agentclient

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	agentpb "github.com/gitfrok/backend/gen/proto/agent/v1"
	"github.com/gitfrok/backend/modules/agent"
	agentapi "github.com/gitfrok/backend/modules/agent/api"
	"github.com/gitfrok/backend/modules/ci"
	ciapi "github.com/gitfrok/backend/modules/ci/api"
	"github.com/gitfrok/backend/platform/bus"
	ggrpc "google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// TestEnvelopeStateCapsBindTheRealDispatcher is the T-0035 real-wire proof the
// stub-sink test (TestEnvelopeStateUpdateAppliesAndAcks) deliberately cannot be:
// the agent's Envelope sink is NOT a recorder but the SAME ci.EnvelopeCaps holder
// the real CI dispatcher reads through EnvelopeThrottle on every tick
// (ci.NewRuntime wires WithEnvelopeThrottle(caps)). An EnvelopeStateUpdate stated
// by the control plane over the real mTLS channel therefore lands in the exact
// holder the dispatch loop binds — throttle applied on breach, lifted on recovery,
// and the applied state reported back is the EnvelopeStateAck the control plane's
// delivery records (the wire carries generation + applied + error; that IS the
// applied fact today).
//
// The observable enforcement fact on the data plane is the scaler-input half of
// the throttle: the dispatcher's tick caps the KEDA queue-depth gauge at the
// published QueueDepthCap. The test reads that gauge through the runtime's real
// Prometheus endpoint, so a breach renders the capped depth and a recovery renders
// the full depth again. The claim-gate half (MaxCIConcurrency bounding in-flight
// dispatch) binds off the SAME holder — proven against a held inflight by the
// dispatcher package's own suite; here the wire-to-holder-to-tick loop is what is
// under test, and the holder reading is the composition fact.
func TestEnvelopeStateCapsBindTheRealDispatcher(t *testing.T) {
	// Wall-anchored fake clock, same discipline as newCPRig: the DevCA root is
	// dated on the wall clock, so a fixed past date would read it as not-yet-valid.
	clock := &fakeClock{t: time.Now()}
	logs := &strings.Builder{}
	logf := func(format string, args ...any) { fmt.Fprintf(logs, format+"\n", args...) }
	ca, err := agent.NewDevCA("test-envelope-realwire-ca", time.Now)
	if err != nil {
		t.Fatalf("NewDevCA: %v", err)
	}
	svc := agent.New(allowPDP{}, bus.NewInProcess(), ca, agentapi.Config{
		CertLifetime:          time.Hour,
		RotationLead:          20 * time.Minute,
		RotationRetryInterval: time.Minute,
		StaleAfter:            5 * time.Minute,
		TokenMaxLifetime:      24 * time.Hour,
		HeartbeatInterval:     30 * time.Second,
		ClockSkewLeeway:       5 * time.Minute,
		Now:                   clock.Now,
	}, logf)

	env := &fakeEnvelopeDelivery{}
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
	srv := agent.NewGRPCServer(svc, 5*time.Millisecond, clock.Now, logf)
	agent.AttachMetering(srv, nil, env)
	agentpb.RegisterAgentGatewayServer(server, srv)
	go func() { _ = server.Serve(lis) }()
	t.Cleanup(server.Stop)
	addr := "localhost" + lis.Addr().String()[strings.LastIndex(lis.Addr().String(), ":"):]

	// The data plane under test is the REAL composition: a CI runtime with a
	// launcher (so the dispatcher exists and ticks), whose EnvelopeCaps holder is
	// handed to the agent as its Envelope sink. Nothing in between is a stub of
	// the throttle itself.
	runtime := ci.NewRuntime(allowPDP{}, bus.NewInProcess(), ci.RunnerConfig{
		RuntimeClass:     "gvisor",
		Image:            "registry.example/ci-runner@sha256:" + strings.Repeat("a", 64),
		SourceEndpoint:   "gitwire",
		SourceCapability: "SOURCE_READ",
		Command:          []string{"/bin/true"},
		Namespace:        "ci-jobs",
	}, ci.NewDevLauncher())
	if !runtime.Dispatches() {
		t.Fatal("runtime without a dispatcher: the throttle would have nothing to bind")
	}
	caps := runtime.EnvelopeCaps()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = runtime.RunDispatcher(ctx) }()

	// gaugeDepth reads the queue depth exactly as KEDA does: through the runtime's
	// Prometheus endpoint, which the dispatcher's tick shapes on every iteration.
	gaugeDepth := func() int64 {
		rec := httptest.NewRecorder()
		runtime.MetricsHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		for _, line := range strings.Split(rec.Body.String(), "\n") {
			if v, ok := strings.CutPrefix(line, "ci_queued_jobs "); ok {
				n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
				if err != nil {
					t.Fatalf("gauge value %q: %v", v, err)
				}
				return n
			}
		}
		t.Fatal("ci_queued_jobs missing from the metrics endpoint")
		return 0
	}
	seq := 0
	enqueue := func(n int) {
		t.Helper()
		for i := 0; i < n; i++ {
			seq++
			_, err := runtime.Jobs().Enqueue(ctx, ciapi.EnqueueRequest{
				Context: ciapi.Context{
					TenantID: "acme", RepositoryID: "repo-1", ActorID: "op-1",
					RequestID:  fmt.Sprintf("req-%d-%d", time.Now().UnixNano(), seq),
					ActorRoles: []string{"owner"},
				},
				Ref: "refs/heads/main", CommitSHA: strings.Repeat("0", 40),
				Trigger: ciapi.TriggerManual,
			})
			if err != nil {
				t.Fatalf("Enqueue: %v", err)
			}
		}
	}

	// The control plane has a breached envelope before the plane connects: the
	// fair-use caps state max 1 in-flight and a queue-depth gauge capped at 2.
	gen1 := env.publish(1, 2)

	_, secret, err := svc.IssueEnrolmentToken(operatorCtx("acme", "op-1"), "acme", "op-1", time.Hour)
	if err != nil {
		t.Fatalf("IssueEnrolmentToken: %v", err)
	}
	client, err := New(Config{
		GatewayAddr:     addr,
		ServerName:      "localhost",
		Roots:           ca.CAPool(),
		Store:           &MemoryCertStore{},
		ClockSkewLeeway: 5 * time.Minute,
		HeartbeatEvery:  10 * time.Millisecond,
		Now:             clock.Now,
		Envelope:        caps, // the REAL dispatcher's holder — not a recorder
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := client.Bootstrap(context.Background(), EnrolInput{
		Token: secret, Cloud: agentpb.Cloud_CLOUD_GKE, Region: "eu-west1",
		AgentVersion: "0.1.0", K8sVersion: "1.31.0",
	}); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	serveCtx, serveCancel := context.WithCancel(context.Background())
	serveErr := make(chan error, 1)
	go func() { serveErr <- client.Connect(serveCtx) }()

	waitFor(t, 5*time.Second, func() bool {
		fleet, err := svc.Fleet(operatorCtx("acme", "op-1"), "acme", "op-1")
		return err == nil && len(fleet) == 1 && fleet[0].Status == agentapi.StatusConnected
	}, "data plane never reached CONNECTED")

	// Breach applied: the caps the wire delivered are the exact values the
	// dispatcher's claim gate and scaler read from the shared holder.
	waitFor(t, 5*time.Second, func() bool {
		return caps.MaxCIConcurrency() == 1 && caps.QueueDepthCap() == 2
	}, "the real caps holder never received the published breach caps")
	waitFor(t, 5*time.Second, func() bool {
		ack, ok := env.lastAck()
		return ok && ack.generation == gen1 && ack.applied && ack.err == ""
	}, "the control plane never recorded an applied ack for the breach generation")

	// The throttle BINDS on the data plane: five queued jobs render as the capped
	// depth 2 on the KEDA gauge, because the dispatcher's tick reads the holder.
	enqueue(5)
	waitFor(t, 5*time.Second, func() bool { return gaugeDepth() == 2 },
		"the KEDA gauge never rendered the capped queue depth under breach")

	// Recovery: the control plane's no-breach evaluation states 0/0 — absolute
	// applied-state semantics, 0 LIFTS the cap (SPEC-0041 AC9).
	gen2 := env.publish(0, 0)
	waitFor(t, 5*time.Second, func() bool {
		return caps.MaxCIConcurrency() == 0 && caps.QueueDepthCap() == 0
	}, "the real caps holder never received the recovery caps")
	waitFor(t, 5*time.Second, func() bool {
		ack, ok := env.lastAck()
		return ok && ack.generation == gen2 && ack.applied && ack.err == ""
	}, "the control plane never recorded an applied ack for the recovery generation")

	// The throttle LIFTS: a fresh burst renders its FULL depth on the gauge — the
	// old cap no longer shapes the scaler input. (While capped, the gauge can
	// never read above 2, so a 3 is proof of lift, not of leftover state.)
	enqueue(3)
	waitFor(t, 5*time.Second, func() bool { return gaugeDepth() == 3 },
		"the KEDA gauge never rendered the full queue depth after recovery")

	serveCancel()
	<-serveErr
}
