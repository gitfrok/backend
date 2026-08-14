package grpc

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	agentpb "github.com/gitfrok/backend/gen/proto/agent/v1"
	"github.com/gitfrok/backend/modules/agent/api"
	"github.com/gitfrok/backend/modules/agent/internal/adapters/memory"
	"github.com/gitfrok/backend/modules/agent/internal/adapters/pki"
	"github.com/gitfrok/backend/modules/agent/internal/app"
	identityapi "github.com/gitfrok/backend/modules/identity/api"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
	platformaudit "github.com/gitfrok/backend/platform/audit"
	"github.com/gitfrok/backend/platform/bus"
	"github.com/gitfrok/backend/platform/tenancy"
	ggrpc "google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// --- harness ---------------------------------------------------------------------------

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

func (allowPDP) Decide(_ context.Context, _ policyapi.Request) (policyapi.Decision, error) {
	return policyapi.Decision{Allowed: true}, nil
}

// auditRecorder captures every audit event the bus delivers.
type auditRecorder struct {
	mu     sync.Mutex
	events []bus.Event
}

func newAuditRecorder(b *bus.InProcess) *auditRecorder {
	r := &auditRecorder{}
	b.Subscribe(platformaudit.EventAudit, func(_ context.Context, e bus.Event) error {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.events = append(r.events, e)
		return nil
	})
	return r
}

func (r *auditRecorder) of(action string) []bus.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []bus.Event
	for _, e := range r.events {
		if a, ok := e.(interface{ Action() string }); ok && a.Action() == action {
			out = append(out, e)
		}
	}
	return out
}

// rig is the full control-plane composition under one in-process gRPC server: app service,
// memory stores, dev CA and the gateway adapter. The TLS layer carries client certificates
// without verifying them — admission is the app layer's audited decision, exactly as in a
// real composition.
type rig struct {
	svc    *app.Service
	ca     *pki.DevCA
	clock  *fakeClock
	logs   *strings.Builder
	audits *auditRecorder
	addr   string
}

func newRig(t *testing.T) *rig {
	t.Helper()
	clock := &fakeClock{t: time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)}
	logs := &strings.Builder{}
	logf := func(format string, args ...any) { fmt.Fprintf(logs, format+"\n", args...) }

	// The CA is dated on the WALL clock: Go's TLS stack verifies chains with real time.
	// Leaf certificates issued through the service carry the fake clock's dates, but the
	// TLS layer only carries them (RequestClientCert) — admission is the app layer's call.
	ca, err := pki.NewDevCA("test-enrolment-ca", time.Now)
	if err != nil {
		t.Fatalf("NewDevCA: %v", err)
	}
	b := bus.NewInProcess()
	cfg := api.Config{
		CertLifetime:          time.Hour,
		RotationLead:          20 * time.Minute,
		RotationRetryInterval: time.Minute,
		StaleAfter:            5 * time.Minute,
		TokenMaxLifetime:      24 * time.Hour,
		HeartbeatInterval:     30 * time.Second,
		ClockSkewLeeway:       5 * time.Minute,
		Now:                   clock.Now,
	}
	svc := app.New(allowPDP{}, b, ca, memory.New(), memory.New(), cfg, logf)

	// Server certificate from the same dev CA, named "localhost" so clients verify it
	// through the normal trust chain — no verification shortcut anywhere in the test. It is
	// dated on the WALL clock: the TLS layer verifies with real time, unlike the app-layer
	// decisions under test, which use the fake clock.
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
		ClientAuth:   tls.RequestClientCert, // admission happens in the app layer, audited
	})))
	agentpb.RegisterAgentGatewayServer(server, NewGateway(svc, 5*time.Millisecond, clock.Now, logf))
	go func() { _ = server.Serve(lis) }()
	t.Cleanup(server.Stop)

	return &rig{svc: svc, ca: ca, clock: clock, logs: logs, audits: newAuditRecorder(b), addr: "localhost" + lis.Addr().String()[strings.LastIndex(lis.Addr().String(), ":"):]}
}

// dial opens one client connection. clientCertPEM is the enrolment-issued credential bundle;
// empty for the token-bootstrap connection. The server's certificate is verified against the
// dev CA's trust pool under the "localhost" name — full verification, both directions.
func (r *rig) dial(t *testing.T, clientCertPEM []byte) agentpb.AgentGatewayClient {
	t.Helper()
	cfg := &tls.Config{RootCAs: r.ca.CAPool(), ServerName: "localhost"}
	if len(clientCertPEM) > 0 {
		cert, err := tls.X509KeyPair(clientCertPEM, clientCertPEM)
		if err != nil {
			t.Fatalf("client keypair: %v", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	conn, err := ggrpc.NewClient(r.addr, ggrpc.WithTransportCredentials(credentials.NewTLS(cfg)))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return agentpb.NewAgentGatewayClient(conn)
}

func operatorCtx(tenant, actor string) context.Context {
	ctx := tenancy.WithTenant(context.Background(), tenancy.ID(tenant))
	return identityapi.WithPrincipal(ctx, identityapi.Principal{TenantID: tenant, ActorID: actor, Roles: []string{"owner"}})
}

// issueSecret mints one enrolment token through the operator surface and returns the secret.
func (r *rig) issueSecret(t *testing.T, tenant string) string {
	t.Helper()
	_, secret, err := r.svc.IssueEnrolmentToken(operatorCtx(tenant, "op-1"), tenant, "op-1", time.Hour)
	if err != nil {
		t.Fatalf("IssueEnrolmentToken: %v", err)
	}
	return secret
}

// connect opens one stream with a deadline so a hung control plane fails the test.
func (r *rig) connect(t *testing.T, client agentpb.AgentGatewayClient) agentpb.AgentGateway_ConnectClient {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	stream, err := client.Connect(ctx)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	return stream
}

// enrolOverWire performs the full first-Connect handshake and returns the ack.
func (r *rig) enrolOverWire(t *testing.T, secret string) (agentpb.AgentGateway_ConnectClient, *agentpb.EnrolmentAck) {
	t.Helper()
	client := r.dial(t, nil)
	stream := r.connect(t, client)
	msg := &agentpb.AgentMessage{
		MessageId: "m-enrol", Seq: 1, SentAt: timestamppb.New(r.clock.Now()),
		Payload: &agentpb.AgentMessage_Enrol{Enrol: &agentpb.Enrol{
			OneTimeToken: secret,
			Cloud:        agentpb.Cloud_CLOUD_GKE,
			Region:       "eu-west1",
			AgentVersion: "0.1.0",
			K8SVersion:   "1.31.0",
			Capabilities: []string{"ci"},
		}},
	}
	if err := stream.Send(msg); err != nil {
		t.Fatalf("Send enrol: %v", err)
	}
	reply, err := stream.Recv()
	if err != nil {
		t.Fatalf("Recv enrolment ack: %v", err)
	}
	ack := reply.GetEnrolmentAck()
	if ack == nil || !ack.GetAccepted() {
		t.Fatalf("enrolment ack = %+v, want accepted", reply)
	}
	return stream, ack
}

// --- AC3 + AC2: full first Connect over a real gRPC server ------------------------------

func TestFirstConnectEnrolmentOverTheWire(t *testing.T) {
	r := newRig(t)
	secret := r.issueSecret(t, "acme")

	stream, ack := r.enrolOverWire(t, secret)
	defer func() { _ = stream.CloseSend() }()

	if ack.GetTenantId() != "acme" || ack.GetDataPlaneId() == "" {
		t.Fatalf("assigned identity = %q/%q", ack.GetTenantId(), ack.GetDataPlaneId())
	}
	cert := ack.GetIssuedCertificate()
	if cert == nil || cert.GetCertificateId() == "" || len(cert.GetCertificatePem()) == 0 || cert.GetExpiresAt() == nil {
		t.Fatalf("issued certificate = %+v", cert)
	}
	if got := ack.GetHeartbeatInterval().AsDuration(); got != 30*time.Second {
		t.Fatalf("heartbeat interval = %v, want 30s", got)
	}

	// AC7: exactly one enrolment record and one first-certificate record.
	if got := len(r.audits.of(platformaudit.ActionAgentEnrolment)); got != 1 {
		t.Fatalf("enrolment audit records = %d, want 1", got)
	}
	if got := len(r.audits.of(platformaudit.ActionAgentCertificateIssued)); got != 1 {
		t.Fatalf("certificate-issued audit records = %d, want 1", got)
	}

	// AC2: the secret never reaches a log line, a wire refusal, or a written record.
	if strings.Contains(r.logs.String(), secret) {
		t.Fatal("token secret appears in control-plane logs")
	}
	for _, e := range r.audits.of(platformaudit.ActionAgentEnrolment) {
		if strings.Contains(fmt.Sprintf("%+v", e), secret) {
			t.Fatal("token secret appears in the audit trail")
		}
	}

	// A heartbeat keeps the plane connected in the operator's fleet (AC8).
	if err := stream.Send(&agentpb.AgentMessage{
		MessageId: "m-hb", Seq: 2, SentAt: timestamppb.New(r.clock.Now()),
		Payload: &agentpb.AgentMessage_Heartbeat{Heartbeat: &agentpb.Heartbeat{}},
	}); err != nil {
		t.Fatalf("Send heartbeat: %v", err)
	}
	fleet, err := r.svc.Fleet(operatorCtx("acme", "op-1"), "acme", "op-1")
	if err != nil {
		t.Fatalf("Fleet: %v", err)
	}
	if len(fleet) != 1 || fleet[0].Status != api.StatusConnected {
		t.Fatalf("fleet after enrolment = %+v, want one CONNECTED row", fleet)
	}
}

// --- AC4: rotation across a certificate boundary ----------------------------------------

func TestRotationAcrossCertificateBoundary(t *testing.T) {
	r := newRig(t)
	stream, ack := r.enrolOverWire(t, r.issueSecret(t, "acme"))
	defer func() { _ = stream.CloseSend() }()
	firstID := ack.GetIssuedCertificate().GetCertificateId()
	dpID := ack.GetDataPlaneId()

	// Inside the rotation lead, the control plane delivers the next certificate on-channel.
	r.clock.advance(40 * time.Minute)
	msg, err := stream.Recv()
	if err != nil {
		t.Fatalf("Recv rotation: %v", err)
	}
	rot1 := msg.GetCertificateRotation().GetCertificate()
	if rot1 == nil || rot1.GetCertificateId() == firstID {
		t.Fatalf("first rotation = %+v, want a fresh certificate", rot1)
	}

	// The agent applies it; the registry follows.
	if err := stream.Send(&agentpb.AgentMessage{
		MessageId: "m-ack1", Seq: 2, SentAt: timestamppb.New(r.clock.Now()),
		Payload: &agentpb.AgentMessage_CertificateRotationAck{CertificateRotationAck: &agentpb.CertificateRotationAck{
			CertificateId: rot1.GetCertificateId(), Applied: true,
		}},
	}); err != nil {
		t.Fatalf("Send rotation ack: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		dp, err := r.svc.GetDataPlane(operatorCtx("acme", "op-1"), "acme", "op-1", dpID)
		if err != nil {
			t.Fatalf("GetDataPlane: %v", err)
		}
		if dp.CurrentCertificateID == rot1.GetCertificateId() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("registry certificate = %q, want %q", dp.CurrentCertificateID, rot1.GetCertificateId())
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Across the boundary: the NEXT rotation is issued off the rotated certificate.
	due := rot1.GetExpiresAt().AsTime().Add(-20 * time.Minute)
	r.clock.advance(due.Sub(r.clock.Now()))
	msg, err = stream.Recv()
	if err != nil {
		t.Fatalf("Recv second rotation: %v", err)
	}
	rot2 := msg.GetCertificateRotation().GetCertificate()
	if rot2 == nil || rot2.GetCertificateId() == rot1.GetCertificateId() || rot2.GetCertificateId() == firstID {
		t.Fatalf("second rotation = %+v, want a new certificate beyond the boundary", rot2)
	}
	if got := len(r.audits.of(platformaudit.ActionAgentCertificateRotation)); got != 1 {
		t.Fatalf("rotation audit records = %d, want exactly 1 (only the applied act)", got)
	}
}

// --- AC5: revocation refuses the next connection ----------------------------------------

func TestRevocationRefusesNextConnection(t *testing.T) {
	r := newRig(t)
	stream, ack := r.enrolOverWire(t, r.issueSecret(t, "acme"))
	_ = stream.CloseSend()
	dpID := ack.GetDataPlaneId()

	if err := r.svc.RevokeDataPlane(operatorCtx("acme", "op-1"), "acme", "op-1", dpID); err != nil {
		t.Fatalf("RevokeDataPlane: %v", err)
	}

	// The same certificate that was healthy a moment ago: refused on the next connection,
	// and the refusal is audited. Nothing in the customer's cluster is touched.
	client := r.dial(t, ack.GetIssuedCertificate().GetCertificatePem())
	refused := r.connect(t, client)
	if _, err := refused.Recv(); err == nil {
		t.Fatal("a revoked data plane must not be admitted")
	}
	if got := len(r.audits.of(platformaudit.ActionAgentConnectionRefused)); got != 1 {
		t.Fatalf("connection-refused audit records = %d, want 1", got)
	}
	if ev := r.audits.of(platformaudit.ActionAgentConnectionRefused)[0]; ev.Tenant() != "acme" {
		t.Fatalf("refusal record tenant = %q, want acme", ev.Tenant())
	}
}

// --- AC6: no degraded mode — a lapsed certificate ends the stream -----------------------

func TestNoDegradedModeLapseRefusal(t *testing.T) {
	r := newRig(t)
	stream, _ := r.enrolOverWire(t, r.issueSecret(t, "acme"))
	defer func() { _ = stream.CloseSend() }()

	// The rotation arrives; the agent never applies it.
	r.clock.advance(40 * time.Minute)
	if msg, err := stream.Recv(); err != nil || msg.GetCertificateRotation() == nil {
		t.Fatalf("expected a rotation, got %v / %v", msg, err)
	}

	// The certificate expires without an applied rotation: the stream ends — refused, never
	// extended, never degraded.
	r.clock.advance(2 * time.Hour)
	if _, err := stream.Recv(); err == nil {
		t.Fatal("a lapsed stream must be ended by the control plane")
	}
	if got := len(r.audits.of(platformaudit.ActionAgentConnectionRefused)); got == 0 {
		t.Fatal("the lapsed connection must be audited as refused")
	}
}

// --- AC9: coarse shapes and tenant isolation at the wire boundary ------------------------

func TestWireRefusalsAreCoarseAndIsolated(t *testing.T) {
	r := newRig(t)
	_, ackOK := r.enrolOverWire(t, r.issueSecret(t, "acme"))

	// An unknown token and a malformed token refuse identically (TOKEN_INVALID conflates
	// malformed/unknown/cross-tenant), and the prose never echoes what was presented.
	for _, bogus := range []string{"not-a-real-token", ""} {
		client := r.dial(t, nil)
		stream := r.connect(t, client)
		if err := stream.Send(&agentpb.AgentMessage{
			MessageId: "m-bogus", Seq: 1, SentAt: timestamppb.New(r.clock.Now()),
			Payload: &agentpb.AgentMessage_Enrol{Enrol: &agentpb.Enrol{OneTimeToken: bogus}},
		}); err != nil {
			t.Fatalf("Send: %v", err)
		}
		reply, err := stream.Recv()
		if err != nil {
			t.Fatalf("Recv refusal: %v", err)
		}
		refused := reply.GetEnrolmentAck()
		echoed := bogus != "" && strings.Contains(reply.String(), bogus)
		if refused == nil || refused.GetAccepted() ||
			refused.GetRefusalReason() != agentpb.EnrolmentRefusalReason_ENROLMENT_REFUSAL_REASON_TOKEN_INVALID ||
			echoed {
			t.Fatalf("refusal for %q = %+v, want coarse TOKEN_INVALID", bogus, reply)
		}
	}

	// Tenant beta sees nothing of acme's plane — the same shape as for a record that does
	// not exist anywhere.
	dpID := ackOK.GetDataPlaneId()
	_, errCross := r.svc.GetDataPlane(operatorCtx("beta", "op-2"), "beta", "op-2", dpID)
	_, errMissing := r.svc.GetDataPlane(operatorCtx("beta", "op-2"), "beta", "op-2", "no-such-plane")
	if !errors.Is(errCross, api.ErrNotFound) || !errors.Is(errMissing, api.ErrNotFound) || errCross.Error() != errMissing.Error() {
		t.Fatalf("cross-tenant read = %v, missing read = %v; both must be the same ErrNotFound", errCross, errMissing)
	}
	fleet, err := r.svc.Fleet(operatorCtx("beta", "op-2"), "beta", "op-2")
	if err != nil || len(fleet) != 0 {
		t.Fatalf("tenant beta fleet = %+v, err=%v; want empty", fleet, err)
	}
}
