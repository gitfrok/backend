package grpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	agentpb "github.com/gitfrok/backend/gen/proto/agent/v1"
	"github.com/gitfrok/backend/modules/agent/api"
	"github.com/gitfrok/backend/modules/agent/internal/adapters/custody"
	"github.com/gitfrok/backend/modules/agent/internal/adapters/memory"
	"github.com/gitfrok/backend/modules/agent/internal/app"
	identityapi "github.com/gitfrok/backend/modules/identity/api"
	"github.com/gitfrok/backend/platform/bus"
	"github.com/gitfrok/backend/platform/tenancy"
	ggrpc "google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// The AC2 rotation test at the RECONCILE level (SPEC-0044 AC2, T-0040): the
// full control-plane composition under custody — a FakeSigner as the CI
// custody service, the custody Issuer as the app layer's CA, and the gateway
// delivering every staging step as DesiredState.ca_trust_bundle. The flow is
// the rotation procedure itself: stage a new root beside the current one,
// both validate, new issuance chains to the new root, and the old root
// leaves ONLY after every certificate it issued has expired — the removal
// precondition, honoured across a reconcile cycle.

// custodyRig is the custody-backed twin of the dev-CA rig: identical wire
// shape, custody everywhere a key would be.
type custodyRig struct {
	svc         *app.Service
	gw          *Gateway
	bundle      *custody.Bundle
	issuer      *custody.Issuer
	appClock    *fakeClock // the app layer's clock: sessions, validity windows
	bundleClock *fakeClock // the bundle's own clock: staging timestamps, the removal precondition
	addr        string
}

func newCustodyRig(t *testing.T) *custodyRig {
	t.Helper()
	// Two clocks deliberately: the app clock stays anchored so streams stay
	// healthy for the whole test, while the bundle's clock advances past the
	// old root's issued certificates to satisfy the removal precondition —
	// exactly the operator's "wait out the overlap, then remove" procedure,
	// compressed.
	now := time.Now()
	appClock := &fakeClock{t: now}
	bundleClock := &fakeClock{t: now}
	logf := func(format string, args ...any) { t.Logf("controlplane: "+format, args...) }

	fake := custody.NewFakeSigner()
	bundle, err := custody.NewBundle(fake, bundleClock.Now)
	if err != nil {
		t.Fatalf("NewBundle: %v", err)
	}
	if _, err := bundle.Bootstrap(context.Background(), "agent-ca-gen1"); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	issuer, err := custody.NewIssuer(bundle)
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}

	cfg := api.Config{
		CertLifetime:          time.Hour,
		RotationLead:          20 * time.Minute,
		RotationRetryInterval: time.Minute,
		StaleAfter:            5 * time.Minute,
		TokenMaxLifetime:      24 * time.Hour,
		HeartbeatInterval:     30 * time.Second,
		ClockSkewLeeway:       5 * time.Minute,
		Now:                   appClock.Now,
	}
	svc := app.New(allowPDP{}, bus.NewInProcess(), issuer, memory.New(), memory.New(), cfg, logf)

	// The server certificate is minted through the SAME custody seam the
	// identities use — the composition-root swap changes neither door's TLS
	// shape. Wall-clock dated: the TLS layer verifies with real time.
	serverCert, err := issuer.IssueServer("agent-gateway", []string{"localhost"}, time.Now(), 24*time.Hour)
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
	gw := NewGateway(svc, 2*time.Millisecond, appClock.Now, logf)
	// The reconcile wiring under test: the bundle IS the distribution source.
	gw.AttachCATrustBundle(bundle)
	agentpb.RegisterAgentGatewayServer(server, gw)
	go func() { _ = server.Serve(lis) }()
	t.Cleanup(server.Stop)

	return &custodyRig{
		svc: svc, gw: gw, bundle: bundle, issuer: issuer,
		appClock: appClock, bundleClock: bundleClock,
		addr: "localhost" + lis.Addr().String()[strings.LastIndex(lis.Addr().String(), ":"):],
	}
}

// dial opens one token-bootstrap connection verifying the server against the
// bundle's live roots.
func (r *custodyRig) dial(t *testing.T) agentpb.AgentGatewayClient {
	t.Helper()
	pool, err := r.issuer.CAPool()
	if err != nil {
		t.Fatalf("CAPool: %v", err)
	}
	cfg := &tls.Config{RootCAs: pool, ServerName: "localhost"}
	conn, err := ggrpc.NewClient(r.addr, ggrpc.WithTransportCredentials(credentials.NewTLS(cfg)))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return agentpb.NewAgentGatewayClient(conn)
}

// issueSecret mints one enrolment token through the operator surface.
func (r *custodyRig) issueSecret(t *testing.T, tenant string) string {
	t.Helper()
	ctx := tenancy.WithTenant(context.Background(), tenancy.ID(tenant))
	ctx = identityapi.WithPrincipal(ctx, identityapi.Principal{TenantID: tenant, ActorID: "op-1", Roles: []string{"owner"}})
	_, secret, err := r.svc.IssueEnrolmentToken(ctx, tenant, "op-1", time.Hour)
	if err != nil {
		t.Fatalf("IssueEnrolmentToken: %v", err)
	}
	return secret
}

// enrolWire performs the full first-Connect handshake and returns the
// stream, the accepted ack, and the stream context's cancel function.
func (r *custodyRig) enrolWire(t *testing.T, client agentpb.AgentGatewayClient, secret string) (agentpb.AgentGateway_ConnectClient, *agentpb.EnrolmentAck, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	stream, err := client.Connect(ctx)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	msg := &agentpb.AgentMessage{
		MessageId: "m-enrol", Seq: 1, SentAt: timestamppb.New(r.appClock.Now()),
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
	return stream, ack, cancel
}

// recvDesiredState reads the stream until one DesiredState carrying the CA
// trust bundle arrives, skipping anything else. wantRev bounds the wait: the
// test names the revision it expects next.
func recvDesiredState(t *testing.T, stream agentpb.AgentGateway_ConnectClient) *agentpb.DesiredState {
	t.Helper()
	for {
		reply, err := stream.Recv()
		if err != nil {
			t.Fatalf("Recv desired state: %v", err)
		}
		if ds := reply.GetDesiredState(); ds != nil && ds.GetCaTrustBundle() != nil {
			return ds
		}
	}
}

// expectNoBundleDelivery asserts the stream stays quiet for d: a REFUSED
// staging step must not distribute anything. The reader's Recv ends when
// cancel closes the stream's context, so no lingering reader can consume a
// later delivery.
func expectNoBundleDelivery(t *testing.T, stream agentpb.AgentGateway_ConnectClient, cancel context.CancelFunc, d time.Duration) {
	t.Helper()
	type outcome struct{ bundle *agentpb.CATrustBundle }
	out := make(chan outcome, 1)
	go func() {
		for {
			reply, err := stream.Recv()
			if err != nil {
				out <- outcome{}
				return
			}
			if ds := reply.GetDesiredState(); ds != nil && ds.GetCaTrustBundle() != nil {
				out <- outcome{bundle: ds.GetCaTrustBundle()}
				return
			}
		}
	}()
	select {
	case o := <-out:
		if o.bundle != nil {
			t.Fatalf("unexpected CA trust bundle delivery after a refused staging step: %+v", o.bundle)
		}
	case <-time.After(d):
		// The window stayed quiet; end the stream so the reader returns.
		cancel()
		<-out
	}
}

// firstLeaf parses the first CERTIFICATE block of one issued PEM bundle.
func firstLeaf(t *testing.T, pemBundle []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(pemBundle)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("issued bundle carries no certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse issued leaf: %v", err)
	}
	return cert
}

func TestAC2_CARotationDistributedOverReconcile(t *testing.T) {
	r := newCustodyRig(t)

	// One data plane enrols under the bootstrapped root.
	stream1, ack1, cancel1 := r.enrolWire(t, r.dial(t), r.issueSecret(t, "acme"))
	defer func() { cancel1(); _ = stream1.CloseSend() }()
	gen1Leaf := firstLeaf(t, ack1.GetIssuedCertificate().GetCertificatePem())
	if gen1Leaf.Issuer.CommonName != "agent-ca-gen1" {
		t.Fatalf("first certificate chains to %q, want agent-ca-gen1", gen1Leaf.Issuer.CommonName)
	}

	// The reconcile channel states the bootstrapped bundle.
	ds := recvDesiredState(t, stream1)
	b := ds.GetCaTrustBundle()
	if ds.GetGeneration() != r.bundle.StagingRevision() || b.GetRevision() != r.bundle.StagingRevision() {
		t.Fatalf("generation/revision = %d/%d, want staging revision %d", ds.GetGeneration(), b.GetRevision(), r.bundle.StagingRevision())
	}
	if len(b.GetTrustedRoots()) != 1 || b.GetTrustedRoots()[0].GetRootId() != "agent-ca-gen1" || b.GetIssuanceRootId() != "agent-ca-gen1" {
		t.Fatalf("bootstrapped bundle on the wire = %+v", b)
	}

	// STAGE: a new root joins beside the current one — the dual-validate
	// window opens, and the channel distributes it: two trusted roots, new
	// issuance chained to the new one.
	gen2, err := r.bundle.Stage(context.Background(), "agent-ca-gen2")
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	ds = recvDesiredState(t, stream1)
	b = ds.GetCaTrustBundle()
	if len(b.GetTrustedRoots()) != 2 {
		t.Fatalf("overlap bundle = %+v, want both roots trusted", b)
	}
	if b.GetTrustedRoots()[0].GetRootId() != "agent-ca-gen1" || b.GetTrustedRoots()[1].GetRootId() != string(gen2) {
		t.Fatalf("overlap roots = %+v, want [agent-ca-gen1 agent-ca-gen2] oldest-first", b.GetTrustedRoots())
	}
	if b.GetIssuanceRootId() != string(gen2) {
		t.Fatalf("issuance root during overlap = %q, want %q", b.GetIssuanceRootId(), gen2)
	}
	for _, root := range b.GetTrustedRoots() {
		if len(root.GetCertificatePem()) == 0 || root.GetNotAfter() == nil {
			t.Fatalf("distributed root %q lacks certificate or expiry", root.GetRootId())
		}
	}

	// New issuance chains to the NEW root while the old one still validates,
	// and the joiner's stream receives the overlap state as its first one.
	stream2, ack2, cancel2 := r.enrolWire(t, r.dial(t), r.issueSecret(t, "acme"))
	defer func() { cancel2(); _ = stream2.CloseSend() }()
	gen2Leaf := firstLeaf(t, ack2.GetIssuedCertificate().GetCertificatePem())
	if gen2Leaf.Issuer.CommonName != "agent-ca-gen2" {
		t.Fatalf("new issuance chains to %q, want agent-ca-gen2", gen2Leaf.Issuer.CommonName)
	}
	ds2 := recvDesiredState(t, stream2)
	if got := ds2.GetCaTrustBundle().GetIssuanceRootId(); got != string(gen2) {
		t.Fatalf("joiner's first bundle state issuance root = %q, want %q", got, gen2)
	}

	// PREMATURE REMOVAL is refused — the first plane's certificate still
	// chains to gen1 — the revision is untouched, and nothing distributes.
	revBefore := r.bundle.StagingRevision()
	if err := r.bundle.RemoveRoot("agent-ca-gen1"); !errors.Is(err, custody.ErrRootStillNeeded) {
		t.Fatalf("premature removal = %v, want ErrRootStillNeeded", err)
	}
	if got := r.bundle.StagingRevision(); got != revBefore {
		t.Fatalf("refused removal moved the staging revision %d -> %d", revBefore, got)
	}
	// The quiet window ends stream1 by design; the fleet's progression from
	// here is observed on stream2.
	expectNoBundleDelivery(t, stream1, cancel1, 150*time.Millisecond)

	// The overlap plays out: the bundle's clock moves past every certificate
	// gen1 issued, and the removal lands — the channel distributes the
	// converged bundle: one trusted root, same issuance root.
	r.bundleClock.advance(2 * time.Hour)
	if err := r.bundle.RemoveRoot("agent-ca-gen1"); err != nil {
		t.Fatalf("removal after the overlap: %v", err)
	}
	ds = recvDesiredState(t, stream2)
	b = ds.GetCaTrustBundle()
	if len(b.GetTrustedRoots()) != 1 || b.GetTrustedRoots()[0].GetRootId() != string(gen2) || b.GetIssuanceRootId() != string(gen2) {
		t.Fatalf("converged bundle on the wire = %+v", b)
	}
	if ds.GetGeneration() != r.bundle.StagingRevision() {
		t.Fatalf("converged generation = %d, want %d", ds.GetGeneration(), r.bundle.StagingRevision())
	}
}
