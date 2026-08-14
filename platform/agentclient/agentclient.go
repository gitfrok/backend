package agentclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	agentpb "github.com/gitfrok/backend/gen/proto/agent/v1"
	"github.com/gitfrok/backend/platform/ids"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// FailureReason is the coarse vocabulary an agent uses to say why it could not take a rotated
// certificate — the in-process mirror of the wire's CertificateRotationFailureReason (ADR-0060).
type FailureReason = agentpb.CertificateRotationFailureReason

const (
	failureUnparsable    = agentpb.CertificateRotationFailureReason_CERTIFICATE_ROTATION_FAILURE_REASON_UNPARSABLE
	failureUntrusted     = agentpb.CertificateRotationFailureReason_CERTIFICATE_ROTATION_FAILURE_REASON_UNTRUSTED
	failurePersistFailed = agentpb.CertificateRotationFailureReason_CERTIFICATE_ROTATION_FAILURE_REASON_PERSIST_FAILED
	failureClockSkew     = agentpb.CertificateRotationFailureReason_CERTIFICATE_ROTATION_FAILURE_REASON_CLOCK_SKEW
	failureUnspecified   = agentpb.CertificateRotationFailureReason_CERTIFICATE_ROTATION_FAILURE_REASON_UNSPECIFIED
)

// RotationOutcome is the decision ApplyRotation reached for one issued certificate.
type RotationOutcome struct {
	Applied bool
	// Reason is set when !Applied; it is the coarse enum the control plane audits.
	Reason FailureReason
}

// EnrolInput is the install-time input the agent presents on its first Connect. Token is the
// one-time secret: consumed here, never stored, never logged (SPEC-0038 AC2).
type EnrolInput struct {
	Token        string
	Cloud        agentpb.Cloud
	Region       string
	AgentVersion string
	K8sVersion   string
	Capabilities []string
}

// Identity is the control plane's answer to a successful enrolment.
type Identity struct {
	TenantID          string
	DataPlaneID       string
	HeartbeatInterval time.Duration
}

// EnrolmentRefused reports a control-plane refusal of the bootstrap. Its text is the coarse
// wire detail, which never echoes the token (SPEC-0038 AC2, AC9).
type EnrolmentRefused struct {
	Reason agentpb.EnrolmentRefusalReason
	Detail string
}

func (e *EnrolmentRefused) Error() string {
	return fmt.Sprintf("agentclient: enrolment refused (%s)", e.Reason.String())
}

// DialFunc opens one AgentGateway client. It is injectable so tests can serve it an in-process
// rig; the default dials the configured address over mTLS.
type DialFunc func(ctx context.Context, clientCertPEM []byte) (agentpb.AgentGatewayClient, io.Closer, error)

// Config wires the agent client. Every value is per-environment (invariant 13): the install
// supplies the token and the driver supplies cloud/region/capabilities.
type Config struct {
	// GatewayAddr is the control-plane AgentGateway endpoint the agent dials OUTBOUND.
	GatewayAddr string
	// ServerName is the TLS name the gateway's server certificate must carry.
	ServerName string
	// Roots is the pinned trust pool: it verifies the gateway's server certificate AND the
	// client certificates the control plane issues and rotates.
	Roots *x509.CertPool
	// Store durably holds the issued credential bundle (never the token).
	Store CertStore
	// ClockSkewLeeway is the accepted skew between this cluster's clock and the control
	// plane's when judging a certificate's validity window (SPEC-0038 non-functional).
	ClockSkewLeeway time.Duration
	// HeartbeatEvery paces keep-alive heartbeats on the established stream; zero disables.
	HeartbeatEvery time.Duration
	// Now is the clock used for validity-window decisions. Injected for tests.
	Now func() time.Time
	// Logf receives coarse prose only; it is never given the token or the credential.
	Logf func(format string, args ...any)
	// Dial overrides the default mTLS dialer (tests).
	Dial DialFunc
}

// Client is the data-plane agent. One instance serves one data plane.
type Client struct {
	cfg Config

	mu       sync.Mutex // guards concurrent stream sends (heartbeat vs rotation ack)
	identity Identity
}

// New validates the configuration and returns a ready client. It refuses to build on a missing
// trust pool, store, or clock — an agent without any of those cannot connect safely.
func New(cfg Config) (*Client, error) {
	if cfg.Roots == nil {
		return nil, errors.New("agentclient: a pinned trust pool (Roots) is required")
	}
	if cfg.Store == nil {
		return nil, errors.New("agentclient: a credential store is required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	if cfg.Dial == nil {
		cfg.Dial = defaultDial(cfg)
	}
	return &Client{cfg: cfg}, nil
}

// Bootstrap runs the first-Connect enrolment handshake (ADR-0060 §1): dial out without a client
// certificate, present the one-time token, and — on acceptance — persist the issued credential.
// The token is consumed here and never appears in a log line, an error, or the store.
func (c *Client) Bootstrap(ctx context.Context, in EnrolInput) (Identity, error) {
	client, closer, err := c.cfg.Dial(ctx, nil)
	if err != nil {
		return Identity{}, fmt.Errorf("agentclient: dial for enrolment: %w", err)
	}
	defer closer.Close()

	stream, err := client.Connect(ctx)
	if err != nil {
		return Identity{}, fmt.Errorf("agentclient: open enrolment stream: %w", err)
	}

	enrol := &agentpb.Enrol{
		OneTimeToken: in.Token,
		Cloud:        in.Cloud,
		Region:       in.Region,
		AgentVersion: in.AgentVersion,
		K8SVersion:   in.K8sVersion,
		Capabilities: in.Capabilities,
	}
	msg := &agentpb.AgentMessage{
		MessageId: ids.NewULID(),
		Seq:       1,
		SentAt:    timestamppb.New(c.cfg.Now()),
		Payload:   &agentpb.AgentMessage_Enrol{Enrol: enrol},
	}
	if err := stream.Send(msg); err != nil {
		return Identity{}, fmt.Errorf("agentclient: send enrol: %w", err)
	}

	reply, err := stream.Recv()
	if err != nil {
		return Identity{}, fmt.Errorf("agentclient: await enrolment ack: %w", err)
	}
	ack := reply.GetEnrolmentAck()
	if ack == nil {
		return Identity{}, errors.New("agentclient: control plane did not answer with an enrolment ack")
	}
	if !ack.GetAccepted() {
		return Identity{}, &EnrolmentRefused{Reason: ack.GetRefusalReason(), Detail: ack.GetDetail()}
	}

	cert := ack.GetIssuedCertificate()
	if cert == nil || len(cert.GetCertificatePem()) == 0 {
		return Identity{}, errors.New("agentclient: accepted enrolment carried no certificate")
	}
	if err := c.cfg.Store.Save(ctx, cert.GetCertificatePem()); err != nil {
		return Identity{}, fmt.Errorf("agentclient: persist issued credential: %w", err)
	}
	_ = stream.CloseSend()

	id := Identity{TenantID: ack.GetTenantId(), DataPlaneID: ack.GetDataPlaneId()}
	if hb := ack.GetHeartbeatInterval(); hb != nil {
		id.HeartbeatInterval = hb.AsDuration()
	}
	c.mu.Lock()
	c.identity = id
	c.mu.Unlock()
	// Coarse only: tenant and data plane by ID. Never the token, never the credential.
	c.cfg.Logf("agentclient: enrolled as tenant=%s data-plane=%s", id.TenantID, id.DataPlaneID)
	return id, nil
}

// Connect establishes the certified channel from the stored credential and serves it: it applies
// every on-channel certificate rotation and keeps the stream alive with heartbeats until ctx ends
// or the control plane closes the stream. A data plane with no stored credential cannot connect
// (ADR-0060 §4 — there is no degraded mode).
func (c *Client) Connect(ctx context.Context) error {
	pemBundle, err := c.cfg.Store.Load(ctx)
	if err != nil {
		return fmt.Errorf("agentclient: cannot connect without a stored credential: %w", err)
	}
	client, closer, err := c.cfg.Dial(ctx, pemBundle)
	if err != nil {
		return fmt.Errorf("agentclient: dial: %w", err)
	}
	defer closer.Close()

	stream, err := client.Connect(ctx)
	if err != nil {
		return fmt.Errorf("agentclient: open stream: %w", err)
	}

	// Heartbeats keep the data plane inside the control plane's staleness window (SPEC-0038
	// AC8). They ride the same outbound stream; there is no inbound path.
	var wg sync.WaitGroup
	if c.cfg.HeartbeatEvery > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ticker := time.NewTicker(c.cfg.HeartbeatEvery)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					hb := &agentpb.AgentMessage{
						MessageId: ids.NewULID(),
						SentAt:    timestamppb.New(c.cfg.Now()),
						Payload: &agentpb.AgentMessage_Heartbeat{
							Heartbeat: &agentpb.Heartbeat{Overall: agentpb.HealthState_HEALTH_STATE_HEALTHY},
						},
					}
					c.mu.Lock()
					err := stream.Send(hb)
					c.mu.Unlock()
					if err != nil {
						return
					}
				}
			}
		}()
	}
	defer wg.Wait()

	var seq int64
	for {
		msg, err := stream.Recv()
		if err != nil {
			return err
		}
		switch p := msg.GetPayload().(type) {
		case *agentpb.ControlPlaneMessage_CertificateRotation:
			issued := p.CertificateRotation.GetCertificate()
			outcome := c.ApplyRotation(ctx, issued)
			seq++
			ack := c.rotationAck(seq, issued.GetCertificateId(), outcome)
			c.mu.Lock()
			sendErr := stream.Send(ack)
			c.mu.Unlock()
			if sendErr != nil {
				return sendErr
			}
			if outcome.Applied {
				c.cfg.Logf("agentclient: rotated to certificate %s", issued.GetCertificateId())
			} else {
				c.cfg.Logf("agentclient: refused rotation (%s)", outcome.Reason.String())
			}
		case *agentpb.ControlPlaneMessage_Ping:
			// A ping only proves the channel is live; the recv itself already refreshed
			// contact. Nothing to send back on this surface.
		default:
			// DesiredState, commands and friends belong to later specs (SPEC-0039/0041); the
			// enrolment surface ignores them.
		}
	}
}

// ApplyRotation decides whether the agent takes one issued certificate and, if so, persists it.
// The decision order maps one-to-one onto the failure enum: an undecodable bundle is UNPARSABLE,
// a validity window the local clock cannot honour is CLOCK_SKEW, a chain the pinned pool does not
// trust is UNTRUSTED, and a store that cannot durably hold it is PERSIST_FAILED.
func (c *Client) ApplyRotation(ctx context.Context, cert *agentpb.ClientCertificate) RotationOutcome {
	if cert == nil || len(cert.GetCertificatePem()) == 0 {
		return RotationOutcome{Reason: failureUnparsable}
	}
	leaf, intermediates, err := parseBundle(cert.GetCertificatePem())
	if err != nil {
		return RotationOutcome{Reason: failureUnparsable}
	}

	// Clock skew is judged before trust: a perfectly valid certificate that this cluster's
	// clock says is not yet (or no longer) usable is an operational fault, not an attack.
	now := c.cfg.Now()
	if now.Before(leaf.NotBefore.Add(-c.cfg.ClockSkewLeeway)) || !now.Before(leaf.NotAfter) {
		return RotationOutcome{Reason: failureClockSkew}
	}

	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         c.cfg.Roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return RotationOutcome{Reason: failureUntrusted}
	}

	if err := c.cfg.Store.Save(ctx, cert.GetCertificatePem()); err != nil {
		return RotationOutcome{Reason: failurePersistFailed}
	}
	return RotationOutcome{Applied: true}
}

// rotationAck builds the acknowledgement for one rotation. The certificate ID echoes the one the
// control plane issued — that correlation is how the registry knows which rotation landed.
func (c *Client) rotationAck(seq int64, certificateID string, outcome RotationOutcome) *agentpb.AgentMessage {
	ack := &agentpb.CertificateRotationAck{
		CertificateId: certificateID,
		Applied:       outcome.Applied,
	}
	if !outcome.Applied {
		ack.FailureReason = outcome.Reason
	}
	return &agentpb.AgentMessage{
		MessageId: ids.NewULID(),
		Seq:       seq,
		SentAt:    timestamppb.New(c.cfg.Now()),
		Payload:   &agentpb.AgentMessage_CertificateRotationAck{CertificateRotationAck: ack},
	}
}

// parseBundle splits a PEM credential bundle into its leaf certificate and any intermediates.
func parseBundle(bundle []byte) (*x509.Certificate, *x509.CertPool, error) {
	var leaf *x509.Certificate
	intermediates := x509.NewCertPool()
	rest := bundle
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("agentclient: unparsable certificate in bundle: %w", err)
		}
		if leaf == nil {
			leaf = cert
		} else {
			intermediates.AddCert(cert)
		}
	}
	if leaf == nil {
		return nil, nil, errors.New("agentclient: bundle contains no certificate")
	}
	return leaf, intermediates, nil
}

// defaultDial builds the outbound mTLS connection to the gateway. The client presents its stored
// credential when one is supplied; it always verifies the gateway against the pinned pool.
func defaultDial(cfg Config) DialFunc {
	return func(_ context.Context, clientCertPEM []byte) (agentpb.AgentGatewayClient, io.Closer, error) {
		tlsCfg := &tls.Config{
			RootCAs:    cfg.Roots,
			ServerName: cfg.ServerName,
			MinVersion: tls.VersionTLS12,
		}
		if len(clientCertPEM) > 0 {
			keypair, err := tls.X509KeyPair(clientCertPEM, clientCertPEM)
			if err != nil {
				return nil, nil, fmt.Errorf("agentclient: load client keypair: %w", err)
			}
			tlsCfg.Certificates = []tls.Certificate{keypair}
		}
		conn, err := grpc.NewClient(cfg.GatewayAddr,
			grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
		if err != nil {
			return nil, nil, err
		}
		return agentpb.NewAgentGatewayClient(conn), conn, nil
	}
}
