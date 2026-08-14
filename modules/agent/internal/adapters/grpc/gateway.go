// Package grpc is the Agent context's wire adapter: the AgentGateway.Connect half of the
// data-plane channel (ADR-0017 single outbound bidi stream, ADR-0060 enrolment identity).
// It translates between the proto messages and the app layer's Gateway port; every decision
// and every audit record stays behind that port.
//
// Admission discipline: the TLS layer CARRIES the client certificate (RequestClientCert) but
// does not verify it — verification, expiry, registration and revocation are the app layer's
// AdmitPeerCertificates decision, because every refusal it makes must be audited (SPEC-0038
// AC5, AC7). A TLS-layer rejection would refuse without a record.
package grpc

import (
	"context"
	"errors"
	"strings"
	"time"

	agentpb "github.com/gitfrok/backend/gen/proto/agent/v1"
	"github.com/gitfrok/backend/modules/agent/api"
	"github.com/gitfrok/backend/platform/ids"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Gateway implements agentpb.AgentGatewayServer on top of the app layer's api.Gateway.
type Gateway struct {
	agentpb.UnimplementedAgentGatewayServer

	gw   api.Gateway
	poll time.Duration        // rotation-lapse polling cadence
	now  func() time.Time     // the same clock the app layer decides with
	logf func(string, ...any) // coarse prose only; never credentials (AC2)
}

var _ agentpb.AgentGatewayServer = (*Gateway)(nil)

// NewGateway wires the adapter. poll bounds how late a lapsed certificate can go unnoticed;
// one second is ample for hour-long certificates (invariant 13: per-environment).
func NewGateway(gw api.Gateway, poll time.Duration, now func() time.Time, logf func(format string, args ...any)) *Gateway {
	if gw == nil || now == nil || logf == nil {
		panic("agent grpc: gateway, clock and logger are all required")
	}
	if poll <= 0 {
		poll = time.Second
	}
	return &Gateway{gw: gw, poll: poll, now: now, logf: logf}
}

// Connect is the single outbound stream an agent keeps open (ADR-0017). Its first half is
// the identity handshake: either the connection already carries a control-plane certificate
// (admission), or the very first message is an Enrol with the one-time token (bootstrap).
// After either path succeeds, the stream serves certificate rotation and contact until the
// control plane ends it — there is no degraded mode (SPEC-0038 AC6).
func (g *Gateway) Connect(stream grpc.BidiStreamingServer[agentpb.AgentMessage, agentpb.ControlPlaneMessage]) error {
	ctx := stream.Context()

	if raw := peerCertificates(ctx); len(raw) > 0 {
		id, err := g.gw.AdmitPeerCertificates(ctx, raw)
		if err != nil {
			// AdmitPeerCertificates audited the refusal; the wire answer is one coarse shape.
			g.logf("agent: connection refused")
			return status.Error(codes.PermissionDenied, "connection refused")
		}
		ss, err := g.gw.OpenStream(ctx, id)
		if err != nil {
			return status.Error(codes.Internal, "connection refused")
		}
		defer ss.Close(ctx)
		return g.serve(ctx, stream, ss)
	}

	// No certificate: this must be the very first Connect, bootstrapped by the token.
	msg, err := stream.Recv()
	if err != nil {
		return err
	}
	enrol := msg.GetEnrol()
	if enrol == nil {
		return status.Error(codes.InvalidArgument, "an uncertified connection must begin with enrol")
	}
	e, err := g.gw.Enrol(ctx, api.EnrolRequest{
		Token:        enrol.GetOneTimeToken(),
		Cloud:        enrol.GetCloud().String(),
		Region:       enrol.GetRegion(),
		AgentVersion: enrol.GetAgentVersion(),
		K8sVersion:   enrol.GetK8SVersion(),
		Capabilities: enrol.GetCapabilities(),
	})
	if err != nil {
		var refused *api.EnrolmentRefused
		if !errors.As(err, &refused) {
			g.logf("agent: enrolment failed: %v", err)
			return status.Error(codes.Internal, "enrolment failed")
		}
		// Refused: one coarse EnrolmentAck, then the stream ends. The message never names
		// the token or the cause more finely than the enum (AC2, AC9).
		ack := &agentpb.EnrolmentAck{Accepted: false, RefusalReason: wireReason(refused.Reason), Detail: refusalDetail(refused.Reason)}
		msg := controlPlaneMessage(0, 1, g.now())
		msg.Payload = &agentpb.ControlPlaneMessage_EnrolmentAck{EnrolmentAck: ack}
		if sendErr := stream.Send(msg); sendErr != nil {
			return sendErr
		}
		return nil
	}

	ss, err := g.gw.OpenStream(ctx, e.Identity)
	if err != nil {
		return status.Error(codes.Internal, "enrolment failed")
	}
	defer ss.Close(ctx)
	ack := &agentpb.EnrolmentAck{
		Accepted:          true,
		IssuedCertificate: clientCertificate(e.Certificate),
		TenantId:          e.TenantID,
		DataPlaneId:       e.DataPlaneID,
		HeartbeatInterval: durationpb.New(e.HeartbeatInterval),
	}
	ackMsg := controlPlaneMessage(0, 1, g.now())
	ackMsg.Payload = &agentpb.ControlPlaneMessage_EnrolmentAck{EnrolmentAck: ack}
	if err := stream.Send(ackMsg); err != nil {
		return err
	}
	return g.serve(ctx, stream, ss)
}

// serve runs the established stream: rotation delivery, ack intake, contact, and the hard
// end on lapse or revocation. It returns when the stream must close.
func (g *Gateway) serve(ctx context.Context, stream grpc.BidiStreamingServer[agentpb.AgentMessage, agentpb.ControlPlaneMessage], ss api.StreamSession) error {
	in := make(chan *agentpb.AgentMessage, 16)
	recvErr := make(chan error, 1)
	go func() {
		for {
			msg, err := stream.Recv()
			if err != nil {
				recvErr <- err
				return
			}
			select {
			case in <- msg:
			case <-ctx.Done():
				return
			}
		}
	}()

	ticker := time.NewTicker(g.poll)
	defer ticker.Stop()
	var seq, ackSeq int64
	send := func(msg *agentpb.ControlPlaneMessage) error {
		seq++
		msg.MessageId = ids.NewULID()
		msg.Seq = seq
		msg.SentAt = timestamppb.New(g.now())
		msg.AckSeq = ackSeq
		return stream.Send(msg)
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ss.Done():
			// The control plane ended this stream itself — revocation landing on a live
			// session (AC5). There is no continuation.
			return status.Error(codes.PermissionDenied, "connection ended by control plane")
		case err := <-recvErr:
			return err
		case msg := <-in:
			ackSeq = msg.GetSeq()
			switch p := msg.GetPayload().(type) {
			case *agentpb.AgentMessage_Heartbeat:
				ss.Touch(ctx)
			case *agentpb.AgentMessage_CertificateRotationAck:
				ack := p.CertificateRotationAck
				reason := strings.TrimPrefix(ack.GetFailureReason().String(), "CERTIFICATE_ROTATION_FAILURE_REASON_")
				if err := ss.AckRotation(ctx, ack.GetCertificateId(), ack.GetApplied(), reason); err != nil {
					return status.Error(codes.Internal, "rotation acknowledgement failed")
				}
			default:
				// State, telemetry, usage and friends ride this same stream but belong to
				// later specs (SPEC-0039/0041); the enrolment surface ignores them.
			}
		case <-ticker.C:
			now := g.now()
			if ss.Lapsed(now) {
				_ = g.gw.RefusedLapsed(ctx, ss.Identity())
				return status.Error(codes.PermissionDenied, "certificate lapsed without rotation")
			}
			if now.Before(ss.RotationDueAt()) {
				continue
			}
			cert, err := ss.Rotate(ctx)
			if err != nil {
				if errors.Is(err, api.ErrNotFound) {
					_ = g.gw.RefusedLapsed(ctx, ss.Identity())
					return status.Error(codes.PermissionDenied, "certificate lapsed without rotation")
				}
				g.logf("agent: rotation issuance failed; retrying")
				continue
			}
			rotation := &agentpb.ControlPlaneMessage_CertificateRotation{
				CertificateRotation: &agentpb.CertificateRotation{Certificate: clientCertificate(cert)},
			}
			if err := send(&agentpb.ControlPlaneMessage{Payload: rotation}); err != nil {
				return err
			}
		}
	}
}

// controlPlaneMessage stamps one outbound message: ID, monotonic seq, send time, and the
// highest agent seq processed so far.
func controlPlaneMessage(ackSeq, seq int64, at time.Time) *agentpb.ControlPlaneMessage {
	return &agentpb.ControlPlaneMessage{
		MessageId: ids.NewULID(),
		Seq:       seq,
		SentAt:    timestamppb.New(at),
		AckSeq:    ackSeq,
	}
}

func clientCertificate(c api.IssuedCertificate) *agentpb.ClientCertificate {
	return &agentpb.ClientCertificate{
		CertificateId:  c.CertificateID,
		CertificatePem: c.PEM,
		ExpiresAt:      timestamppb.New(c.ExpiresAt),
	}
}

// peerCertificates surfaces the client chain the TLS layer carried, leaf first.
func peerCertificates(ctx context.Context) [][]byte {
	p, ok := peer.FromContext(ctx)
	if !ok || p == nil || p.AuthInfo == nil {
		return nil
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil
	}
	var raw [][]byte
	for _, c := range tlsInfo.State.PeerCertificates {
		raw = append(raw, c.Raw)
	}
	return raw
}

// wireReason maps the app layer's coarse vocabulary onto the contract enum.
func wireReason(r api.RefusalReason) agentpb.EnrolmentRefusalReason {
	switch r {
	case api.RefusalTokenSpent:
		return agentpb.EnrolmentRefusalReason_ENROLMENT_REFUSAL_REASON_TOKEN_SPENT
	case api.RefusalTokenExpired:
		return agentpb.EnrolmentRefusalReason_ENROLMENT_REFUSAL_REASON_TOKEN_EXPIRED
	case api.RefusalTokenRevoked:
		return agentpb.EnrolmentRefusalReason_ENROLMENT_REFUSAL_REASON_TOKEN_REVOKED
	case api.RefusalDenied:
		return agentpb.EnrolmentRefusalReason_ENROLMENT_REFUSAL_REASON_DENIED
	default:
		return agentpb.EnrolmentRefusalReason_ENROLMENT_REFUSAL_REASON_TOKEN_INVALID
	}
}

// refusalDetail is coarse prose for the wire's detail field. It never echoes the token and
// never names a cause more finely than the enum (AC2, AC9).
func refusalDetail(r api.RefusalReason) string {
	switch r {
	case api.RefusalTokenSpent:
		return "enrolment refused: the token has already been used"
	case api.RefusalTokenExpired:
		return "enrolment refused: the token has expired"
	case api.RefusalTokenRevoked:
		return "enrolment refused: the token was revoked"
	case api.RefusalDenied:
		return "enrolment refused by the control plane"
	default:
		return "enrolment refused: the token is not valid"
	}
}
