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
	"fmt"
	"strings"
	"time"

	agentpb "github.com/gitfrok/backend/gen/proto/agent/v1"
	"github.com/gitfrok/backend/modules/agent/api"
	meteringapi "github.com/gitfrok/backend/modules/metering/api"
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

	// Metering seams, attached post-construction by the composition root
	// (T-0034, SPEC-0041). Both are optional: a surface without them still
	// serves enrolment, rotation and contact. Telemetry and usage received on
	// the stream are forwarded to the sink; the newest envelope desired state
	// is delivered to the stream and its ack recorded (AC9). The gateway
	// cannot tell what counts on the other side (invariant 14).
	sink      meteringapi.Sink
	envelopes meteringapi.EnvelopeDelivery

	// caBundles is the custody rotation seam (T-0040, SPEC-0044 AC2):
	// attached post-construction by the composition root, it is the source
	// the stream polls for the newest staged CA trust bundle, delivered as
	// DesiredState.ca_trust_bundle on the reconcile channel. Optional: a
	// surface without it still serves enrolment, rotation and contact.
	caBundles api.CATrustBundleSource

	// releaseBundles is the release-trust rotation seam (T-0041, SPEC-0045
	// AC2): attached post-construction by the composition root, it is the
	// source the stream polls for the newest staged RELEASE trust bundle —
	// the cosign release-signing keys of ADR-0044/ADR-0065 — delivered as
	// DesiredState.release_trust_bundle on the reconcile channel. A
	// different artifact from caBundles, on its own field with its own
	// type. Optional, like caBundles.
	releaseBundles api.ReleaseTrustBundleSource

	// releaseApplied records the release trust bundle revision each data
	// plane acknowledges — the distribution registry keyed by data_plane_id
	// (ADR-0065, SPEC-0045 AC2). Optional: a surface without it still
	// distributes; it just does not record convergence.
	releaseApplied api.ReleaseTrustAppliedRegistry
}

var _ agentpb.AgentGatewayServer = (*Gateway)(nil)

// AttachTelemetrySink wires the metering ingestion seam every TelemetrySample and
// UsageSample received on an established stream is forwarded to.
func (g *Gateway) AttachTelemetrySink(s meteringapi.Sink) { g.sink = s }

// AttachEnvelopeDelivery wires the metering seam the stream polls for the newest
// envelope desired state and reports acknowledgements back to (SPEC-0041 AC9).
func (g *Gateway) AttachEnvelopeDelivery(e meteringapi.EnvelopeDelivery) { g.envelopes = e }

// AttachCATrustBundle wires the custody rotation seam the stream polls for the
// newest staged CA trust bundle (SPEC-0044 AC2). Each advance of the bundle
// revision is delivered as one DesiredState carrying ca_trust_bundle; the
// fleet dual-validates against trusted_roots while new issuance chains to
// issuance_root_id.
func (g *Gateway) AttachCATrustBundle(s api.CATrustBundleSource) { g.caBundles = s }

// AttachReleaseTrustBundle wires the release-trust rotation seam the stream
// polls for the newest staged RELEASE trust bundle (SPEC-0045 AC2). Each
// advance of the bundle revision is delivered as one DesiredState carrying
// release_trust_bundle; the fleet dual-validates signatures against
// trusted_keys while new releases sign with signing_key_id. This is the
// cosign release-signing bundle of ADR-0044/ADR-0065 — a different artifact
// from the CA trust bundle AttachCATrustBundle delivers, on its own field.
func (g *Gateway) AttachReleaseTrustBundle(s api.ReleaseTrustBundleSource) { g.releaseBundles = s }

// AttachReleaseTrustApplied wires the registry the stream records each
// plane's release-bundle acknowledgement into, keyed by data_plane_id
// (ADR-0065, SPEC-0045 AC2).
func (g *Gateway) AttachReleaseTrustApplied(r api.ReleaseTrustAppliedRegistry) { g.releaseApplied = r }

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
	var lastEnvelopeGen int64      // newest EnvelopeStateUpdate this stream delivered (AC9)
	var lastCABundleRev int64      // newest CA trust bundle revision this stream delivered (SPEC-0044 AC2)
	var lastReleaseBundleRev int64 // newest RELEASE trust bundle revision this stream delivered (SPEC-0045 AC2)
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
			id := ss.Identity()
			switch p := msg.GetPayload().(type) {
			case *agentpb.AgentMessage_Heartbeat:
				ss.Touch(ctx)
			case *agentpb.AgentMessage_CertificateRotationAck:
				ack := p.CertificateRotationAck
				reason := strings.TrimPrefix(ack.GetFailureReason().String(), "CERTIFICATE_ROTATION_FAILURE_REASON_")
				if err := ss.AckRotation(ctx, ack.GetCertificateId(), ack.GetApplied(), reason); err != nil {
					return status.Error(codes.Internal, "rotation acknowledgement failed")
				}
			case *agentpb.AgentMessage_Telemetry:
				// Metering counts from what it RECEIVES (ADR-0061 §1): every
				// sample the channel delivers is forwarded under the stream's
				// own identity. A refusal is logged, never traded against the
				// stream — metering must not degrade the channel that carries
				// it, and git must never depend on it (SPEC-0041 AC7).
				if g.sink != nil {
					t := telemetryOf(msg.GetMessageId(), msg.GetSeq(), p.Telemetry)
					if err := g.sink.IngestTelemetry(ctx, id.TenantID, id.DataPlaneID, t); err != nil {
						g.logf("agent: telemetry ingest refused: %v", err)
					}
				}
			case *agentpb.AgentMessage_Usage:
				// The data plane's OWN totals: operational input, never a
				// counter input (ADR-0061 §2). Forwarded the same way.
				if g.sink != nil {
					u := usageOf(msg.GetMessageId(), msg.GetSeq(), p.Usage)
					if err := g.sink.IngestUsage(ctx, id.TenantID, id.DataPlaneID, u); err != nil {
						g.logf("agent: usage ingest refused: %v", err)
					}
				}
			case *agentpb.AgentMessage_EnvelopeStateAck:
				ack := p.EnvelopeStateAck
				if g.envelopes != nil {
					if err := g.envelopes.AckDesiredState(ctx, id.TenantID, ack.GetGeneration(), ack.GetApplied(), ack.GetError()); err != nil {
						g.logf("agent: envelope ack recording failed: %v", err)
					}
				}
			case *agentpb.AgentMessage_DesiredStateAck:
				// A plane's acknowledgement of a delivered desired state. The
				// release trust bundle's applied revision is recorded per
				// data plane — the registry keyed by data_plane_id (SPEC-0045
				// AC2) — and ONLY for an ack the payload-kind discriminator
				// identifies as answering the RELEASE trust bundle: the CA
				// bundle and the release bundle deliver on INDEPENDENT
				// revision spaces (both start at 1), so an unattributed
				// generation recorded here would pollute the registry through
				// its forward-only GREATEST upsert, uncorrectably. An ack of
				// UNSPECIFIED kind comes from a plane predating the
				// discriminator and is attributed to NO registry — attribution
				// never widens on ambiguity. Recording a refusal is logged,
				// never traded against the stream.
				ack := p.DesiredStateAck
				switch ack.GetKind() {
				case agentpb.DesiredStateKind_DESIRED_STATE_KIND_RELEASE_TRUST_BUNDLE:
					if g.releaseApplied != nil && ack.GetApplied() {
						if err := g.releaseApplied.RecordReleaseTrustApplied(ctx, id.TenantID, id.DataPlaneID, ack.GetGeneration()); err != nil {
							g.logf("agent: release trust applied-revision recording failed: %v", err)
						}
					}
				case agentpb.DesiredStateKind_DESIRED_STATE_KIND_CA_TRUST_BUNDLE:
					// The CA bundle's applied state rides its own surface
					// (SPEC-0044); it is never recorded into the release
					// registry — the two bundles never share a ledger.
				default:
					// UNSPECIFIED: a plane predating the discriminator. Its
					// generation cannot be attributed, so it is recorded
					// nowhere; the ack itself stays observational.
					g.logf("agent: desired-state ack without a payload kind is attributed to no registry")
				}
			default:
				// Remaining state messages ride this same stream but belong to
				// later specs; the enrolment surface ignores them.
			}
		case <-ticker.C:
			now := g.now()
			if ss.Lapsed(now) {
				_ = g.gw.RefusedLapsed(ctx, ss.Identity())
				return status.Error(codes.PermissionDenied, "certificate lapsed without rotation")
			}
			// Envelope delivery (SPEC-0041 AC9): when a newer evaluation
			// exists for this tenant, state it on the stream; the data plane
			// applies it and acks. The control plane never reaches in.
			if g.envelopes != nil {
				tenant := ss.Identity().TenantID
				if d, ok, err := g.envelopes.LatestDesiredState(ctx, tenant); err == nil && ok && d.Generation > lastEnvelopeGen {
					update := envelopeUpdate(d)
					if err := send(&agentpb.ControlPlaneMessage{Payload: &agentpb.ControlPlaneMessage_EnvelopeState{EnvelopeState: update}}); err != nil {
						return err
					}
					lastEnvelopeGen = d.Generation
				}
			}
			// CA trust bundle distribution (SPEC-0044 AC2): when the custody
			// bundle has advanced — a staged root, a completed removal — state
			// the newest revision on the stream as desired state. Generation
			// tracks the bundle revision: it is the only desired-state source
			// this surface publishes today; a later composition of several
			// sources must generalize it.
			if g.caBundles != nil {
				if st, ok, err := g.caBundles.LatestCATrustBundle(ctx); err == nil && ok && st.Revision > lastCABundleRev {
					msg := &agentpb.ControlPlaneMessage{Payload: &agentpb.ControlPlaneMessage_DesiredState{
						DesiredState: &agentpb.DesiredState{
							Generation:    st.Revision,
							CaTrustBundle: caTrustBundleWire(st),
						},
					}}
					if err := send(msg); err != nil {
						return err
					}
					lastCABundleRev = st.Revision
				}
			}
			// Release trust bundle distribution (SPEC-0045 AC2): when the
			// staged release bundle has advanced — a staged key, a completed
			// removal — state the newest revision on the stream as desired
			// state, on its OWN field: the release trust bundle of
			// ADR-0044/ADR-0065 never rides the CA bundle's field or type.
			if g.releaseBundles != nil {
				if st, ok, err := g.releaseBundles.LatestReleaseTrustBundle(ctx); err == nil && ok && st.Revision > lastReleaseBundleRev {
					msg := &agentpb.ControlPlaneMessage{Payload: &agentpb.ControlPlaneMessage_DesiredState{
						DesiredState: &agentpb.DesiredState{
							Generation:         st.Revision,
							ReleaseTrustBundle: releaseTrustBundleWire(st),
						},
					}}
					if err := send(msg); err != nil {
						return err
					}
					lastReleaseBundleRev = st.Revision
				}
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

// telemetryOf maps one contract TelemetrySample onto the metering surface. The dedup key
// is the envelope's stamped message ID; an unstamped message falls back to the stream's
// seq so ingest keeps an idempotency key either way (SPEC-0041 non-functional).
func telemetryOf(messageID string, seq int64, ts *agentpb.TelemetrySample) meteringapi.Telemetry {
	if messageID == "" {
		messageID = fmt.Sprintf("agent-msg-%d", seq)
	}
	return meteringapi.Telemetry{
		MessageID: messageID,
		Window:    intervalOf(ts.GetWindowStart(), ts.GetWindowEnd()),
		Gauges:    ts.GetGauges(),
		Counters:  ts.GetCounters(),
	}
}

// usageOf maps one contract UsageSample onto the metering surface.
func usageOf(messageID string, seq int64, us *agentpb.UsageSample) meteringapi.Usage {
	if messageID == "" {
		messageID = fmt.Sprintf("agent-msg-%d", seq)
	}
	return meteringapi.Usage{
		MessageID:         messageID,
		Window:            intervalOf(us.GetWindowStart(), us.GetWindowEnd()),
		CIMinutes:         us.GetCiMinutes(),
		StorageBytes:      us.GetStorageBytes(),
		EgressBytes:       us.GetEgressBytes(),
		SeatCount:         us.GetSeatCount(),
		CIConcurrencyPeak: us.GetCiConcurrencyPeak(),
		ScanBytes:         us.GetScanBytes(),
		RepositoryCount:   us.GetRepositoryCount(),
		IndexBytes:        us.GetIndexBytes(),
	}
}

func intervalOf(start, end *timestamppb.Timestamp) meteringapi.Interval {
	var iv meteringapi.Interval
	if start != nil {
		iv.Start = start.AsTime()
	}
	if end != nil {
		iv.End = end.AsTime()
	}
	return iv
}

// envelopeUpdate maps the metering context's evaluation onto the contract's desired
// state: every decision cites the counter and the interval it was made from (G6).
func envelopeUpdate(d meteringapi.EnvelopeDesiredState) *agentpb.EnvelopeStateUpdate {
	out := &agentpb.EnvelopeStateUpdate{
		Generation:       d.Generation,
		MaxCiConcurrency: d.MaxCIConcurrency,
		QueueDepthCap:    d.QueueDepthCap,
	}
	for _, dec := range d.Decisions {
		out.Dimensions = append(out.Dimensions, &agentpb.DimensionEnvelope{
			Dimension:         wireDimension(dec.Dimension),
			State:             wireEnvelopeState(dec.State),
			CurrentValue:      dec.Value,
			EnvelopeValue:     dec.Threshold.Envelope,
			NotificationValue: dec.Threshold.Notify,
			Unit:              dec.Dimension.Unit(),
			WindowStart:       timestamppb.New(dec.Window.Start),
			WindowEnd:         timestamppb.New(dec.Window.End),
		})
	}
	return out
}

// caTrustBundleWire maps the custody bundle's projection onto the contract's
// CATrustBundle (agent/v1, SPEC-0044 AC2): revision, trusted roots as PEM
// with their own expiry, and the root new issuance chains to. Public trust
// data only — no credential and no private half exists to carry.
func caTrustBundleWire(st api.CATrustBundleState) *agentpb.CATrustBundle {
	out := &agentpb.CATrustBundle{
		Revision:       st.Revision,
		IssuanceRootId: st.IssuanceRootID,
	}
	for _, r := range st.Roots {
		out.TrustedRoots = append(out.TrustedRoots, &agentpb.CATrustRoot{
			RootId:         r.ID,
			CertificatePem: r.CertificatePEM,
			NotAfter:       timestamppb.New(r.NotAfter),
		})
	}
	return out
}

// releaseTrustBundleWire maps the staged release bundle's projection onto the
// contract's ReleaseTrustBundle (agent/v1, SPEC-0045 AC2): revision, trusted
// keys as PEM, and the key new releases sign with. Public trust data only —
// no signing private key exists in this process to carry. A different wire
// type from caTrustBundleWire, exactly as the two bundles are different
// artifacts.
func releaseTrustBundleWire(st api.ReleaseTrustBundleState) *agentpb.ReleaseTrustBundle {
	out := &agentpb.ReleaseTrustBundle{
		Revision:     st.Revision,
		SigningKeyId: st.SigningKeyID,
	}
	for _, k := range st.Keys {
		out.TrustedKeys = append(out.TrustedKeys, &agentpb.ReleaseTrustKey{
			KeyId:        k.ID,
			PublicKeyPem: k.PublicKeyPEM,
		})
	}
	return out
}

func wireDimension(d meteringapi.Dimension) agentpb.FairUseDimension {
	switch d {
	case meteringapi.DimensionSeats:
		return agentpb.FairUseDimension_FAIR_USE_DIMENSION_SEATS
	case meteringapi.DimensionRepositoryCount:
		return agentpb.FairUseDimension_FAIR_USE_DIMENSION_REPOSITORY_COUNT
	case meteringapi.DimensionRepositoryStorage:
		return agentpb.FairUseDimension_FAIR_USE_DIMENSION_REPOSITORY_STORAGE
	case meteringapi.DimensionCIMinutes:
		return agentpb.FairUseDimension_FAIR_USE_DIMENSION_CI_MINUTES
	case meteringapi.DimensionCIConcurrency:
		return agentpb.FairUseDimension_FAIR_USE_DIMENSION_CI_CONCURRENCY
	case meteringapi.DimensionScanVolume:
		return agentpb.FairUseDimension_FAIR_USE_DIMENSION_SCAN_VOLUME
	case meteringapi.DimensionIndexSize:
		return agentpb.FairUseDimension_FAIR_USE_DIMENSION_INDEX_SIZE
	case meteringapi.DimensionEgress:
		return agentpb.FairUseDimension_FAIR_USE_DIMENSION_EGRESS
	default:
		return agentpb.FairUseDimension_FAIR_USE_DIMENSION_UNSPECIFIED
	}
}

func wireEnvelopeState(s meteringapi.State) agentpb.EnvelopeState {
	switch s {
	case meteringapi.StateWithin:
		return agentpb.EnvelopeState_ENVELOPE_STATE_WITHIN
	case meteringapi.StateNear:
		return agentpb.EnvelopeState_ENVELOPE_STATE_NEAR
	case meteringapi.StateExceeded:
		return agentpb.EnvelopeState_ENVELOPE_STATE_EXCEEDED
	default:
		return agentpb.EnvelopeState_ENVELOPE_STATE_UNSPECIFIED
	}
}
