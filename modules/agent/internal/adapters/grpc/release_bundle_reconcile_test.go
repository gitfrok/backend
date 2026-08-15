package grpc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"sync"
	"testing"
	"time"

	agentpb "github.com/gitfrok/backend/gen/proto/agent/v1"
	"github.com/gitfrok/backend/modules/agent/internal/adapters/releasebundle"
	identityapi "github.com/gitfrok/backend/modules/identity/api"
	"github.com/gitfrok/backend/platform/tenancy"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// The AC2 harness test at the RECONCILE level (SPEC-0045 AC2, T-0041): the
// versioned RELEASE trust bundle — the cosign release-signing keys of
// ADR-0044/ADR-0065 — distributes and rotates across AT LEAST TWO harness
// data planes of one tenant over the outbound-only channel, with the staged
// dual-validate overlap applied per fleet and NO downtime: at no instant in
// stage, overlap or removal does either plane's trust set reject a
// legitimate signature. Everything here is named and typed apart from the CA
// trust bundle of SPEC-0044 — a different field, a different wire type, and
// never one test proving the other artifact.

// releaseKeyPair is one release-signing keypair for the harness: the private
// half stays in the test (the publishing CI's posture), the public PEM is
// what stages into the bundle.
type releaseKeyPair struct {
	id   string
	priv *ecdsa.PrivateKey
	pem  []byte
}

func newReleaseKeyPair(t *testing.T, id string) releaseKeyPair {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate %s: %v", id, err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal %s: %v", id, err)
	}
	return releaseKeyPair{id: id, priv: priv, pem: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})}
}

// signRelease signs one release's canonical identity the way sign-release.sh
// does: ECDSA over sha256(oci_ref@digest), DER.
func signReleaseSig(t *testing.T, k releaseKeyPair, ociRef, digest string) []byte {
	t.Helper()
	h := sha256.Sum256([]byte(ociRef + "@" + digest))
	sig, err := ecdsa.SignASN1(rand.Reader, k.priv, h[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return sig
}

// wireVerifies reports whether sig checks out against ANY trusted key of one
// delivered ReleaseTrustBundle — exactly what a data plane does with its
// pinned keys before applying a SignedRelease.
func wireVerifies(t *testing.T, b *agentpb.ReleaseTrustBundle, sig []byte, ociRef, digest string) bool {
	t.Helper()
	h := sha256.Sum256([]byte(ociRef + "@" + digest))
	for _, k := range b.GetTrustedKeys() {
		block, _ := pem.Decode(k.GetPublicKeyPem())
		if block == nil {
			t.Fatalf("distributed key %q carries no PEM block", k.GetKeyId())
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			t.Fatalf("distributed key %q does not parse: %v", k.GetKeyId(), err)
		}
		ec, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			t.Fatalf("distributed key %q is %T, want ECDSA", k.GetKeyId(), pub)
		}
		if ecdsa.VerifyASN1(ec, h[:], sig) {
			return true
		}
	}
	return false
}

// memApplied is the harness half of the distribution registry: the release
// trust bundle revision each data plane has applied, keyed by data_plane_id
// (ADR-0065, SPEC-0045 AC2). The durable postgres half carries the same
// shape in the composition; the harness proves the channel feeds it.
type memApplied struct {
	mu sync.Mutex
	m  map[string]int64
}

func newMemApplied() *memApplied { return &memApplied{m: map[string]int64{}} }

func (r *memApplied) RecordReleaseTrustApplied(_ context.Context, _, dataPlaneID string, revision int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[dataPlaneID] = revision
	return nil
}

func (r *memApplied) applied(dataPlaneID string) (int64, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	v, ok := r.m[dataPlaneID]
	return v, ok
}

// recvReleaseDesiredState reads the stream until one DesiredState carrying
// the RELEASE trust bundle arrives — its own field, never the CA bundle's —
// skipping anything else.
func recvReleaseDesiredState(t *testing.T, stream agentpb.AgentGateway_ConnectClient) *agentpb.DesiredState {
	t.Helper()
	for {
		reply, err := stream.Recv()
		if err != nil {
			t.Fatalf("Recv release desired state: %v", err)
		}
		if ds := reply.GetDesiredState(); ds != nil && ds.GetReleaseTrustBundle() != nil {
			return ds
		}
	}
}

// ackDesiredState is the plane's answer to one delivered RELEASE trust
// bundle: it applied the named generation, and the payload-kind
// discriminator says WHICH artifact it answers — the release bundle's
// revision space, never the CA bundle's. This is what feeds the applied
// registry.
func ackDesiredState(t *testing.T, stream agentpb.AgentGateway_ConnectClient, generation int64) {
	t.Helper()
	msg := &agentpb.AgentMessage{
		MessageId: "m-dsack", Seq: 2, SentAt: timestamppb.New(time.Now()),
		Payload: &agentpb.AgentMessage_DesiredStateAck{DesiredStateAck: &agentpb.DesiredStateAck{
			Generation: generation, Applied: true,
			Kind: agentpb.DesiredStateKind_DESIRED_STATE_KIND_RELEASE_TRUST_BUNDLE,
		}},
	}
	if err := stream.Send(msg); err != nil {
		t.Fatalf("Send desired state ack: %v", err)
	}
}

// ackDesiredStateAs sends one desired-state ack naming an explicit payload
// kind — the harness seam for the attribution property: the registry must
// move ONLY on acks identified as answering the release bundle.
func ackDesiredStateAs(t *testing.T, stream agentpb.AgentGateway_ConnectClient, generation int64, kind agentpb.DesiredStateKind) {
	t.Helper()
	msg := &agentpb.AgentMessage{
		MessageId: "m-dsack-kind", Seq: 3, SentAt: timestamppb.New(time.Now()),
		Payload: &agentpb.AgentMessage_DesiredStateAck{DesiredStateAck: &agentpb.DesiredStateAck{
			Generation: generation, Applied: true, Kind: kind,
		}},
	}
	if err := stream.Send(msg); err != nil {
		t.Fatalf("Send desired state ack (%s): %v", kind, err)
	}
}

func TestAC2_ReleaseTrustBundleDistributedAcrossTwoPlanesWithoutDowntime(t *testing.T) {
	r := newCustodyRig(t) // the channel rig: enrolment, rotation, contact — CA custody underneath

	// The release machinery under test: its own bundle, attached on its own
	// seam, with the applied registry keyed by data_plane_id.
	rb, err := releasebundle.NewBundle(time.Now)
	if err != nil {
		t.Fatalf("releasebundle.NewBundle: %v", err)
	}
	applied := newMemApplied()
	r.gw.AttachReleaseTrustBundle(rb)
	r.gw.AttachReleaseTrustApplied(applied)

	gen1 := newReleaseKeyPair(t, "release-signing-gen1")
	if err := rb.Bootstrap(gen1.id, gen1.pem); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	const ociRef = "registry.example/gitfrok/operator"
	const digest = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	gen1Sig := signReleaseSig(t, gen1, ociRef, digest)

	// TWO harness data planes of ONE tenant enrol over the outbound channel.
	stream1, ack1, cancel1 := r.enrolWire(t, r.dial(t), r.issueSecret(t, "acme"))
	defer func() { cancel1(); _ = stream1.CloseSend() }()
	stream2, ack2, cancel2 := r.enrolWire(t, r.dial(t), r.issueSecret(t, "acme"))
	defer func() { cancel2(); _ = stream2.CloseSend() }()
	plane1, plane2 := ack1.GetDataPlaneId(), ack2.GetDataPlaneId()
	if plane1 == "" || plane2 == "" || plane1 == plane2 {
		t.Fatalf("the tenant's two planes must hold DISTINCT data_plane_ids, got %q and %q", plane1, plane2)
	}
	// The registry keys planes by data_plane_id (ADR-0065): both of the
	// tenant's planes are readable under their own identity.
	ctx := tenancy.WithTenant(context.Background(), tenancy.ID("acme"))
	ctx = identityapi.WithPrincipal(ctx, identityapi.Principal{TenantID: "acme", ActorID: "op-1", Roles: []string{"owner"}})
	for _, id := range []string{plane1, plane2} {
		if _, err := r.svc.GetDataPlane(ctx, "acme", "op-1", id); err != nil {
			t.Fatalf("registry holds no plane %q: %v", id, err)
		}
	}

	// Both planes receive the bootstrapped bundle on its OWN field.
	ds1 := recvReleaseDesiredState(t, stream1)
	ds2 := recvReleaseDesiredState(t, stream2)
	for i, ds := range []*agentpb.DesiredState{ds1, ds2} {
		b := ds.GetReleaseTrustBundle()
		if b.GetRevision() != rb.StagingRevision() {
			t.Fatalf("plane %d bundle revision = %d, want %d", i+1, b.GetRevision(), rb.StagingRevision())
		}
		if len(b.GetTrustedKeys()) != 1 || b.GetTrustedKeys()[0].GetKeyId() != gen1.id || b.GetSigningKeyId() != gen1.id {
			t.Fatalf("plane %d bootstrapped bundle = %+v", i+1, b)
		}
		// The CA bundle's field is NOT the vehicle: this desired state
		// carries the release bundle on its own field and nothing on the
		// CA field (SPEC-0045's two-bundles note, asserted per delivery).
		if ds.GetCaTrustBundle() != nil {
			t.Fatalf("plane %d release delivery rides the CA bundle's field — the two bundles never share a vehicle", i+1)
		}
		if !wireVerifies(t, b, gen1Sig, ociRef, digest) {
			t.Fatalf("plane %d cannot verify gen1's signature against the bootstrapped bundle", i+1)
		}
		ackDesiredState(t, streamFor(i+1, stream1, stream2), b.GetRevision())
	}

	// STAGE: a new release-signing key joins beside the current one — the
	// dual-validate window opens fleet-wide, and BOTH planes receive it.
	gen2 := newReleaseKeyPair(t, "release-signing-gen2")
	if err := rb.Stage(gen2.id, gen2.pem); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	ds1 = recvReleaseDesiredState(t, stream1)
	ds2 = recvReleaseDesiredState(t, stream2)
	gen2Sig := signReleaseSig(t, gen2, ociRef, digest)
	for i, ds := range []*agentpb.DesiredState{ds1, ds2} {
		b := ds.GetReleaseTrustBundle()
		if len(b.GetTrustedKeys()) != 2 {
			t.Fatalf("plane %d overlap bundle = %+v, want both keys trusted", i+1, b)
		}
		if b.GetTrustedKeys()[0].GetKeyId() != gen1.id || b.GetTrustedKeys()[1].GetKeyId() != gen2.id {
			t.Fatalf("plane %d overlap keys = %+v, want [gen1 gen2] oldest-first", i+1, b.GetTrustedKeys())
		}
		if b.GetSigningKeyId() != gen2.id {
			t.Fatalf("plane %d signing key during overlap = %q, want %q", i+1, b.GetSigningKeyId(), gen2.id)
		}
		// NO DOWNTIME: the pre-stage signature still verifies AND the new
		// key's signature verifies already — on every plane.
		if !wireVerifies(t, b, gen1Sig, ociRef, digest) {
			t.Fatalf("plane %d: gen1 signature stopped validating during the overlap — downtime", i+1)
		}
		if !wireVerifies(t, b, gen2Sig, ociRef, digest) {
			t.Fatalf("plane %d: gen2 signature does not validate during the overlap", i+1)
		}
		ackDesiredState(t, streamFor(i+1, stream1, stream2), b.GetRevision())
	}

	// The applied registry converged on the newest revision, keyed by each
	// plane's own data_plane_id — the distribution registry of ADR-0065.
	waitForApplied(t, applied, plane1, rb.StagingRevision())
	waitForApplied(t, applied, plane2, rb.StagingRevision())

	// The overlap plays out: the old key leaves, and BOTH planes converge on
	// the single-key bundle — gen2 signatures verify throughout, gen1 no
	// longer does once converged.
	if err := rb.RemoveKey(gen1.id); err != nil {
		t.Fatalf("RemoveKey after the overlap: %v", err)
	}
	ds1 = recvReleaseDesiredState(t, stream1)
	ds2 = recvReleaseDesiredState(t, stream2)
	for i, ds := range []*agentpb.DesiredState{ds1, ds2} {
		b := ds.GetReleaseTrustBundle()
		if len(b.GetTrustedKeys()) != 1 || b.GetTrustedKeys()[0].GetKeyId() != gen2.id || b.GetSigningKeyId() != gen2.id {
			t.Fatalf("plane %d converged bundle = %+v", i+1, b)
		}
		if ds.GetGeneration() != rb.StagingRevision() {
			t.Fatalf("plane %d converged generation = %d, want %d", i+1, ds.GetGeneration(), rb.StagingRevision())
		}
		if !wireVerifies(t, b, gen2Sig, ociRef, digest) {
			t.Fatalf("plane %d: gen2 signature does not validate after convergence", i+1)
		}
		ackDesiredState(t, streamFor(i+1, stream1, stream2), b.GetRevision())
	}
	waitForApplied(t, applied, plane1, rb.StagingRevision())
	waitForApplied(t, applied, plane2, rb.StagingRevision())
}

func streamFor(n int, s1, s2 agentpb.AgentGateway_ConnectClient) agentpb.AgentGateway_ConnectClient {
	if n == 1 {
		return s1
	}
	return s2
}

// TestDesiredStateAckAttributionNeverCrossesBundles is the misattribution
// tripwire the payload-kind discriminator exists for (agent/v1
// DesiredStateAck.kind): the CA bundle and the release bundle deliver on
// INDEPENDENT revision spaces that both start at 1, so the release applied
// registry must move ONLY on an ack identified as answering the release
// bundle. A CA-bundle ack — and an unspecified-kind ack from a plane
// predating the discriminator — must leave the registry untouched, however
// high its generation: the forward-only GREATEST upsert would make a
// pollution uncorrectable, so it must never be recorded in the first place.
func TestDesiredStateAckAttributionNeverCrossesBundles(t *testing.T) {
	r := newCustodyRig(t)

	rb, err := releasebundle.NewBundle(time.Now)
	if err != nil {
		t.Fatalf("releasebundle.NewBundle: %v", err)
	}
	applied := newMemApplied()
	r.gw.AttachReleaseTrustBundle(rb)
	r.gw.AttachReleaseTrustApplied(applied)

	gen1 := newReleaseKeyPair(t, "release-signing-gen1")
	if err := rb.Bootstrap(gen1.id, gen1.pem); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	stream, ack, cancel := r.enrolWire(t, r.dial(t), r.issueSecret(t, "acme"))
	defer func() { cancel(); _ = stream.CloseSend() }()
	plane := ack.GetDataPlaneId()

	// The plane receives the bootstrapped release bundle and acks it under
	// the release kind: the registry converges on that revision.
	ds := recvReleaseDesiredState(t, stream)
	ackDesiredState(t, stream, ds.GetReleaseTrustBundle().GetRevision())
	waitForApplied(t, applied, plane, rb.StagingRevision())

	// A CA-bundle ack naming a HIGHER generation (the CA revision space
	// overlaps the release one) must NOT move the release registry.
	ackDesiredStateAs(t, stream, rb.StagingRevision()+41, agentpb.DesiredStateKind_DESIRED_STATE_KIND_CA_TRUST_BUNDLE)
	// Neither may an unspecified-kind ack — a plane predating the
	// discriminator is attributed to no registry.
	ackDesiredStateAs(t, stream, rb.StagingRevision()+42, agentpb.DesiredStateKind_DESIRED_STATE_KIND_UNSPECIFIED)

	// A release-kind ack then still lands exactly where it always did —
	// proving the channel kept serving and the gate narrows, never blocks.
	ackDesiredState(t, stream, rb.StagingRevision())
	waitForApplied(t, applied, plane, rb.StagingRevision())

	// The tripwire itself: after BOTH foreign-kind acks and the final
	// release ack, the registry holds EXACTLY the release revision — the
	// foreign generations never entered it.
	if rev, ok := applied.applied(plane); !ok || rev != rb.StagingRevision() {
		t.Fatalf("release registry = (%d, %v) after foreign-kind acks at +%d/+%d, want exactly (%d, true)",
			rev, ok, 41, 42, rb.StagingRevision())
	}
}

// waitForApplied bounds the ack recording: the applied registry must show
// the plane at wantRev shortly after the plane acked.
func waitForApplied(t *testing.T, r *memApplied, dataPlaneID string, wantRev int64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if rev, ok := r.applied(dataPlaneID); ok && rev == wantRev {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	rev, ok := r.applied(dataPlaneID)
	t.Fatalf("plane %q never recorded applied revision %d (got %d, recorded=%v)", dataPlaneID, wantRev, rev, ok)
}
