// The gRPC door for the operator enrolment-token issuance surface (SPEC-0038
// AC1), over contracts/proto/agent/v1's EnrolmentService.
//
// This door is a PEP and nothing more, exactly as the residency Declare door is
// (SPEC-0043, ADR-0063): it authorizes no action itself, it asks the agent
// service — which asks the PDP action agent.enrolment_token.issue — and it
// renders every refusal in one coarse shape.
//
// What makes this door a boundary is where the subject comes from. The caller is
// a VERIFIED principal, never a request claim (ADR-0045): the door resolves it
// through the credential verification gateway (ADR-0043) — the identity seam's
// PAT verification, the same narrow gateway the Git front door and the residency
// Declare door use — and carries it in the request context through identity/api's
// WithPrincipal/RequirePrincipal seam. The IssueEnrolmentTokenRequest carries the
// lifetime and NOTHING ELSE: tenant and actor are properties of the verified
// principal on the call, and a field naming them would be an unauthenticated
// routing claim. A call the door cannot verify is refused before any policy
// question is asked, so no PDP decision is ever recorded for an unverified
// subject.
//
// The secret discipline of SPEC-0038 AC2 rides this door: the one_time_token
// exists in exactly one response — the one this RPC returns on success. It is
// never logged, never echoed into a refusal, and the audit trail the issuance
// leaves names the token by ID only.
package grpc

import (
	"context"
	"strings"

	agentpb "github.com/gitfrok/backend/gen/proto/agent/v1"
	"github.com/gitfrok/backend/modules/agent/api"
	identityapi "github.com/gitfrok/backend/modules/identity/api"
	"github.com/gitfrok/backend/platform/tenancy"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// enrolmentAuthorizationKey is the metadata key the caller's credential travels
// under — the gRPC spelling of the HTTP Authorization header the Git front door
// reads, bearing "Bearer <token>". It is a transport convention, never a subject
// claim: the value is verified before anything reads a tenant from it.
const enrolmentAuthorizationKey = "authorization"

// EnrolmentDoor serves EnrolmentService over the agent module's Operator port,
// verifying the caller through the identity seam before any policy question.
type EnrolmentDoor struct {
	agentpb.UnimplementedEnrolmentServiceServer
	op   api.Operator
	auth identityapi.Authenticator
	logf func(format string, args ...any)
}

var _ agentpb.EnrolmentServiceServer = (*EnrolmentDoor)(nil)

// NewEnrolmentDoor wires the door over the agent operator surface and the
// credential verification gateway. A nil authenticator fails closed: every call
// is refused, which is the sanctioned posture while no verifier is composed —
// never a fallback to a self-asserted caller. logf records the operational
// channel; nil is a no-op, and it never carries the secret (AC2).
func NewEnrolmentDoor(op api.Operator, auth identityapi.Authenticator, logf func(format string, args ...any)) *EnrolmentDoor {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &EnrolmentDoor{op: op, auth: auth, logf: logf}
}

// issueDenied is the ONE coarse shape for every failed issuance on this door:
// unverified, unauthorized and store failure are indistinguishable on the wire,
// so probing the surface cannot enumerate tenants or causes (SPEC-0001). A
// single reason is a security property, not laziness — the specific cause
// belongs in the audit trail.
func issueDenied() error {
	return status.Error(codes.PermissionDenied, "agent: enrolment token issuance unavailable")
}

// verifiedCaller resolves the caller the request context already carries or,
// failing that, verifies the credential on the wire through the identity seam.
// It returns ok=false for anything it cannot verify; it never invents a subject.
func (s *EnrolmentDoor) verifiedCaller(ctx context.Context) (context.Context, identityapi.Principal, bool) {
	// A principal already verified upstream (the composition root's seam) is the
	// caller: WithPrincipal is a transport-boundary helper, and this adapter is
	// transport.
	if principal, err := identityapi.RequirePrincipal(ctx); err == nil {
		return tenancy.WithTenant(ctx, tenancy.ID(principal.TenantID)), principal, true
	}
	if s.auth == nil {
		return ctx, identityapi.Principal{}, false
	}
	token, ok := enrolBearerToken(ctx)
	if !ok {
		return ctx, identityapi.Principal{}, false
	}
	principal, ok := s.auth.AuthenticatePAT(ctx, token)
	if !ok {
		return ctx, identityapi.Principal{}, false
	}
	ctx = tenancy.WithTenant(ctx, tenancy.ID(principal.TenantID))
	return identityapi.WithPrincipal(ctx, principal), principal, true
}

// enrolBearerToken extracts the credential from the call's authorization
// metadata. Anything that is not exactly one "Bearer <token>" value is the same
// absence.
func enrolBearerToken(ctx context.Context) (string, bool) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", false
	}
	values := md.Get(enrolmentAuthorizationKey)
	if len(values) != 1 {
		return "", false
	}
	const prefix = "Bearer "
	v := values[0]
	if len(v) <= len(prefix) || !strings.EqualFold(v[:len(prefix)], prefix) {
		return "", false
	}
	return strings.TrimSpace(v[len(prefix):]), true
}

// IssueEnrolmentToken implements agentpb.EnrolmentServiceServer.
//
// The caller is verified BEFORE any policy decision: an unverified caller never
// reaches the PDP, so no decision is recorded for a subject the platform did not
// verify. Tenant and actor are taken from the verified principal — never from the
// request, which supplies the lifetime only. The domain clamps the lifetime,
// writes the token's hash durably and appends exactly one audit record naming the
// tenant, the verified actor and the token's ID and expiry — never the secret
// (AC2, AC7). A PDP refusal is audited as the decision point's denial event; the
// wire answer stays the single coarse shape either way.
func (s *EnrolmentDoor) IssueEnrolmentToken(ctx context.Context, req *agentpb.IssueEnrolmentTokenRequest) (*agentpb.IssueEnrolmentTokenResponse, error) {
	ctx, principal, ok := s.verifiedCaller(ctx)
	if !ok {
		// An unverified caller has no tenant to scope an audit record to — the
		// platform's audit chain is tenant-scoped by construction (invariant 1) —
		// so the refusal is recorded on the operational channel only. The refusal
		// stays coarse, carries nothing of the presenter, and no PDP decision is
		// made for an unverified subject.
		s.logf("agent: enrolment token issuance refused — no verified principal")
		return nil, issueDenied()
	}

	token, secret, err := s.op.IssueEnrolmentToken(ctx, principal.TenantID, principal.ActorID, req.GetLifetime().AsDuration())
	if err != nil {
		// The refusal is already audited: a PDP denial leaves the decision
		// point's denial record on the tenant's trail, and the wire answer is
		// the single coarse shape — never the secret, never the cause (AC2).
		return nil, issueDenied()
	}
	// The secret exists in this response exactly once (AC2): the store holds
	// only its hash, so nothing downstream can ever serve it again.
	return &agentpb.IssueEnrolmentTokenResponse{
		TokenId:      token.ID,
		OneTimeToken: secret,
		IssuedAt:     timestamppb.New(token.IssuedAt),
		ExpiresAt:    timestamppb.New(token.ExpiresAt),
	}, nil
}
