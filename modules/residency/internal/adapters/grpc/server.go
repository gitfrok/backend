// The gRPC door for the residency Declare surface (T-0038, SPEC-0043), over
// contracts/proto/residency/v1's ResidencyService.
//
// This door is a PEP and nothing more (ADR-0063 decision 3): it authorizes no
// action itself, it asks the residency service — which asks the PDP action
// residency.declaration.set — and it renders every refusal in one coarse shape.
//
// What makes this door different from the Phase-2 doors is where the subject
// comes from. The caller is a VERIFIED principal, never a request claim
// (ADR-0045): the door resolves it through the credential verification gateway
// (ADR-0043) — the identity seam's PAT verification, the same narrow gateway the
// Git front door uses — and carries it in the request context through
// identity/api's WithPrincipal/RequirePrincipal seam. The residency/v1 messages
// carry no tenant, actor or role field at all, and the contract test beside this
// module asserts they never do (SPEC-0043 AC6). A call the door cannot verify is
// refused before any policy question is asked, so no PDP decision is ever
// recorded for an unverified subject.
package grpc

import (
	"context"
	"strings"

	residencyv1 "github.com/gitfrok/backend/gen/proto/residency/v1"
	identityapi "github.com/gitfrok/backend/modules/identity/api"
	"github.com/gitfrok/backend/modules/residency/api"
	"github.com/gitfrok/backend/platform/tenancy"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// authorizationKey is the metadata key the caller's credential travels under —
// the gRPC spelling of the HTTP Authorization header the Git front door reads,
// bearing "Bearer <token>". It is a transport convention, never a subject claim:
// the value is verified before anything reads a tenant from it.
const authorizationKey = "authorization"

// Server serves ResidencyService over the residency module's Service port,
// verifying the caller through the identity seam before any policy question.
type Server struct {
	residencyv1.UnimplementedResidencyServiceServer
	svc  api.Service
	auth identityapi.Authenticator
	logf func(format string, args ...any)
}

var _ residencyv1.ResidencyServiceServer = (*Server)(nil)

// NewServer wires the door over the residency service and the credential
// verification gateway. A nil authenticator fails closed: every call is refused,
// which is the sanctioned posture while no verifier is composed (SPEC-0043 scope
// note) — never a fallback to a self-asserted caller. logf records the
// operational channel; nil is a no-op.
func NewServer(svc api.Service, auth identityapi.Authenticator, logf func(format string, args ...any)) *Server {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Server{svc: svc, auth: auth, logf: logf}
}

// declDenied is the ONE coarse shape for every failed declaration on this door:
// unverified, unauthorized, malformed, cross-tenant and absent are
// indistinguishable on the wire, so probing the surface cannot enumerate
// tenants or declarations (SPEC-0001). A single reason is a security property,
// not laziness — the specific cause belongs in the audit trail (SPEC-0043 AC1).
func declDenied() error {
	return status.Error(codes.PermissionDenied, "residency: declaration unavailable")
}

// verifiedCaller resolves the caller the request context already carries or,
// failing that, verifies the credential on the wire through the identity seam.
// It returns ok=false for anything it cannot verify; it never invents a subject.
func (s *Server) verifiedCaller(ctx context.Context) (context.Context, identityapi.Principal, bool) {
	// A principal already verified upstream (the composition root's seam) is the
	// caller: WithPrincipal is a transport-boundary helper, and this adapter is
	// transport.
	if principal, err := identityapi.RequirePrincipal(ctx); err == nil {
		return tenancy.WithTenant(ctx, tenancy.ID(principal.TenantID)), principal, true
	}
	if s.auth == nil {
		return ctx, identityapi.Principal{}, false
	}
	token, ok := bearerToken(ctx)
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

// bearerToken extracts the credential from the call's authorization metadata.
// Anything that is not exactly one "Bearer <token>" value is the same absence.
func bearerToken(ctx context.Context) (string, bool) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", false
	}
	values := md.Get(authorizationKey)
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

// DeclareResidency implements residencyv1.ResidencyServiceServer.
//
// The caller is verified BEFORE any policy decision (SPEC-0043 AC6): an
// unverified caller never reaches the PDP, so no decision is recorded for a
// subject the platform did not verify. Tenant, actor and roles are taken from
// the verified principal — never from the request, which supplies cloud and
// region only. A refusal the PDP returns is audited by the residency service
// itself, as exactly one DENIED record naming the verified actor and previous
// and new pinning (SPEC-0043 AC1).
func (s *Server) DeclareResidency(ctx context.Context, req *residencyv1.DeclareResidencyRequest) (*residencyv1.DeclareResidencyResponse, error) {
	ctx, principal, ok := s.verifiedCaller(ctx)
	if !ok {
		// An unverified caller has no tenant to scope an audit record to — the
		// platform's audit chain is tenant-scoped by construction (invariant 1) —
		// so the refusal is recorded on the operational channel only, exactly as
		// the agent door records an unattributable enrolment refusal. The refusal
		// stays coarse, carries nothing of the presenter, and no PDP decision is
		// made for an unverified subject (AC6).
		s.logf("residency: declare refused — no verified principal")
		return nil, declDenied()
	}

	decl, err := s.svc.Declare(ctx, principal.TenantID, principal.ActorID, principal.Roles,
		req.GetCloud(), req.GetRegion())
	if err != nil {
		// The refusal is already on the tenant's audit trail: the residency
		// service witnessed exactly one DENIED declaration record beside the
		// decision point's generic denial event (SPEC-0043 AC1). The wire answer
		// stays the single coarse shape.
		return nil, declDenied()
	}
	return &residencyv1.DeclareResidencyResponse{
		Cloud:       decl.Cloud,
		Region:      decl.Region,
		EffectiveAt: timestamppb.New(decl.EffectiveAt),
		ChainSeq:    decl.ChainSeq,
		RecordHash:  decl.RecordHash,
	}, nil
}
