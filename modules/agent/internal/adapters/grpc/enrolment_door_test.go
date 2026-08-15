// Package grpc tests drive the enrolment issuance door against SPEC-0038's
// acceptance criteria as the residency Declare door's tests do for SPEC-0043:
// the verified principal is required before any policy decision and is the only
// source of tenant/actor (AC1's subject rule, inherited from SPEC-0043 AC6), the
// surface is a PEP that renders every refusal in one coarse shape (SPEC-0001),
// the secret travels in exactly one response (AC2), and no request field chooses
// the subject (the request carries the lifetime and nothing else).
package grpc

import (
	"context"
	"errors"
	"testing"
	"time"

	agentpb "github.com/gitfrok/backend/gen/proto/agent/v1"
	"github.com/gitfrok/backend/modules/agent/api"
	identityapi "github.com/gitfrok/backend/modules/identity/api"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
)

// fakeOperator records the issuance call it receives — the tenant, actor and
// lifetime the door derived from the verified principal — so the tests can assert
// the subject came from the principal, never the request.
type fakeOperator struct {
	issued   bool
	tenantID string
	actorID  string
	lifetime time.Duration
	token    api.EnrolmentToken
	secret   string
	err      error
}

func (o *fakeOperator) IssueEnrolmentToken(_ context.Context, tenantID, actorID string, lifetime time.Duration) (api.EnrolmentToken, string, error) {
	o.issued = true
	o.tenantID, o.actorID, o.lifetime = tenantID, actorID, lifetime
	if o.err != nil {
		return api.EnrolmentToken{}, "", o.err
	}
	return o.token, o.secret, nil
}

func (o *fakeOperator) RevokeEnrolmentToken(context.Context, string, string, string) error {
	return errors.New("not used")
}

func (o *fakeOperator) RevokeDataPlane(context.Context, string, string, string) error {
	return errors.New("not used")
}

func (o *fakeOperator) GetDataPlane(context.Context, string, string, string) (api.DataPlane, error) {
	return api.DataPlane{}, errors.New("not used")
}

func (o *fakeOperator) Fleet(context.Context, string, string) ([]api.FleetView, error) {
	return nil, errors.New("not used")
}

var _ api.Operator = (*fakeOperator)(nil)

func enrolPrincipalCtx(tenant, actor string, roles ...string) context.Context {
	return identityapi.WithPrincipal(context.Background(), identityapi.Principal{
		TenantID: tenant, ActorID: actor, Roles: roles,
	})
}

func issuedFixture() *fakeOperator {
	return &fakeOperator{
		token: api.EnrolmentToken{
			ID: "tok-1", TenantID: "acme", IssuedBy: "op-1",
			IssuedAt:  time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC),
			ExpiresAt: time.Date(2026, 8, 16, 13, 0, 0, 0, time.UTC),
		},
		secret: "gfe_secret_once",
	}
}

// TestIssueUsesVerifiedPrincipalNotRequest is SPEC-0038 AC1's subject rule
// (inherited from SPEC-0043 AC6): the tenant and actor the operator surface is
// asked with are the verified principal's, and the request contributes only the
// lifetime. The response carries the server-set facts — the token's ID, the
// secret exactly once, and the validity window the domain recorded (AC2).
func TestIssueUsesVerifiedPrincipalNotRequest(t *testing.T) {
	op := issuedFixture()
	door := NewEnrolmentDoor(op, nil, nil)

	resp, err := door.IssueEnrolmentToken(enrolPrincipalCtx("acme", "op-1", "owner"),
		&agentpb.IssueEnrolmentTokenRequest{Lifetime: durationpb.New(time.Hour)})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if !op.issued {
		t.Fatal("the operator surface was never asked — the door did not delegate")
	}
	if op.tenantID != "acme" || op.actorID != "op-1" { //arch:allow-inline-authz asserts the door forwards the verified principal, never decides access
		t.Fatalf("subject must come from the verified principal, got tenant=%q actor=%q",
			op.tenantID, op.actorID)
	}
	if op.lifetime != time.Hour {
		t.Fatalf("the request supplies the lifetime only, got %v", op.lifetime)
	}
	if resp.GetTokenId() != "tok-1" || resp.GetOneTimeToken() != "gfe_secret_once" {
		t.Fatalf("response must carry the token's ID and the secret exactly once, got %+v", resp)
	}
	if resp.GetIssuedAt().AsTime() != op.token.IssuedAt || resp.GetExpiresAt().AsTime() != op.token.ExpiresAt {
		t.Fatalf("response must carry the server-set validity window, got %v..%v",
			resp.GetIssuedAt().AsTime(), resp.GetExpiresAt().AsTime())
	}
}

// TestIssueForwardsAbsentLifetimeAsZero is the domain's clamp input: an absent
// lifetime reaches the operator surface as zero, where the domain clamps it to
// the configured maximum — the door never invents a lifetime of its own.
func TestIssueForwardsAbsentLifetimeAsZero(t *testing.T) {
	op := issuedFixture()
	door := NewEnrolmentDoor(op, nil, nil)
	if _, err := door.IssueEnrolmentToken(enrolPrincipalCtx("acme", "op-1", "owner"),
		&agentpb.IssueEnrolmentTokenRequest{}); err != nil {
		t.Fatalf("issue: %v", err)
	}
	if op.lifetime != 0 {
		t.Fatalf("an absent lifetime must reach the domain as zero for clamping, got %v", op.lifetime)
	}
}

// TestIssueRefusesUnverifiedBeforePolicy is the AC6 analogue: a call with no
// verified principal is refused coarsely and the operator surface — and therefore
// the PDP — is never reached, so no decision is recorded for an unverified subject.
func TestIssueRefusesUnverifiedBeforePolicy(t *testing.T) {
	for name, ctx := range map[string]context.Context{
		"no principal": context.Background(),
		"empty tenant": identityapi.WithPrincipal(context.Background(), identityapi.Principal{ActorID: "op-1"}),
		"empty actor":  identityapi.WithPrincipal(context.Background(), identityapi.Principal{TenantID: "acme"}),
	} {
		t.Run(name, func(t *testing.T) {
			op := issuedFixture()
			door := NewEnrolmentDoor(op, nil, nil)
			_, err := door.IssueEnrolmentToken(ctx, &agentpb.IssueEnrolmentTokenRequest{Lifetime: durationpb.New(time.Hour)})
			if status.Code(err) != codes.PermissionDenied {
				t.Fatalf("err = %v, want a coarse PermissionDenied", err)
			}
			if op.issued {
				t.Fatal("an unverified caller must not reach the operator surface/PDP — no decision may be recorded")
			}
		})
	}
}

// TestIssueRefusalIsOneCoarseShape is SPEC-0001 applied to this door: the
// unverified refusal, the PDP-denied refusal and a store failure are the same
// single coarse answer on the wire — one reason, so the surface cannot be probed
// into distinguishing tenants, roles or causes.
func TestIssueRefusalIsOneCoarseShape(t *testing.T) {
	unverified := NewEnrolmentDoor(issuedFixture(), nil, nil)
	_, wantErr := unverified.IssueEnrolmentToken(context.Background(),
		&agentpb.IssueEnrolmentTokenRequest{Lifetime: durationpb.New(time.Hour)})
	wantStatus, ok := status.FromError(wantErr)
	if !ok || wantStatus.Code() != codes.PermissionDenied {
		t.Fatalf("unverified refusal = %v, want a PermissionDenied status", wantErr)
	}

	for name, op := range map[string]*fakeOperator{
		"pdp denied":     {err: api.ErrAuthorizationDenied},
		"service failed": {err: errors.New("store down")},
	} {
		t.Run(name, func(t *testing.T) {
			door := NewEnrolmentDoor(op, nil, nil)
			_, err := door.IssueEnrolmentToken(enrolPrincipalCtx("acme", "op-1", "owner"),
				&agentpb.IssueEnrolmentTokenRequest{Lifetime: durationpb.New(time.Hour)})
			got, ok := status.FromError(err)
			if !ok || got.Code() != wantStatus.Code() || got.Message() != wantStatus.Message() {
				t.Fatalf("refusal = %v, want the identical coarse shape %v", err, wantStatus)
			}
		})
	}
}

// enrolFakeAuthenticator verifies exactly the tokens it was given, resolving each
// to the principal it maps — the identity seam's shape, stood in for the real
// credential store.
type enrolFakeAuthenticator struct {
	tokens map[string]identityapi.Principal
	calls  int
}

func (a *enrolFakeAuthenticator) AuthenticatePAT(_ context.Context, token string) (identityapi.Principal, bool) {
	a.calls++
	p, ok := a.tokens[token]
	return p, ok
}

func (a *enrolFakeAuthenticator) AuthenticateSSHKey(context.Context, string, string) (identityapi.Principal, bool) {
	return identityapi.Principal{}, false
}

func (a *enrolFakeAuthenticator) IssuePAT(context.Context, string, string, string, []string, []string, *time.Time) (identityapi.PAT, string, error) {
	return identityapi.PAT{}, "", errors.New("not used")
}

func (a *enrolFakeAuthenticator) RevokePAT(context.Context, string, string, string) (identityapi.PAT, error) {
	return identityapi.PAT{}, errors.New("not used")
}

func (a *enrolFakeAuthenticator) ListPATs(context.Context, string, string) ([]identityapi.PAT, error) {
	return nil, errors.New("not used")
}

var _ identityapi.Authenticator = (*enrolFakeAuthenticator)(nil)

// enrolBearerCtx is one incoming call carrying the credential the way the wire
// does: an authorization metadata value of "Bearer <token>".
func enrolBearerCtx(token string) context.Context {
	return metadata.NewIncomingContext(context.Background(),
		metadata.Pairs("authorization", "Bearer "+token))
}

// TestIssueVerifiesWireCredentialBeforePolicy is the verification half of the
// subject rule (ADR-0043): a caller with no principal in context but a valid
// bearer credential is verified through the identity seam, and the resolved
// principal — not anything on the wire — is the subject the PDP is asked about.
func TestIssueVerifiesWireCredentialBeforePolicy(t *testing.T) {
	auth := &enrolFakeAuthenticator{tokens: map[string]identityapi.Principal{
		"gfp_default_owner": {TenantID: "acme", ActorID: "op-1", Roles: []string{"owner"}},
	}}
	op := issuedFixture()
	door := NewEnrolmentDoor(op, auth, nil)

	resp, err := door.IssueEnrolmentToken(enrolBearerCtx("gfp_default_owner"),
		&agentpb.IssueEnrolmentTokenRequest{Lifetime: durationpb.New(time.Hour)})
	if err != nil {
		t.Fatalf("issue with a verified credential: %v", err)
	}
	if auth.calls != 1 {
		t.Fatalf("the credential must be verified exactly once, got %d", auth.calls)
	}
	if op.tenantID != "acme" || op.actorID != "op-1" { //arch:allow-inline-authz asserts the door forwards the verified credential's principal, never decides access
		t.Fatalf("subject must come from the verified credential, got tenant=%q actor=%q",
			op.tenantID, op.actorID)
	}
	if resp.GetTokenId() != "tok-1" {
		t.Fatalf("response must carry the issued token, got %+v", resp)
	}
}

// TestIssueRefusesUnverifiableCredentialBeforePolicy is the refusal half:
// anything the identity seam cannot verify — a bad token, a malformed
// authorization value, no credential at all, or no verifier composed — is refused
// with the one coarse shape before the operator surface/PDP is reached, so no
// decision is ever recorded for an unverified subject.
func TestIssueRefusesUnverifiableCredentialBeforePolicy(t *testing.T) {
	auth := &enrolFakeAuthenticator{tokens: map[string]identityapi.Principal{}}
	cases := map[string]context.Context{
		"unknown token":    enrolBearerCtx("gfp_default_forged"),
		"no bearer prefix": metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "gfp_default_owner")),
		"empty bearer":     metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer ")),
		"no metadata":      context.Background(),
	}
	for name, ctx := range cases {
		t.Run(name, func(t *testing.T) {
			op := issuedFixture()
			door := NewEnrolmentDoor(op, auth, nil)
			_, err := door.IssueEnrolmentToken(ctx, &agentpb.IssueEnrolmentTokenRequest{Lifetime: durationpb.New(time.Hour)})
			if status.Code(err) != codes.PermissionDenied {
				t.Fatalf("err = %v, want the coarse PermissionDenied", err)
			}
			if op.issued {
				t.Fatal("an unverifiable credential must not reach the operator surface/PDP")
			}
		})
	}
	// A door composed without a verifier fails closed on every call — never a
	// fallback to a self-asserted caller.
	op := issuedFixture()
	door := NewEnrolmentDoor(op, nil, nil)
	if _, err := door.IssueEnrolmentToken(enrolBearerCtx("gfp_default_owner"),
		&agentpb.IssueEnrolmentTokenRequest{Lifetime: durationpb.New(time.Hour)}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("a door without a verifier refuses everything, got %v", err)
	}
	if op.issued {
		t.Fatal("a verifier-less door must not reach the operator surface/PDP")
	}
}

// TestIssueRecordsUnverifiedRefusalOnOperationalChannel is the audit half for the
// unattributable case: a refusal whose caller could not be verified has no tenant
// to scope an audit record to (the platform's chain is tenant-scoped by
// construction, invariant 1), so it is recorded on the operational channel — and
// the coarse wire answer carries nothing of the presenter.
func TestIssueRecordsUnverifiedRefusalOnOperationalChannel(t *testing.T) {
	var lines []string
	logf := func(format string, args ...any) { lines = append(lines, format) }
	door := NewEnrolmentDoor(issuedFixture(), nil, logf)
	if _, err := door.IssueEnrolmentToken(context.Background(),
		&agentpb.IssueEnrolmentTokenRequest{Lifetime: durationpb.New(time.Hour)}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("err = %v, want the coarse refusal", err)
	}
	if len(lines) != 1 {
		t.Fatalf("the unattributable refusal is recorded on the operational channel exactly once, got %d", len(lines))
	}
}
