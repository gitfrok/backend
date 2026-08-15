// Package grpc tests drive the residency Declare door against SPEC-0043's
// acceptance criteria: the verified principal is required before any policy
// decision and is the only source of tenant/actor/roles (AC6), the surface is a
// PEP that renders every refusal in one coarse shape (AC1, AC7), and no request
// field chooses the subject (AC6).
package grpc

import (
	"context"
	"errors"
	"testing"
	"time"

	residencyv1 "github.com/gitfrok/backend/gen/proto/residency/v1"
	identityapi "github.com/gitfrok/backend/modules/identity/api"
	"github.com/gitfrok/backend/modules/residency/api"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// fakeService records the declare call it receives — the tenant, actor and roles
// the door derived from the verified principal — so the tests can assert the
// subject came from the principal, never the request.
type fakeService struct {
	declared bool
	tenantID string
	actorID  string
	roles    []string
	cloud    string
	region   string
	decl     api.Declaration
	err      error
}

func (s *fakeService) Declare(_ context.Context, tenantID, actorID string, roles []string, cloud, region string) (api.Declaration, error) {
	s.declared = true
	s.tenantID, s.actorID, s.roles, s.cloud, s.region = tenantID, actorID, roles, cloud, region
	if s.err != nil {
		return api.Declaration{}, s.err
	}
	return s.decl, nil
}

func (s *fakeService) Declaration(_ context.Context, _ string) (api.Declaration, bool, error) {
	return api.Declaration{}, false, nil
}

func (s *fakeService) ObservePlacement(_ context.Context, _, _, _, _ string) error { return nil }

var _ api.Service = (*fakeService)(nil)

func principalCtx(tenant, actor string, roles ...string) context.Context {
	return identityapi.WithPrincipal(context.Background(), identityapi.Principal{
		TenantID: tenant, ActorID: actor, Roles: roles,
	})
}

func declaredFixture() *fakeService {
	return &fakeService{decl: api.Declaration{
		TenantID: "acme", Cloud: "gke", Region: "europe-west1",
		EffectiveAt: time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC),
		ActorID:     "owner-1", ChainSeq: 7, RecordHash: "hash-7",
	}}
}

// TestDeclareUsesVerifiedPrincipalNotRequest is SPEC-0043 AC6 and AC1: the tenant,
// actor and roles the service is asked with are the verified principal's, and the
// request contributes only cloud and region. The response carries the server-set
// facts (effective time and chain position) the service recorded.
func TestDeclareUsesVerifiedPrincipalNotRequest(t *testing.T) {
	svc := declaredFixture()
	server := NewServer(svc, nil, nil)

	resp, err := server.DeclareResidency(principalCtx("acme", "owner-1", "owner"),
		&residencyv1.DeclareResidencyRequest{Cloud: "gke", Region: "europe-west1"})
	if err != nil {
		t.Fatalf("declare: %v", err)
	}
	if !svc.declared {
		t.Fatal("the service was never asked — the door did not delegate")
	}
	if svc.tenantID != "acme" || svc.actorID != "owner-1" || len(svc.roles) != 1 || svc.roles[0] != "owner" { //arch:allow-inline-authz asserts the door forwards the verified principal's roles, never decides access
		t.Fatalf("subject must come from the verified principal, got tenant=%q actor=%q roles=%v",
			svc.tenantID, svc.actorID, svc.roles)
	}
	if svc.cloud != "gke" || svc.region != "europe-west1" {
		t.Fatalf("the request supplies cloud and region only, got %q/%q", svc.cloud, svc.region)
	}
	if resp.GetCloud() != "gke" || resp.GetRegion() != "europe-west1" ||
		resp.GetChainSeq() != 7 || resp.GetRecordHash() != "hash-7" {
		t.Fatalf("response must carry the declared pinning and chain citation, got %+v", resp)
	}
	if resp.GetEffectiveAt().AsTime() != svc.decl.EffectiveAt {
		t.Fatalf("response effective time = %v, want the server-set %v",
			resp.GetEffectiveAt().AsTime(), svc.decl.EffectiveAt)
	}
}

// TestDeclareRefusesUnverifiedBeforePolicy is SPEC-0043 AC6: a call with no
// verified principal is refused coarsely and the service — and therefore the PDP
// — is never reached, so no decision is recorded for an unverified subject.
func TestDeclareRefusesUnverifiedBeforePolicy(t *testing.T) {
	for name, ctx := range map[string]context.Context{
		"no principal": context.Background(),
		"empty tenant": identityapi.WithPrincipal(context.Background(), identityapi.Principal{ActorID: "owner-1"}),
		"empty actor":  identityapi.WithPrincipal(context.Background(), identityapi.Principal{TenantID: "acme"}),
	} {
		t.Run(name, func(t *testing.T) {
			svc := declaredFixture()
			server := NewServer(svc, nil, nil)
			_, err := server.DeclareResidency(ctx, &residencyv1.DeclareResidencyRequest{Cloud: "gke", Region: "europe-west1"})
			if status.Code(err) != codes.PermissionDenied {
				t.Fatalf("err = %v, want a coarse PermissionDenied", err)
			}
			if svc.declared {
				t.Fatal("an unverified caller must not reach the service/PDP — no decision may be recorded")
			}
		})
	}
}

// TestDeclareRefusalIsOneCoarseShape is SPEC-0043 AC7 (and SPEC-0001): the
// unverified refusal, the PDP-denied refusal and a service failure are the same
// single coarse answer on the wire — one reason, so the surface cannot be probed
// into distinguishing tenants, roles or causes.
func TestDeclareRefusalIsOneCoarseShape(t *testing.T) {
	// The unverified-caller refusal sets the single coarse shape every other
	// refusal must match.
	unverified := NewServer(declaredFixture(), nil, nil)
	_, wantErr := unverified.DeclareResidency(context.Background(),
		&residencyv1.DeclareResidencyRequest{Cloud: "gke", Region: "europe-west1"})
	wantStatus, ok := status.FromError(wantErr)
	if !ok || wantStatus.Code() != codes.PermissionDenied {
		t.Fatalf("unverified refusal = %v, want a PermissionDenied status", wantErr)
	}

	for name, svc := range map[string]*fakeService{
		"pdp denied":     {err: api.ErrResidencyUnavailable},
		"service failed": {err: errors.New("store down")},
	} {
		t.Run(name, func(t *testing.T) {
			server := NewServer(svc, nil, nil)
			_, err := server.DeclareResidency(principalCtx("acme", "owner-1", "owner"),
				&residencyv1.DeclareResidencyRequest{Cloud: "gke", Region: "europe-west1"})
			got, ok := status.FromError(err)
			if !ok || got.Code() != wantStatus.Code() || got.Message() != wantStatus.Message() {
				t.Fatalf("refusal = %v, want the identical coarse shape %v", err, wantStatus)
			}
		})
	}
}

// fakeAuthenticator verifies exactly the tokens it was given, resolving each to
// the principal it maps — the identity seam's shape, stood in for the real
// credential store.
type fakeAuthenticator struct {
	tokens map[string]identityapi.Principal
	calls  int
}

func (a *fakeAuthenticator) AuthenticatePAT(_ context.Context, token string) (identityapi.Principal, bool) {
	a.calls++
	p, ok := a.tokens[token]
	return p, ok
}

func (a *fakeAuthenticator) AuthenticateSSHKey(context.Context, string, string) (identityapi.Principal, bool) {
	return identityapi.Principal{}, false
}

func (a *fakeAuthenticator) IssuePAT(context.Context, string, string, string, []string, []string, *time.Time) (identityapi.PAT, string, error) {
	return identityapi.PAT{}, "", errors.New("not used")
}

func (a *fakeAuthenticator) RevokePAT(context.Context, string, string, string) (identityapi.PAT, error) {
	return identityapi.PAT{}, errors.New("not used")
}

func (a *fakeAuthenticator) ListPATs(context.Context, string, string) ([]identityapi.PAT, error) {
	return nil, errors.New("not used")
}

var _ identityapi.Authenticator = (*fakeAuthenticator)(nil)

// bearerCtx is one incoming call carrying the credential the way the wire does:
// an authorization metadata value of "Bearer <token>".
func bearerCtx(token string) context.Context {
	return metadata.NewIncomingContext(context.Background(),
		metadata.Pairs("authorization", "Bearer "+token))
}

// TestDeclareVerifiesWireCredentialBeforePolicy is SPEC-0043 AC6's verification
// half (ADR-0043): a caller with no principal in context but a valid bearer
// credential is verified through the identity seam, and the resolved principal —
// not anything on the wire — is the subject the PDP is asked about. A refusal on
// this path never reaches the service/PDP.
func TestDeclareVerifiesWireCredentialBeforePolicy(t *testing.T) {
	auth := &fakeAuthenticator{tokens: map[string]identityapi.Principal{
		"gfp_default_owner": {TenantID: "acme", ActorID: "owner-1", Roles: []string{"owner"}},
	}}
	svc := declaredFixture()
	server := NewServer(svc, auth, nil)

	resp, err := server.DeclareResidency(bearerCtx("gfp_default_owner"),
		&residencyv1.DeclareResidencyRequest{Cloud: "gke", Region: "europe-west1"})
	if err != nil {
		t.Fatalf("declare with a verified credential: %v", err)
	}
	if auth.calls != 1 {
		t.Fatalf("the credential must be verified exactly once, got %d", auth.calls)
	}
	if svc.tenantID != "acme" || svc.actorID != "owner-1" || svc.roles[0] != "owner" { //arch:allow-inline-authz asserts the door forwards the verified credential's roles, never decides access
		t.Fatalf("subject must come from the verified credential, got tenant=%q actor=%q roles=%v",
			svc.tenantID, svc.actorID, svc.roles)
	}
	if resp.GetChainSeq() != 7 {
		t.Fatalf("response must carry the witnessed record, got %+v", resp)
	}
}

// TestDeclareRefusesUnverifiableCredentialBeforePolicy is AC6's refusal half:
// anything the identity seam cannot verify — a bad token, a malformed
// authorization value, no credential at all, or no verifier composed — is
// refused with the one coarse shape before the service/PDP is reached, so no
// decision is ever recorded for an unverified subject.
func TestDeclareRefusesUnverifiableCredentialBeforePolicy(t *testing.T) {
	auth := &fakeAuthenticator{tokens: map[string]identityapi.Principal{}}
	cases := map[string]context.Context{
		"unknown token":    bearerCtx("gfp_default_forged"),
		"no bearer prefix": metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "gfp_default_owner")),
		"empty bearer":     metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer ")),
		"no metadata":      context.Background(),
	}
	for name, ctx := range cases {
		t.Run(name, func(t *testing.T) {
			svc := declaredFixture()
			server := NewServer(svc, auth, nil)
			_, err := server.DeclareResidency(ctx, &residencyv1.DeclareResidencyRequest{Cloud: "gke", Region: "europe-west1"})
			if status.Code(err) != codes.PermissionDenied {
				t.Fatalf("err = %v, want the coarse PermissionDenied", err)
			}
			if svc.declared {
				t.Fatal("an unverifiable credential must not reach the service/PDP")
			}
		})
	}
	// A door composed without a verifier fails closed on every call — never a
	// fallback to a self-asserted caller (SPEC-0043 scope note).
	svc := declaredFixture()
	server := NewServer(svc, nil, nil)
	if _, err := server.DeclareResidency(bearerCtx("gfp_default_owner"),
		&residencyv1.DeclareResidencyRequest{Cloud: "gke", Region: "europe-west1"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("a door without a verifier refuses everything, got %v", err)
	}
	if svc.declared {
		t.Fatal("a verifier-less door must not reach the service/PDP")
	}
}

// TestDeclareRecordsUnverifiedRefusalOnOperationalChannel is AC6's audit half for
// the unattributable case: a refusal whose caller could not be verified has no
// tenant to scope an audit record to (the platform's chain is tenant-scoped by
// construction, invariant 1), so it is recorded on the operational channel — and
// the coarse wire answer carries nothing of the presenter.
func TestDeclareRecordsUnverifiedRefusalOnOperationalChannel(t *testing.T) {
	var lines []string
	logf := func(format string, args ...any) { lines = append(lines, format) }
	server := NewServer(declaredFixture(), nil, logf)
	if _, err := server.DeclareResidency(context.Background(),
		&residencyv1.DeclareResidencyRequest{Cloud: "gke", Region: "europe-west1"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("err = %v, want the coarse refusal", err)
	}
	if len(lines) != 1 {
		t.Fatalf("the unattributable refusal is recorded on the operational channel exactly once, got %d", len(lines))
	}
}
