package grpc

import (
	"context"
	"errors"
	"net"
	"testing"

	policyv1 "github.com/gitfrok/backend/gen/proto/policy/v1"
	"github.com/gitfrok/backend/modules/policy/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

type stubPDP struct {
	decision api.Decision
	err      error
	lastReq  api.Request
}

func (s *stubPDP) Decide(_ context.Context, req api.Request) (api.Decision, error) {
	s.lastReq = req
	return s.decision, s.err
}

// dial stands up the real server over an in-memory listener and returns a real generated client.
// Exercising the actual generated stubs is the point: the marshalling is where a field can go
// missing, and a test that called the server struct directly would skip exactly that.
func dial(t *testing.T, pdp api.DecisionPoint) policyv1.PolicyDecisionPointClient {
	t.Helper()

	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer()
	policyv1.RegisterPolicyDecisionPointServer(srv, NewServer(pdp))
	go func() {
		if err := srv.Serve(lis); err != nil {
			t.Logf("server stopped: %v", err)
		}
	}()

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		srv.Stop()
	})
	return policyv1.NewPolicyDecisionPointClient(conn)
}

func protoRequest() *policyv1.DecideRequest {
	return &policyv1.DecideRequest{
		TenantId: "acme",
		Subject:  &policyv1.Subject{Id: "u-1", TenantId: "acme", Roles: []string{"reader"}},
		Action:   "repo.read",
		Resource: &policyv1.Resource{Type: "repository", Id: "repo-1"},
		Context:  map[string]string{"protocol": "https"},
	}
}

// Every field must survive the trip in both directions. A dropped field on the way in is the
// dangerous one: the PDP still answers, just a different question than was asked.
func TestRequestFieldsCrossTheWire(t *testing.T) {
	pdp := &stubPDP{decision: api.Decision{Allowed: true}}
	client := dial(t, pdp)

	if _, err := client.Decide(t.Context(), protoRequest()); err != nil {
		t.Fatalf("Decide: %v", err)
	}

	got := pdp.lastReq
	if got.TenantID != "acme" {
		t.Errorf("TenantID = %q", got.TenantID)
	}
	if got.Action != "repo.read" {
		t.Errorf("Action = %q", got.Action)
	}
	if got.Subject.ID != "u-1" || got.Subject.TenantID != "acme" {
		t.Errorf("Subject = %+v", got.Subject)
	}
	if len(got.Subject.Roles) != 1 || got.Subject.Roles[0] != "reader" {
		t.Errorf("Roles = %v", got.Subject.Roles)
	}
	if got.Resource.Type != "repository" || got.Resource.ID != "repo-1" {
		t.Errorf("Resource = %+v", got.Resource)
	}
	if got.Context["protocol"] != "https" {
		t.Errorf("Context = %v", got.Context)
	}
}

func TestResponseFieldsCrossTheWire(t *testing.T) {
	want := api.Decision{
		Allowed:        true,
		Reason:         "allowed: subject holds a role granting this action",
		PolicyRevision: "0.1.0",
		DecisionID:     "01HZY",
	}
	client := dial(t, &stubPDP{decision: want})

	got, err := client.Decide(t.Context(), protoRequest())
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if !got.Allowed || got.Reason != want.Reason ||
		got.PolicyRevision != want.PolicyRevision || got.DecisionId != want.DecisionID {
		t.Errorf("response = %+v, want %+v", got, want)
	}
}

func TestDenialCrossesAsANormalResponse(t *testing.T) {
	client := dial(t, &stubPDP{decision: api.Decision{Reason: "denied", PolicyRevision: "0.1.0"}})

	got, err := client.Decide(t.Context(), protoRequest())
	// A denial is an answer, not a transport failure. Returning an error status would make the
	// PEP unable to tell "you may not" from "the PDP is down" — and those need different handling:
	// one is cacheable, the other must be retried or must fail the request.
	if err != nil {
		t.Fatalf("a denial came back as a gRPC error: %v", err)
	}
	if got.Allowed {
		t.Error("Allowed = true for a denied decision")
	}
}

// An evaluator failure must reach the caller as an error status, NOT as allowed=false.
//
// The difference matters because the BFF caches: a denial is a decision and gets cached, while a
// failure is the absence of one and must not be. Returning a synthesized deny would poison the
// cache with an answer no policy ever gave, and it would keep denying after the PDP recovered.
func TestEvaluatorFailureIsAnErrorStatusNotADenial(t *testing.T) {
	client := dial(t, &stubPDP{err: errors.New("bundle exploded")})

	got, err := client.Decide(t.Context(), protoRequest())
	if err == nil {
		t.Fatalf("an evaluator failure returned a normal response %+v", got)
	}
	if status.Code(err) == 0 {
		t.Error("expected a non-OK status code")
	}
	if got.GetAllowed() {
		t.Error("an evaluator failure returned Allowed=true")
	}
}

// Proto3 message fields are pointers and a client may legitimately omit them. Omitting the subject
// must be a denial decided by policy, never a panic in the server — a nil-deref here would be a
// remotely-triggerable crash of the component every authorization flows through.
func TestAbsentMessageFieldsAreNotAPanic(t *testing.T) {
	pdp := &stubPDP{decision: api.Decision{Reason: "denied"}}
	client := dial(t, pdp)

	got, err := client.Decide(t.Context(), &policyv1.DecideRequest{Action: "repo.read"})
	if err != nil {
		t.Fatalf("a request with no subject or resource errored: %v", err)
	}
	if got.Allowed {
		t.Error("a request with no subject was allowed")
	}
	// And the empty values must reach the evaluator, so policy is what denies it.
	if pdp.lastReq.Subject.ID != "" || pdp.lastReq.Resource.Type != "" {
		t.Errorf("absent fields did not map to zero values: %+v", pdp.lastReq)
	}
}
