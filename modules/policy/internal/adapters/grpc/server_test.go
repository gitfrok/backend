package grpc

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	policyv1 "github.com/gitfrok/backend/gen/proto/policy/v1"
	"github.com/gitfrok/backend/modules/policy/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
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

// stubRecords is the provenance seam: the dry-run and retrieval answers are dictated here;
// this file is about how they cross the wire.
type stubRecords struct {
	decisions  []api.Decision
	record     api.Record
	dryRunErr  error
	getErr     error
	lastDryRun api.DryRunRequest
}

func (s *stubRecords) EvaluateDryRun(_ context.Context, req api.DryRunRequest) ([]api.Decision, error) {
	s.lastDryRun = req
	return s.decisions, s.dryRunErr
}

func (s *stubRecords) GetDecision(_ context.Context, _, _ string) (api.Record, error) {
	return s.record, s.getErr
}

// dial stands up the real server over an in-memory listener and returns a real generated client.
// Exercising the actual generated stubs is the point: the marshalling is where a field can go
// missing, and a test that called the server struct directly would skip exactly that.
func dial(t *testing.T, pdp api.DecisionPoint, records api.DecisionRecords) policyv1.PolicyDecisionPointClient {
	t.Helper()

	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer()
	policyv1.RegisterPolicyDecisionPointServer(srv, NewServer(pdp, records))
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
	client := dial(t, pdp, nil)

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
	client := dial(t, &stubPDP{decision: want}, nil)

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
	client := dial(t, &stubPDP{decision: api.Decision{Reason: "denied", PolicyRevision: "0.1.0"}}, nil)

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
	client := dial(t, &stubPDP{err: errors.New("bundle exploded")}, nil)

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
	client := dial(t, pdp, nil)

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

// --- T-0025: the provenance surface on the wire -------------------------------------------------

// The provenance Decide now returns is server-produced and must cross the wire field for field:
// a dropped input_digest or mode would make the contract's evidence section unprovable.
func TestDecideProvenanceCrossesTheWire(t *testing.T) {
	client := dial(t, &stubPDP{decision: api.Decision{
		Allowed:        true,
		PolicyRevision: "0.6.0",
		DecisionID:     "01HZY",
		InputDigest:    "sha256:abc",
		Mode:           api.ModeEnforced,
	}}, nil)

	got, err := client.Decide(t.Context(), protoRequest())
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if got.InputDigest != "sha256:abc" {
		t.Errorf("InputDigest = %q, want the server-produced digest", got.InputDigest)
	}
	if got.Mode != policyv1.EvaluationMode_EVALUATION_MODE_ENFORCED {
		t.Errorf("Mode = %v, want EVALUATION_MODE_ENFORCED for a Decide response", got.Mode)
	}
}

func dryRunRequest() *policyv1.EvaluateDryRunRequest {
	return &policyv1.EvaluateDryRunRequest{
		TenantId:           "acme",
		CandidateBundleRef: "proposed/0.7.0",
		Range: &policyv1.HistoricalRange{
			Action:   "merge_request.merge",
			Resource: &policyv1.Resource{Type: "merge_request", Id: "mr-1"},
		},
		MaxResults: 50,
	}
}

// The dry-run request maps onto the port field for field, and every would-be decision comes
// back labelled DRY_RUN under the candidate's revision — nothing about it is caller-supplied.
func TestEvaluateDryRunCrossesTheWire(t *testing.T) {
	rec := &stubRecords{decisions: []api.Decision{{
		Allowed: false, Reason: "denied", PolicyRevision: "0.7.0", DecisionID: "01DRY1",
		InputDigest: "sha256:abc", Mode: api.ModeDryRun,
	}}}
	client := dial(t, &stubPDP{}, rec)

	got, err := client.EvaluateDryRun(t.Context(), dryRunRequest())
	if err != nil {
		t.Fatalf("EvaluateDryRun: %v", err)
	}
	if rec.lastDryRun.TenantID != "acme" || rec.lastDryRun.CandidateBundleRef != "proposed/0.7.0" ||
		rec.lastDryRun.Range.Action != "merge_request.merge" ||
		rec.lastDryRun.Range.Resource.Type != "merge_request" || rec.lastDryRun.MaxResults != 50 {
		t.Errorf("port saw %+v, want the wire request's fields", rec.lastDryRun)
	}
	if len(got.Decisions) != 1 {
		t.Fatalf("EvaluateDryRun returned %d decisions, want 1", len(got.Decisions))
	}
	d := got.Decisions[0]
	if d.Mode != policyv1.EvaluationMode_EVALUATION_MODE_DRY_RUN {
		t.Errorf("Mode = %v, want EVALUATION_MODE_DRY_RUN", d.Mode)
	}
	if d.PolicyRevision != "0.7.0" || d.DecisionId != "01DRY1" || d.InputDigest != "sha256:abc" || d.Allowed {
		t.Errorf("decision = %+v, want the candidate's would-be answer", d)
	}
}

// An over-cap or malformed dry-run is the REQUEST's failure, not the server's: InvalidArgument.
func TestEvaluateDryRunRefusalsMapToStatuses(t *testing.T) {
	for _, tc := range []struct {
		name string
		req  *policyv1.EvaluateDryRunRequest
		err  error
		want codes.Code
	}{
		{"missing tenant", &policyv1.EvaluateDryRunRequest{CandidateBundleRef: "x"}, nil, codes.InvalidArgument},
		{"missing candidate", &policyv1.EvaluateDryRunRequest{TenantId: "acme"}, nil, codes.InvalidArgument},
		{"over-cap range", dryRunRequest(), api.ErrInvalidRequest, codes.InvalidArgument},
		{"no candidate loader", dryRunRequest(), api.ErrNoCandidateLoader, codes.Unimplemented},
		{"candidate failure", dryRunRequest(), errors.New("boom"), codes.Internal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := dial(t, &stubPDP{}, &stubRecords{dryRunErr: tc.err})
			_, err := client.EvaluateDryRun(t.Context(), tc.req)
			if status.Code(err) != tc.want {
				t.Errorf("EvaluateDryRun = %v, want %v", err, tc.want)
			}
		})
	}
}

// GetDecision's wire contract: a found record crosses field for field, and a missing or
// cross-tenant ID is an EMPTY response — one coarse shape, never an error status that would
// distinguish nonexistent from not-yours (SPEC-0030 AC6).
func TestGetDecisionCrossesTheWire(t *testing.T) {
	at := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	rec := &stubRecords{record: api.Record{
		DecisionID: "01HZY", PolicyRevision: "0.6.0", InputDigest: "sha256:abc",
		Mode: api.ModeEnforced, TenantID: "acme", ActorID: "u-1",
		Action: "repo.read", Resource: api.Resource{Type: "repository", ID: "repo-1"},
		Allowed: true, DecidedAt: at,
	}}
	client := dial(t, &stubPDP{}, rec)

	got, err := client.GetDecision(t.Context(), &policyv1.GetDecisionRequest{TenantId: "acme", DecisionId: "01HZY"})
	if err != nil {
		t.Fatalf("GetDecision: %v", err)
	}
	r := got.Record
	if r == nil {
		t.Fatal("GetDecision returned no record")
	}
	if r.DecisionId != "01HZY" || r.PolicyRevision != "0.6.0" || r.InputDigest != "sha256:abc" ||
		r.Mode != policyv1.EvaluationMode_EVALUATION_MODE_ENFORCED || r.TenantId != "acme" ||
		r.ActorId != "u-1" || r.Action != "repo.read" || !r.Allowed {
		t.Errorf("record = %+v, want the stored decision's provenance and outcome", r)
	}
	if r.Resource.GetType() != "repository" || r.Resource.GetId() != "repo-1" {
		t.Errorf("Resource = %+v", r.Resource)
	}
	if !r.DecidedAt.AsTime().Equal(at) {
		t.Errorf("DecidedAt = %v, want %v", r.DecidedAt.AsTime(), at)
	}
}

func TestGetDecisionNotFoundIsAnEmptyResponse(t *testing.T) {
	client := dial(t, &stubPDP{}, &stubRecords{getErr: api.ErrNotFound})

	got, err := client.GetDecision(t.Context(), &policyv1.GetDecisionRequest{TenantId: "acme", DecisionId: "nope"})
	if err != nil {
		t.Fatalf("a nonexistent decision came back as an error: %v", err)
	}
	if got.Record != nil {
		t.Errorf("absent decision returned a record: %+v", got.Record)
	}
}

func TestGetDecisionRefusalsMapToStatuses(t *testing.T) {
	for _, tc := range []struct {
		name string
		req  *policyv1.GetDecisionRequest
		err  error
		want codes.Code
	}{
		{"missing tenant", &policyv1.GetDecisionRequest{DecisionId: "x"}, nil, codes.InvalidArgument},
		{"missing decision id", &policyv1.GetDecisionRequest{TenantId: "acme"}, nil, codes.InvalidArgument},
		{"store failure", &policyv1.GetDecisionRequest{TenantId: "acme", DecisionId: "x"}, errors.New("boom"), codes.Internal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := dial(t, &stubPDP{}, &stubRecords{getErr: tc.err})
			_, err := client.GetDecision(t.Context(), tc.req)
			if status.Code(err) != tc.want {
				t.Errorf("GetDecision = %v, want %v", err, tc.want)
			}
		})
	}
}

// A plane that composes no provenance surface is honest about it: the RPCs report Unimplemented
// while Decide still serves — never a synthesized result.
func TestProvenanceRPCsAreUnimplementedWithoutRecords(t *testing.T) {
	client := dial(t, &stubPDP{decision: api.Decision{Allowed: true}}, nil)

	if _, err := client.EvaluateDryRun(t.Context(), dryRunRequest()); status.Code(err) != codes.Unimplemented {
		t.Errorf("EvaluateDryRun without records = %v, want Unimplemented", err)
	}
	if _, err := client.GetDecision(t.Context(), &policyv1.GetDecisionRequest{TenantId: "acme", DecisionId: "x"}); status.Code(err) != codes.Unimplemented {
		t.Errorf("GetDecision without records = %v, want Unimplemented", err)
	}
	// And the decision door is unaffected by the missing provenance surface.
	if got, err := client.Decide(t.Context(), protoRequest()); err != nil || !got.Allowed {
		t.Errorf("Decide without records = %v / %v, want a normal answer", got, err)
	}
}
