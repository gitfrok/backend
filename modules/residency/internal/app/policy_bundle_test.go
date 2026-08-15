package app

// Behavioral proof that the residency Declare surface consumes the reviewed
// policy bundle's decision for residency.declaration.set (SPEC-0043 AC7,
// T-0038, ADR-0067): the service presents the verified principal's identity to
// the REAL bundle from governance/policies — never a copy of it — and the
// bundle's answer is the declaration's outcome. Owner and the tenant-scoped
// platform operator are allowed; every other role, a tenant mismatch and a
// non-tenant resource are refused. The governance repo's Rego tests prove the
// rule's content; this test proves the backend asks the question the rule
// expects and acts on the answer (SPEC-0002 AC4).

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gitfrok/backend/modules/policy"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
	"github.com/gitfrok/backend/modules/residency/api"
	"github.com/gitfrok/backend/modules/residency/internal/adapters/memory"
	platformaudit "github.com/gitfrok/backend/platform/audit"
	"github.com/gitfrok/backend/platform/bus"
	"github.com/gitfrok/backend/platform/tenancy"
)

// governanceBundleDir is the reviewed policy bundle, mounted beside the backend
// in every development checkout and in CI. The test skips when it is not there —
// the proof is about the two repos composing, and one repo alone cannot fake the
// other's half (same seam as the codereview merge-gate bundle test).
func governanceBundleDir() (string, bool) {
	dir := filepath.Join("..", "..", "..", "..", "..", "governance", "policies")
	if _, err := os.Stat(filepath.Join(dir, ".manifest")); err != nil {
		return "", false
	}
	return dir, true
}

// bundlePDP loads the real bundle onto an in-process bus and returns the
// decision point the residency service would ask.
func bundlePDP(t *testing.T) policyapi.DecisionPoint {
	t.Helper()
	dir, ok := governanceBundleDir()
	if !ok {
		t.Skip("governance/policies not checked out beside backend/; the bundle proof needs both repos")
	}
	pdp, err := policy.NewOPADecisionPoint(dir, bus.NewInProcess())
	if err != nil {
		t.Fatalf("the real governance bundle does not load: %v", err)
	}
	return pdp
}

// declareRequest is the exact PDP question the residency service asks for a
// declaration (service.go Declare): the action residency.declaration.set about
// the tenant, under the caller's tenant-scoped identity.
func declareRequest(tenantID, actorID string, roles []string, resource policyapi.Resource) policyapi.Request {
	return policyapi.Request{
		TenantID: tenantID,
		Subject:  policyapi.Subject{ID: actorID, TenantID: tenantID, Roles: roles},
		Action:   platformaudit.ActionResidencyDeclarationSet,
		Resource: resource,
	}
}

func tenantResource(tenantID string) policyapi.Resource {
	return policyapi.Resource{Type: "tenant", ID: tenantID}
}

func decideAllowed(t *testing.T, pdp policyapi.DecisionPoint, req policyapi.Request) bool {
	t.Helper()
	decision, err := pdp.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("decide %s: %v", req.Action, err)
	}
	return decision.Allowed
}

// TestBundleOwnerDeclares proves the unchanged owner grant: the tenant's owner,
// asked about its own tenant, is allowed (SPEC-0043 AC7).
func TestBundleOwnerDeclares(t *testing.T) {
	pdp := bundlePDP(t)
	if !decideAllowed(t, pdp, declareRequest("acme", "owner-1", []string{"owner"}, tenantResource("acme"))) {
		t.Fatal("the tenant's owner must be allowed to declare its residency")
	}
}

// TestBundlePlatformOperatorDeclaresBoundTenant proves ADR-0067: a tenant-scoped
// platform_operator may declare for the tenant it is bound to — the principal's
// tenant equals the tenant the declaration is about (SPEC-0043 AC7).
func TestBundlePlatformOperatorDeclaresBoundTenant(t *testing.T) {
	pdp := bundlePDP(t)
	if !decideAllowed(t, pdp, declareRequest("acme", "operator-1", []string{"platform_operator"}, tenantResource("acme"))) {
		t.Fatal("a platform_operator bound to the tenant must be allowed to declare its residency")
	}
}

// TestBundleNonOwnerTenantRolesRefused proves every non-owner tenant role is
// refused: the declaration stays an owner-or-platform-operator act (SPEC-0043
// AC7).
func TestBundleNonOwnerTenantRolesRefused(t *testing.T) {
	pdp := bundlePDP(t)
	for _, roles := range [][]string{
		{"member"},
		{"auditor"},
		{"developer"},
		{}, // anonymous
	} {
		if decideAllowed(t, pdp, declareRequest("acme", "actor-1", roles, tenantResource("acme"))) {
			t.Fatalf("roles %v must not declare residency", roles)
		}
	}
}

// TestBundlePlatformOperatorTenantMismatchRefused proves there is no cross-tenant
// path: a platform_operator whose principal tenant differs from the tenant the
// declaration is about is refused (ADR-0046 decision 2, SPEC-0043 AC7).
func TestBundlePlatformOperatorTenantMismatchRefused(t *testing.T) {
	pdp := bundlePDP(t)
	// The operator is bound to globex (subject tenant) but asks about acme.
	req := policyapi.Request{
		TenantID: "acme",
		Subject:  policyapi.Subject{ID: "operator-1", TenantID: "globex", Roles: []string{"platform_operator"}},
		Action:   platformaudit.ActionResidencyDeclarationSet,
		Resource: tenantResource("acme"),
	}
	if decideAllowed(t, pdp, req) {
		t.Fatal("a platform_operator bound to another tenant must not declare for this one")
	}
}

// TestBundleDeclarationOnlyAboutTenant proves the action is asked about the tenant
// kind only: any other resource kind is refused (SPEC-0043 AC7).
func TestBundleDeclarationOnlyAboutTenant(t *testing.T) {
	pdp := bundlePDP(t)
	for _, res := range []policyapi.Resource{
		{Type: "repository", ID: "repo-1"},
		{Type: "data_plane", ID: "plane-1"},
	} {
		if decideAllowed(t, pdp, declareRequest("acme", "owner-1", []string{"owner"}, res)) {
			t.Fatalf("declaring residency about a %s must be refused", res.Type)
		}
	}
}

// TestBundleOneAuditRecordPerActAndRefusal is SPEC-0043 AC1's audit half, proved
// end-to-end against the real bundle: an allowed declaration appends exactly one
// witnessed record and no denial event, while a PDP-refused declaration appends
// exactly one witnessed DENIED record naming the verified actor and previous and
// new pinning — beside the decision point's generic PolicyDecisionDenied event,
// which is the policy_decisions section's platform-wide log, not the residency
// record. Every act and every refusal leaves exactly one residency record,
// never zero and never two.
func TestBundleOneAuditRecordPerActAndRefusal(t *testing.T) {
	dir, ok := governanceBundleDir()
	if !ok {
		t.Skip("governance/policies not checked out beside backend/; the bundle proof needs both repos")
	}
	events := bus.NewInProcess()
	pdp, err := policy.NewOPADecisionPoint(dir, events)
	if err != nil {
		t.Fatalf("the real governance bundle does not load: %v", err)
	}
	var denials []platformaudit.PolicyDecisionDenied
	events.Subscribe(platformaudit.EventAudit, func(_ context.Context, e bus.Event) error {
		if d, ok := e.(platformaudit.PolicyDecisionDenied); ok {
			denials = append(denials, d)
		}
		return nil
	})
	wit := &fakeWitness{}
	svc := New(pdp, wit, memory.New(), api.Config{Now: time.Now}, nil)
	ctx := tenancy.WithTenant(context.Background(), tenancy.ID("acme"))

	// The allowed act: exactly one witnessed declaration record, no denial event.
	if _, err := svc.Declare(ctx, "acme", "owner-1", []string{"owner"}, "gke", "europe-west1"); err != nil {
		t.Fatalf("owner declare: %v", err)
	}
	if len(wit.entries) != 1 {
		t.Fatalf("an allowed declaration appends exactly one record, got %d", len(wit.entries))
	}
	if len(denials) != 0 {
		t.Fatalf("an allowed declaration publishes no denial event, got %d", len(denials))
	}

	// The refused act: exactly one witnessed DENIED declaration record, beside the
	// PDP's generic denial event.
	if _, err := svc.Declare(ctx, "acme", "member-1", []string{"member"}, "aws", "us-east1"); !errors.Is(err, api.ErrResidencyUnavailable) {
		t.Fatalf("member declare = %v, want the coarse refusal", err)
	}
	if len(wit.entries) != 2 {
		t.Fatalf("a refused declaration appends exactly one residency record, got %d entries", len(wit.entries))
	}
	refusal := wit.entries[1]
	if refusal.Action != platformaudit.ActionResidencyDeclarationSet || !refusal.Denied || refusal.ActorID != "member-1" {
		t.Fatalf("the refusal record must be a DENIED declaration naming the verified actor: %+v", refusal)
	}
	if refusal.Detail[platformaudit.DetailResidencyPinnedCloud] != "aws" ||
		refusal.Detail[platformaudit.DetailResidencyPreviousCloud] != "gke" {
		t.Fatalf("the refusal record names attempted and previous pinning: %+v", refusal.Detail)
	}
	if len(denials) != 1 {
		t.Fatalf("a refused declaration publishes exactly one generic denial event, got %d", len(denials))
	}
	if denials[0].DeniedAction != platformaudit.ActionResidencyDeclarationSet || denials[0].TenantID != "acme" || denials[0].ActorID != "member-1" {
		t.Fatalf("the generic denial event must name the action, tenant and verified actor: %+v", denials[0])
	}

	// AC7's distinction (ADR-0067 decision 3): a tenant-scoped platform
	// operator declares — allowed by the grant rule — and its record's
	// granted role names the vendor act, where the owner's record names the
	// tenant's own.
	if _, err := svc.Declare(ctx, "acme", "operator-1", []string{"platform_operator"}, "aws", "us-east1"); err != nil {
		t.Fatalf("platform_operator declare: %v", err)
	}
	if len(wit.entries) != 3 {
		t.Fatalf("a third act appends exactly one more record, got %d entries", len(wit.entries))
	}
	operatorRec := wit.entries[2]
	if operatorRec.Denied || operatorRec.ActorID != "operator-1" {
		t.Fatalf("the operator's record must be an ALLOWED declaration naming the verified actor: %+v", operatorRec)
	}
	//arch:allow-inline-authz test asserts an audit label, decides no access
	if got := wit.entries[0].Detail[platformaudit.DetailResidencyGrantedRole]; got != "owner" {
		t.Fatalf("the owner's record names granted_role owner, got %q", got)
	}
	if got := operatorRec.Detail[platformaudit.DetailResidencyGrantedRole]; got != "platform_operator" {
		t.Fatalf("the operator's record names granted_role platform_operator, got %q", got)
	}
}
