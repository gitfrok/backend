// Package api is the Policy context's in-process surface (ADR-0025, SPEC-0002).
//
// Every authorization answer in the process comes through this port. Invariant 2 says no service
// performs an inline permission check, so this is not the recommended way to ask — it is the only
// one, and `internal/arch`'s inline-authz fitness function fails a build that grows another.
//
// The port is deliberately one method. There is no "may this subject do any of these", no
// "what may this subject do", and no way to fetch the rules: each of those would let a caller
// assemble its own decision out of parts, which is the same inline permission logic wearing a
// different shape. Ask about one action and act on the answer.
//
// SPEC-0002, T-0005. ADR-0006 (policy-as-code, deny-by-default).
package api

import "context"

// Subject is the principal an action is attributed to.
//
// Roles are carried in rather than looked up, which is what keeps a decision a pure function of
// its request — the property that makes it cacheable at all (SPEC-0002 AC3) and keeps the PDP free
// of a dependency on a running directory service.
type Subject struct {
	// ID is the stable principal identifier. Empty means anonymous, which is a legitimate thing
	// to ask about: policy decides what an anonymous caller may do rather than the caller guessing.
	ID string
	// TenantID is the tenant this subject belongs to. Policy compares it against Request.TenantID,
	// so holding a role in one tenant is not holding it in another (invariant 1).
	TenantID string
	// Roles the subject holds within its tenant.
	Roles []string
}

// Resource is what the action would be performed on.
type Resource struct {
	// Type is the kind of thing — "repository". A string for the same reason Action is one.
	Type string
	// ID is an opaque identifier within that type; never a URL and never the contents.
	ID string
}

// Request asks whether one action is permitted. It mirrors DecideRequest in
// contracts/proto/policy/v1 field for field — the same document, in-process.
type Request struct {
	// TenantID scopes the decision. Every decision is tenant-scoped (invariant 1); a request
	// without one is denied by policy rather than evaluated globally.
	TenantID string
	Subject  Subject
	// Action is the dotted vocabulary from governance/policies — "repo.read". Open by design: a
	// new protected action should be additive, never a coordinated deploy across every PEP.
	Action   string
	Resource Resource
	// Context carries additional request attributes policy may consider. Small, non-sensitive
	// values; never credentials and never resource contents.
	Context map[string]string
}

// Decision is the PDP's answer.
type Decision struct {
	// Allowed is the answer. The zero value is false, so a Decision that was never populated —
	// by a bug, an early return, a partially-decoded response — denies. That is not an accident
	// of Go's zero values; it is the reason this is a bool and not a three-state enum.
	Allowed bool
	// Reason is safe to return to the caller and deliberately coarse: one denial reason for every
	// cause, so repeated probing cannot enumerate the tenants and roles deny-by-default hides.
	// The specific cause goes to the audit trail.
	Reason string
	// PolicyRevision is the bundle revision that produced this decision. A PEP keys its cache on
	// it, so a policy change invalidates every cached decision without anyone remembering to
	// flush anything.
	PolicyRevision string
	// DecisionID is a ULID correlating this decision with the audit event recording it. Assigned
	// by the PDP: a caller able to name its own decision could also claim another's outcome.
	DecisionID string
}

// DecisionPoint evaluates one authorization question against the loaded policy bundle.
type DecisionPoint interface {
	// Decide answers whether req is permitted.
	//
	// A non-nil error is NOT a denial to be inspected and worked around — it means no decision
	// was reached, and the returned Decision is the zero value, which denies. Callers must treat
	// both the error and the Decision as refusals; there is no third outcome in which proceeding
	// is correct (ADR-0006).
	Decide(ctx context.Context, req Request) (Decision, error)
}
