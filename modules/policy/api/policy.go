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

import (
	"context"
	"errors"
	"time"
)

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
	// InputDigest is the digest over the canonicalized input this decision was made over
	// (SPEC-0030). Server-produced: an auditor re-derives it from the recorded input, and no
	// caller has a way to supply it.
	InputDigest string
	// Mode is the evaluation mode of this decision (SPEC-0029 AC2, SPEC-0030): ENFORCED for
	// Decide, DRY_RUN only from a dry-run evaluation. Server-produced — no request carries it.
	Mode Mode
	// ReliedUponTriage lists the ACCEPT/FALSE_POSITIVE triage record IDs the security merge gate
	// relied on when it exempted a findings breach (SPEC-0029 AC4). Empty when no exemption was
	// applied. Produced by the policy document itself, so the decision names what it relied on.
	ReliedUponTriage []string
}

// Mode distinguishes an enforced decision from a dry-run one (SPEC-0029 AC2, SPEC-0030). A
// dry-run decision is never an authorization outcome and is labelled wherever it appears, so a
// consumer can never mistake it for an enforced control — and a caller has no way to assert
// either value: no request carries a mode.
type Mode string

const (
	// ModeEnforced: the decision gated a real action and was recorded as a control in the
	// audit trail. This is the only mode Decide produces.
	ModeEnforced Mode = "ENFORCED"
	// ModeDryRun: what a candidate bundle would have decided. It writes no enforcement, mutates
	// no state, and is never consumed as an authorization outcome.
	ModeDryRun Mode = "DRY_RUN"
)

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

// Record is one stored decision, retrievable after the fact (SPEC-0029 AC1, SPEC-0030). It
// carries the provenance the decision was made under and the outcome, but never the rule source
// text: exposing the rules on this surface would be a way to read policy that skipped the
// governance review the bundle went through (G9).
type Record struct {
	// DecisionID, PolicyRevision, InputDigest and Mode are the decision's identity and
	// provenance — all server-produced.
	DecisionID     string
	PolicyRevision string
	InputDigest    string
	Mode           Mode
	// The question that was asked.
	TenantID string
	// The actor the action was attributed to.
	ActorID  string
	Action   string
	Resource Resource
	// The answer, its coarse reason, and when it was given.
	Allowed   bool
	Reason    string
	DecidedAt time.Time
	// The input the decision was made over, preserved so a dry-run can replay it (SPEC-0029
	// AC2). SubjectRoles and Context are the request's own values; they are inputs to policy,
	// never caller claims about the decision.
	SubjectTenantID string
	SubjectRoles    []string
	Context         map[string]string
}

// HistoricalRange delimits the historical decision inputs a dry-run replays. A zero bound leaves
// that dimension unbounded; the service enforces the overall result cap (SPEC-0030).
type HistoricalRange struct {
	// Action restricts to one action, e.g. "merge_request.merge". Empty replays every action.
	Action string
	// Resource restricts to one resource; zero replays every resource.
	Resource Resource
	// From and To are inclusive bounds on when the replayed decisions were recorded. Zero is
	// unbounded on that side.
	From time.Time
	To   time.Time
}

// DryRunRequest asks the service to replay a bounded range of historical decision inputs through
// a candidate bundle (SPEC-0029 AC2, SPEC-0030). The caller names WHICH bundle and WHICH
// history; it supplies no provenance and no outcome — every one of those is produced by the
// server for each would-be decision.
type DryRunRequest struct {
	TenantID string
	// CandidateBundleRef references reviewed policy code (SPEC-0029 reading A): a reference
	// names reviewed, immutable code — never inline content — so a dry-run cannot become a way
	// to evaluate policy that skipped review.
	CandidateBundleRef string
	Range              HistoricalRange
	// MaxResults caps the would-be decisions one dry-run may produce. A range that would exceed
	// it is rejected rather than silently truncated (SPEC-0030 open question). Zero or negative
	// means the server default.
	MaxResults int
}

// ErrInvalidRequest reports a dry-run or retrieval request that is malformed or asks for more
// than its cap (SPEC-0030: rejected, never silently truncated).
var ErrInvalidRequest = errors.New("policy: invalid request")

// ErrNotFound reports that no decision record exists in this tenant's store. Retrieval maps it
// to the same coarse shape as a cross-tenant read (invariant 1, SPEC-0030 AC6): a caller cannot
// distinguish a nonexistent decision from another tenant's.
var ErrNotFound = errors.New("policy: decision record not found")

// ErrNoCandidateLoader reports a dry-run on a plane with no candidate-bundle loader configured.
// Refusing is the only honest answer: a dry-run that cannot load its candidate must not return
// results computed from something else.
var ErrNoCandidateLoader = errors.New("policy: no candidate bundle loader configured")

// DecisionRecords is the provenance surface of the Policy context (SPEC-0029, SPEC-0030):
// dry-run evaluation over history and retrieval of recorded decisions. Every value it returns
// is server-produced; a caller can name a bundle and a range, never an outcome.
type DecisionRecords interface {
	// EvaluateDryRun replays the tenant's recorded ENFORCED decision inputs within req.Range
	// through the candidate bundle and returns one would-be decision per input, each labelled
	// ModeDryRun and carrying the candidate's revision. It writes no enforcement and never
	// produces an authorization outcome; the would-be decisions are themselves recorded, as
	// DRY_RUN, so they stay distinguishable everywhere they appear (SPEC-0030 AC3).
	EvaluateDryRun(ctx context.Context, req DryRunRequest) ([]Decision, error)
	// GetDecision retrieves one recorded decision by the ID the PDP assigned, within the tenant
	// that made it. A missing or cross-tenant ID yields ErrNotFound — one coarse shape.
	GetDecision(ctx context.Context, tenantID, decisionID string) (Record, error)
}

// Service is the Policy context's full in-process surface: the decision point plus its
// provenance. cmd/ holds this one value and hands each half to whichever door needs it
// (ADR-0025).
type Service interface {
	DecisionPoint
	DecisionRecords
}
