// Package opa evaluates authorization decisions against an OPA bundle (ADR-0006, SPEC-0002).
//
// This module has no `internal/domain`, and that is the honest shape rather than an omission. The
// Policy context's domain is the rule set, and the rule set lives in `governance/policies` because
// invariant 21 says decisions and shared surface have exactly one home. What is left here is an
// adapter: load the bundle someone else authored, evaluate it, and map between its document shape
// and this repo's port. Putting a `domain` package here would mean writing authorization rules in
// Go, which is the thing ADR-0006 exists to stop.
//
// The bundle arrives as a directory path from configuration (invariant 13), never `go:embed`-ed. A
// bundle compiled into this binary would be a second copy of the rules in a repo that does not own
// them, and it would make every policy change a backend release.
package opa

import (
	"context"
	"errors"
	"fmt"

	"github.com/gitfrok/backend/modules/policy/api"
	"github.com/gitfrok/backend/platform/ids"
	"github.com/open-policy-agent/opa/v1/bundle"
	"github.com/open-policy-agent/opa/v1/loader"
	"github.com/open-policy-agent/opa/v1/rego"
)

// decisionQuery is the single document the PDP evaluates.
//
// One query, not two reads of `allow` and `reason`: the policy defines `decision` as a total
// document (both members have defaults), so this is defined for every conceivable input including
// an empty one. That totality is what lets this adapter treat an *undefined* result as a bug in
// the bundle rather than as an answer it has to interpret — and the only safe interpretation of
// "no answer" is deny, which is a decision the policy should be making for itself.
const decisionQuery = "data.gitsaas.authz.decision"

// ErrNoRevision reports a bundle with no manifest revision.
//
// Refusing it is not pedantry. The revision is what a PEP keys its decision cache on
// (SPEC-0002 AC3): with an empty one, every cached decision is keyed on the same empty string and
// a policy change invalidates nothing, so a tightened rule quietly does not apply until each
// cache's TTL happens to lapse. That failure is silent and indistinguishable from the policy never
// having been changed.
var ErrNoRevision = errors.New("opa: bundle manifest declares no revision")

// ErrUndefinedDecision reports that the query returned no result — the bundle loaded, but does not
// define `decision` as the policy contract requires.
var ErrUndefinedDecision = errors.New("opa: policy returned no decision")

// PDP is the OPA-backed decision point. Safe for concurrent use: the prepared query is immutable
// after construction and rego evaluation does not mutate it.
type PDP struct {
	query    rego.PreparedEvalQuery
	revision string
	// modules records which bundle files were compiled in, keyed by path. Kept so the loader's
	// exclusions are assertable rather than assumed.
	modules map[string]struct{}
}

// New loads the bundle at dir and prepares it for evaluation.
//
// Everything that can go wrong with a policy bundle goes wrong here, at wiring time, rather than
// on the first request. A PDP that starts with an unusable bundle would deny every request in the
// system, which reaches an operator as a total outage with no obvious cause; refusing to construct
// reaches them as a failed rollout naming the file.
func New(dir string) (*PDP, error) {
	// _test.rego files are governance's tests OF the policy, not part of what ships. They also
	// reference rules that only exist to be tested, so including them can fail compilation.
	dl := bundle.NewDirectoryLoader(dir).WithFilter(loader.GlobExcludeName("*_test.rego", 1))

	b, err := bundle.NewCustomReader(dl).Read()
	if err != nil {
		return nil, fmt.Errorf("opa: reading bundle from %s: %w", dir, err)
	}
	if b.Manifest.Revision == "" {
		return nil, fmt.Errorf("opa: bundle at %s: %w", dir, ErrNoRevision)
	}

	modules := make(map[string]struct{}, len(b.Modules))
	for _, m := range b.Modules {
		modules[m.Path] = struct{}{}
	}

	// Prepared once. Compiling Rego per request would put the policy compiler on the hot path of
	// every authorized action, and SPEC-0002 asks for a p99 of a few milliseconds.
	query, err := rego.New(
		rego.Query(decisionQuery),
		rego.ParsedBundle("policy", &b),
	).PrepareForEval(context.Background())
	if err != nil {
		return nil, fmt.Errorf("opa: preparing %s from %s: %w", decisionQuery, dir, err)
	}

	return &PDP{query: query, revision: b.Manifest.Revision, modules: modules}, nil
}

// Decide evaluates one request. It implements api.DecisionPoint.
//
// On any error the returned Decision is the zero value, whose Allowed is false. That is stated in
// the port's contract and enforced here by never populating the struct before evaluation succeeds:
// ignoring the error is the most common way an authorization check gets bypassed, and it must not
// be a way to get a permissive answer.
func (p *PDP) Decide(ctx context.Context, req api.Request) (api.Decision, error) {
	rs, err := p.query.Eval(ctx, rego.EvalInput(inputOf(req)))
	if err != nil {
		return api.Decision{}, fmt.Errorf("opa: evaluating %s: %w", decisionQuery, err)
	}
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return api.Decision{}, fmt.Errorf("opa: %s at revision %s: %w", decisionQuery, p.revision, ErrUndefinedDecision)
	}

	doc, ok := rs[0].Expressions[0].Value.(map[string]any)
	if !ok {
		return api.Decision{}, fmt.Errorf("opa: %s returned %T, want an object with allow and reason",
			decisionQuery, rs[0].Expressions[0].Value)
	}

	// A missing or non-bool `allow` is a malformed policy, not a permissive one. Reading it
	// through a checked assertion means the zero value — false — is what a malformed document
	// yields, and the error says so rather than letting it pass as a denial nobody investigates.
	allowed, ok := doc["allow"].(bool)
	if !ok {
		return api.Decision{}, fmt.Errorf("opa: %s returned allow=%v (%T), want a bool",
			decisionQuery, doc["allow"], doc["allow"])
	}
	reason, _ := doc["reason"].(string)

	return api.Decision{
		Allowed:        allowed,
		Reason:         reason,
		PolicyRevision: p.revision,
		DecisionID:     ids.NewULID(),
	}, nil
}

// Revision reports the loaded bundle's revision.
func (p *PDP) Revision() string { return p.revision }

// inputOf maps the port's request onto the document the policy evaluates.
//
// The key names are part of the contract with governance/policies and with
// contracts/proto/policy/v1 — all three are the same document, and renaming a key here silently
// changes what the policy sees. A dropped key is the dangerous direction: the policy still returns
// a decision, so the system keeps answering, just to a different question than it was asked.
func inputOf(req api.Request) map[string]any {
	ctxAttrs := req.Context
	if ctxAttrs == nil {
		// Rego handles a null here fine, but an empty object keeps the document shape identical
		// whether or not a caller passed attributes — one less way for two equivalent requests to
		// look different to a policy, or to a cache keyed on this shape.
		ctxAttrs = map[string]string{}
	}
	roles := req.Subject.Roles
	if roles == nil {
		roles = []string{}
	}

	return map[string]any{
		"tenant_id": req.TenantID,
		"subject": map[string]any{
			"id":        req.Subject.ID,
			"tenant_id": req.Subject.TenantID,
			"roles":     roles,
		},
		"action": req.Action,
		"resource": map[string]any{
			"type": req.Resource.Type,
			"id":   req.Resource.ID,
		},
		"context": ctxAttrs,
	}
}
