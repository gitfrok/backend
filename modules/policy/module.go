// Package policy is the Policy context's composition root (ADR-0025).
//
// See the note in modules/repository/module.go for why a module needs one: cmd/ is told to inject
// concrete implementations, but Go's internal/ rule stops it from naming what it injects.
//
// There is one PDP construction — on a real policy bundle, never a stub. That is deliberate.
// Every other module offers a test adapter so a caller can run without infrastructure; a PDP that
// could be constructed without a policy bundle would be a PDP that answers without consulting
// policy, and the first tired afternoon someone would wire it into something real. If a test needs
// decisions it does not care about, it should implement api.DecisionPoint itself and say so.
//
// The decision RECORD store, by contrast, follows the same split as the other contexts: planes
// without a database URL run on the in-memory store (dev and tests), configured planes run on the
// Postgres adapter. Swapping stores is a change to the composition line and nothing else.
package policy

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	policyv1 "github.com/gitfrok/backend/gen/proto/policy/v1"
	"github.com/gitfrok/backend/modules/policy/api"
	policygrpc "github.com/gitfrok/backend/modules/policy/internal/adapters/grpc"
	policyopa "github.com/gitfrok/backend/modules/policy/internal/adapters/opa"
	policypg "github.com/gitfrok/backend/modules/policy/internal/adapters/postgres"
	"github.com/gitfrok/backend/modules/policy/internal/app"
	"github.com/gitfrok/backend/platform/bus"
	"github.com/gitfrok/backend/platform/db"
)

// NewOPADecisionPoint assembles the PDP on the OPA bundle at bundleDir, auditing its refusals
// to b and recording every decision on the in-memory store: dev and tests, and any plane
// without a database URL.
//
// bundleDir is per-environment configuration (invariant 13) pointing at a copy of
// governance/policies — never a path compiled in, and never embedded, because a bundle inside this
// binary would be a second copy of rules this repo does not own (invariant 21).
//
// It returns an error rather than panicking, and the caller in cmd/ is expected to treat that as
// fatal: a plane that starts without a working PDP denies every request in the system, which
// reaches an operator as an unexplained total outage instead of a failed rollout.
func NewOPADecisionPoint(bundleDir string, b bus.Bus) (api.Service, error) {
	return assemble(bundleDir, b, app.NewMemoryStore())
}

// NewOPADecisionPointWithPostgres assembles the PDP recording its decisions on the Postgres
// adapter: the durable, RLS-isolated trail a configured plane needs for decisions that serve
// as evidence (SPEC-0029 AC1, SPEC-0030).
func NewOPADecisionPointWithPostgres(bundleDir string, b bus.Bus, pool *db.Pool) (api.Service, error) {
	return assemble(bundleDir, b, policypg.New(pool))
}

func assemble(bundleDir string, b bus.Bus, store app.RecordStore) (api.Service, error) {
	evaluator, err := policyopa.New(bundleDir)
	if err != nil {
		return nil, fmt.Errorf("policy: loading bundle: %w", err)
	}
	svc := app.New(evaluator, b, store).WithCandidateLoader(candidateLoader(bundleDir))
	return svc, nil
}

// candidateLoader resolves a dry-run's candidate bundle reference (SPEC-0029 reading A).
//
// Reading A says a reference names reviewed, immutable policy code in governance/ — never
// inline content. On a plane the governance checkout arrives as the bundle mount, so a
// reference is resolved INSIDE the configured bundle root: the same reviewed tree the active
// bundle loaded from, addressed relative to it. The loader refuses anything that would climb
// out of that root — an absolute path or a ".." escape — because a candidate outside the
// reviewed mount would be policy that skipped review, which is precisely what a dry-run must
// not become a way to evaluate.
func candidateLoader(bundleRoot string) func(ctx context.Context, ref string) (api.DecisionPoint, error) {
	root := filepath.Clean(bundleRoot)
	return func(_ context.Context, ref string) (api.DecisionPoint, error) {
		if ref == "" {
			return nil, fmt.Errorf("%w: empty candidate bundle reference", api.ErrInvalidRequest)
		}
		if filepath.IsAbs(ref) {
			return nil, fmt.Errorf("%w: candidate reference must be relative to the bundle root", api.ErrInvalidRequest)
		}
		dir := filepath.Clean(filepath.Join(root, ref))
		// Clean collapses ".." segments; the prefix check then proves nothing escaped the
		// root. String-prefix alone would admit a sibling "policies-evil" of "policies", so
		// the separator is part of the comparison.
		if dir != root && !strings.HasPrefix(dir, root+string(filepath.Separator)) {
			return nil, fmt.Errorf("%w: candidate reference escapes the bundle root", api.ErrInvalidRequest)
		}
		// A symlink inside the mount could still point out of it, so resolve links on both
		// ends and re-check containment on the real paths before anything is loaded.
		realRoot, err := filepath.EvalSymlinks(root)
		if err != nil {
			return nil, fmt.Errorf("policy: resolving bundle root: %w", err)
		}
		realDir, err := filepath.EvalSymlinks(dir)
		if err != nil {
			return nil, fmt.Errorf("%w: candidate reference does not resolve", api.ErrInvalidRequest)
		}
		if realDir != realRoot && !strings.HasPrefix(realDir, realRoot+string(filepath.Separator)) {
			return nil, fmt.Errorf("%w: candidate reference escapes the bundle root", api.ErrInvalidRequest)
		}
		if _, err := os.Stat(filepath.Join(realDir, ".manifest")); err != nil {
			return nil, fmt.Errorf("%w: no bundle at candidate reference %q", api.ErrInvalidRequest, ref)
		}
		return policyopa.New(realDir)
	}
}

// NewGRPCServer exposes the decision ports over contracts/proto/policy/v1 for out-of-process
// PEPs — the BFF today. In-process modules take api.DecisionPoint directly and never dial this.
//
// It takes the ports rather than a concrete type, so extracting Policy into its own service
// (ADR-0026) changes cmd/ and nothing else. records may be nil: Decide still serves, and the
// provenance RPCs report Unimplemented rather than pretending a trail exists.
func NewGRPCServer(pdp api.DecisionPoint, records api.DecisionRecords) policyv1.PolicyDecisionPointServer {
	return policygrpc.NewServer(pdp, records)
}
