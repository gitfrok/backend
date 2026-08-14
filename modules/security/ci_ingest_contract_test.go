package security_test

import (
	"context"
	"errors"
	"testing"
	"time"

	policyapi "github.com/gitfrok/backend/modules/policy/api"
	"github.com/gitfrok/backend/modules/security"
	"github.com/gitfrok/backend/modules/security/api"
	"github.com/gitfrok/backend/platform/bus"
)

// allowPDP permits everything and counts decisions, so a test can prove a
// request was refused BEFORE any policy decision.
type allowPDP struct{ decided int }

func (p *allowPDP) Decide(_ context.Context, _ policyapi.Request) (policyapi.Decision, error) {
	p.decided++
	return policyapi.Decision{Allowed: true, DecisionID: "dec-1", PolicyRevision: "rev-1"}, nil
}

// contractChunk is one minimal, otherwise-valid ingest chunk whose request ID
// is the value under test. startOffset makes each call a distinct scan, so
// repeated ingests do not collide on one scan's batch lifecycle.
func contractChunk(requestID string, startOffset time.Duration) api.IngestChunk {
	base := time.Date(2026, 8, 14, 10, 0, 0, 0, time.UTC)
	return api.IngestChunk{
		Context: api.Context{
			TenantID: "t-1", RepositoryID: "r-1", ActorID: "actor-1", RequestID: requestID,
		},
		Revision: "rev-abc",
		Scan: api.Scan{
			ScannerClass: api.ScannerClassSAST, ToolName: "semgrep", ToolVersion: "1.99.0",
			StartedAt: base.Add(startOffset), EndedAt: base.Add(startOffset + time.Minute),
		},
		Findings: []api.RawFinding{{
			RuleID:   "py-eval",
			Severity: api.SeverityHigh,
			Location: api.Location{ArtifactPath: "app.py", EnclosingContent: "def handler():"},
		}},
		ChunkIndex: 0,
		FinalChunk: true,
	}
}

// TestReservedRequestIDNamespacesAreRefusedAtTheWireBoundary is the AC6
// contract (SPEC-0037): the CI ingest subscriber derives its request IDs in
// the "ci:" namespace exactly as the audit machinery owns "audit:", and a
// WIRE caller squatting either namespace is refused the same way — malformed
// for ingest, invalid context for the reads, and before any PDP decision or
// write. Only the plane's own in-process core may mint those IDs.
func TestReservedRequestIDNamespacesAreRefusedAtTheWireBoundary(t *testing.T) {
	for i, requestID := range []string{
		"audit:req-1",                   // the pre-existing audit namespace
		"ci:job:attempt:sast",           // the CI subscriber's derived shape
		"ci:01M00000000000000000000000", // any id beginning with the prefix
	} {
		pdp := &allowPDP{}
		svc := security.New(pdp, bus.NewInProcess())

		if _, err := svc.IngestScanResults(context.Background(), contractChunk(requestID, time.Duration(i)*time.Hour)); !errors.Is(err, api.ErrMalformed) {
			t.Fatalf("ingest with request ID %q = %v, want ErrMalformed", requestID, err)
		}
		if pdp.decided != 0 {
			t.Fatalf("request ID %q reached the PDP; it must be refused before any decision", requestID)
		}

		// The same namespace invalidates every context that carries it, so the
		// tenant-wide reads deny it coarsely.
		_, err := svc.GetFindingsSummary(context.Background(), api.SummaryRequest{
			Context: api.Context{TenantID: "t-1", ActorID: "actor-1", RequestID: requestID},
		})
		if !errors.Is(err, api.ErrDenied) {
			t.Fatalf("summary with request ID %q = %v, want ErrDenied", requestID, err)
		}
	}
}

// TestOrdinaryRequestIDsAreStillAdmitted is the control: the refusal is the
// reserved PREFIXES, not a new blanket shape rule — an ordinary caller ID
// still ingests to completion through the same public surface.
func TestOrdinaryRequestIDsAreStillAdmitted(t *testing.T) {
	pdp := &allowPDP{}
	svc := security.New(pdp, bus.NewInProcess())
	for i, requestID := range []string{"req-1", "ci-ingest-without-colon", "auditor:shaped-alike"} {
		res, err := svc.IngestScanResults(context.Background(), contractChunk(requestID, time.Duration(i)*time.Hour))
		if err != nil || !res.Completed {
			t.Fatalf("ingest with request ID %q = %+v, %v; want completion", requestID, res, err)
		}
	}
}
