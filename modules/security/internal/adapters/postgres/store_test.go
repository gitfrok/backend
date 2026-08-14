package postgres_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gitfrok/backend/modules/security/api"
	"github.com/gitfrok/backend/modules/security/internal/app"
	secpg "github.com/gitfrok/backend/modules/security/internal/adapters/postgres"
	"github.com/gitfrok/backend/platform/db"
	"github.com/gitfrok/backend/platform/ids"
)

// The Postgres adapter's claims are about what the *database* enforces — the
// UNIQUE identity dedup, the INGESTING→COMPLETE check constraint, chunk
// staging visibility, and RLS — so they are tested against a real Postgres.
//
//	kubectl port-forward -n default deploy/postgres 15432:5432
//	TEST_DATABASE_URL='postgres://gitfrok_app:gitfrok_app@127.0.0.1:15432/gitfrok' \
//	  go test ./modules/security/...

// runID makes each invocation use fresh tenants: findings are resolved,
// never deleted, so a suite cannot reset its fixture — the fixture moves.
var runID = fmt.Sprintf("%d", time.Now().UnixNano()%1_000_000_000)

func tenantFor(t *testing.T) string {
	t.Helper()
	safe := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		default:
			return '-'
		}
	}, t.Name())
	if len(safe) > 40 {
		safe = safe[:40]
	}
	return safe + "-" + runID
}

func store(t *testing.T) *secpg.Store {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — needs a Postgres with the T-0022 migration applied")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	t.Cleanup(cancel)
	pool, err := db.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(pool.Close)
	return secpg.New(pool)
}

func params(t *testing.T, scanID, reqID string, final bool, findings ...app.PreparedFinding) app.IngestParams {
	t.Helper()
	start := time.Now().UTC().Truncate(time.Millisecond)
	return app.IngestParams{
		TenantID:     tenantFor(t),
		RepositoryID: "repo-1",
		Revision:     "rev-1",
		Scan: api.Scan{
			ScannerClass: api.ScannerClassSAST, ToolName: "semgrep", ToolVersion: "1.0.0",
			StartedAt: start, EndedAt: start.Add(time.Minute),
		},
		ScanID:     scanID,
		ChunkIndex: 0,
		RequestID:  reqID,
		FinalChunk: final,
		Findings:   findings,
	}
}

func prepared(rule, identity string) app.PreparedFinding {
	return app.PreparedFinding{
		Identity: identity,
		Raw: api.RawFinding{
			RuleID: rule, Severity: api.SeverityHigh,
			Location:            api.Location{ArtifactPath: "a.py", EnclosingContent: "fn-a"},
			Provenance:          []byte(`{"native":true}`),
			ProvenanceMediaType: "application/json",
		},
	}
}

// One final chunk opens findings; a redelivery replays without duplicating
// (SPEC-0025 AC1, the UNIQUE constraint).
func TestIngestDedupAndReplay(t *testing.T) {
	s := store(t)
	ctx := context.Background()
	scanID := "scan-" + ids.NewULID()
	p := params(t, scanID, "req-1", true, prepared("rule-a", "fnd-"+ids.NewULID()))

	out, err := s.IngestChunk(ctx, p)
	if err != nil || !out.Completed || out.Replayed || out.FindingsRecorded != 1 {
		t.Fatalf("first ingest: %+v err=%v", out, err)
	}
	if len(out.Opened) != 1 || len(out.Resolved) != 0 {
		t.Fatalf("expected one open: %+v", out)
	}

	replay, err := s.IngestChunk(ctx, p)
	if err != nil || !replay.Replayed || !replay.Completed || replay.FindingsRecorded != 1 {
		t.Fatalf("replay: %+v err=%v", replay, err)
	}

	page, err := s.ListFindings(ctx, p.TenantID, app.ListFilter{RepositoryID: "repo-1", Limit: 10})
	if err != nil || len(page) != 1 {
		t.Fatalf("expected exactly one stored finding after replay, got %d (err=%v)", len(page), err)
	}
	if !strings.EqualFold(string(page[0].Provenance), `{"native":true}`) {
		t.Fatalf("provenance round-trip: %q", page[0].Provenance)
	}
}

// Chunk visibility: nothing reads until the final chunk completes, and the
// scan state machine refuses further chunks after completion.
func TestChunkVisibilityAndStateMachine(t *testing.T) {
	s := store(t)
	ctx := context.Background()
	scanID := "scan-" + ids.NewULID()

	first := params(t, scanID, "req-1", false, prepared("rule-a", "fnd-"+ids.NewULID()))
	first.FinalChunk = false
	out, err := s.IngestChunk(ctx, first)
	if err != nil || out.Completed {
		t.Fatalf("non-final chunk: %+v err=%v", out, err)
	}
	page, err := s.ListFindings(ctx, first.TenantID, app.ListFilter{RepositoryID: "repo-1", Limit: 10})
	if err != nil || len(page) != 0 {
		t.Fatalf("partial batch must be invisible, got %d findings", len(page))
	}

	second := first
	second.ChunkIndex, second.RequestID, second.FinalChunk = 1, "req-2", true
	second.Findings = []app.PreparedFinding{prepared("rule-b", "fnd-"+ids.NewULID())}
	out, err = s.IngestChunk(ctx, second)
	if err != nil || !out.Completed {
		t.Fatalf("final chunk: %+v err=%v", out, err)
	}

	// A late chunk against a COMPLETE scan is refused.
	late := second
	late.ChunkIndex, late.RequestID = 2, "req-3"
	if _, err := s.IngestChunk(ctx, late); err == nil {
		t.Fatalf("a chunk after completion must be refused")
	}
}

// Resolution: a second scan by the same tool no longer reporting a finding
// resolves it; the record survives (SPEC-0024 AC9).
func TestResolveNotDelete(t *testing.T) {
	s := store(t)
	ctx := context.Background()
	identity := "fnd-" + ids.NewULID()
	tenant := tenantFor(t)
	start := time.Now().UTC().Truncate(time.Millisecond)

	mk := func(scanID, reqID string, findings ...app.PreparedFinding) app.IngestParams {
		return app.IngestParams{
			TenantID: tenant, RepositoryID: "repo-1", Revision: "rev-1",
			Scan: api.Scan{
				ScannerClass: api.ScannerClassSAST, ToolName: "semgrep", ToolVersion: "1.0.0",
				StartedAt: start, EndedAt: start.Add(time.Minute),
			},
			ScanID: scanID, ChunkIndex: 0, RequestID: reqID, FinalChunk: true, Findings: findings,
		}
	}

	scan1 := "scan-" + ids.NewULID()
	if _, err := s.IngestChunk(ctx, mk(scan1, "r1",
		prepared("rule-a", identity), prepared("rule-b", "fnd-"+ids.NewULID()))); err != nil {
		t.Fatalf("scan 1: %v", err)
	}
	scan2 := "scan-" + ids.NewULID()
	out, err := s.IngestChunk(ctx, mk(scan2, "r2", prepared("rule-a", identity)))
	if err != nil || !out.Completed {
		t.Fatalf("scan 2: %+v err=%v", out, err)
	}
	if len(out.Resolved) != 1 || len(out.Opened) != 0 {
		t.Fatalf("expected one resolution, got %+v", out)
	}

	page, err := s.ListFindings(ctx, tenant, app.ListFilter{RepositoryID: "repo-1", Limit: 10})
	if err != nil || len(page) != 2 {
		t.Fatalf("resolved findings must remain stored, got %d", len(page))
	}
	var resolvedCount int
	for _, f := range page {
		if f.Lifecycle == api.LifecycleResolved {
			resolvedCount++
		}
	}
	if resolvedCount != 1 {
		t.Fatalf("expected exactly one RESOLVED row, got %d", resolvedCount)
	}
}

// Cross-tenant invisibility: another tenant sees nothing of this one's
// findings (RLS, invariant 1).
func TestTenantIsolation(t *testing.T) {
	s := store(t)
	ctx := context.Background()
	p := params(t, "scan-"+ids.NewULID(), "req-1", true, prepared("rule-a", "fnd-"+ids.NewULID()))
	out, err := s.IngestChunk(ctx, p)
	if err != nil || len(out.Opened) != 1 {
		t.Fatalf("ingest: %+v err=%v", out, err)
	}

	other := p.TenantID + "-other"
	if _, err := s.GetFinding(ctx, other, out.Opened[0].ID); err == nil {
		t.Fatalf("another tenant must not read the finding")
	}
	page, err := s.ListFindings(ctx, other, app.ListFilter{RepositoryID: "repo-1", Limit: 10})
	if err != nil || len(page) != 0 {
		t.Fatalf("another tenant must list nothing, got %d", len(page))
	}
	if _, err := s.GetFinding(ctx, p.TenantID, out.Opened[0].ID); err != nil {
		t.Fatalf("the owning tenant must read its finding: %v", err)
	}
}
