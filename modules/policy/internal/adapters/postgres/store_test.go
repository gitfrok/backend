package postgres_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gitfrok/backend/modules/policy/api"
	policypg "github.com/gitfrok/backend/modules/policy/internal/adapters/postgres"
	"github.com/gitfrok/backend/platform/db"
	"github.com/gitfrok/backend/platform/ids"
	"github.com/gitfrok/backend/platform/tenancy"
)

// The Postgres adapter's claims are about what the *database* enforces — the append-only
// PRIMARY KEY, the mode CHECK constraint, and RLS — so they are tested against a real Postgres.
//
//	kubectl port-forward -n default deploy/postgres 15432:5432
//	TEST_DATABASE_URL='postgres://gitfrok_app:gitfrok_app@127.0.0.1:15432/gitfrok' \
//	  go test ./modules/policy/...

// runID makes each invocation use fresh tenants: records are append-only by design, so a suite
// cannot reset its fixture — the fixture moves.
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

// tenantCtx binds the tenant H1's fail-closed read guard requires before a
// Get or Range is even asked of the database.
func tenantCtx(t *testing.T, tenant string) context.Context {
	t.Helper()
	return tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
}

func store(t *testing.T) *policypg.Store {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — needs a Postgres with the T-0025 migration applied")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	t.Cleanup(cancel)
	pool, err := db.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(pool.Close)
	return policypg.New(pool)
}

func record(tenantID string, at time.Time) api.Record {
	return api.Record{
		DecisionID:      ids.NewULID(),
		PolicyRevision:  "0.6.0",
		InputDigest:     "sha256:test",
		Mode:            api.ModeEnforced,
		TenantID:        tenantID,
		ActorID:         "u-1",
		Action:          "merge_request.merge",
		Resource:        api.Resource{Type: "merge_request", ID: "mr-1"},
		Allowed:         false,
		Reason:          "denied",
		DecidedAt:       at,
		SubjectTenantID: tenantID,
		SubjectRoles:    []string{"owner"},
		Context:         map[string]string{"protocol": "https"},
	}
}

// Append then Get: every stored field survives the round trip, because a record that lost a
// field would be evidence for a different decision than the one made.
func TestAppendAndGetRoundTrip(t *testing.T) {
	s := store(t)
	tenant := tenantFor(t)
	want := record(tenant, time.Now().UTC().Truncate(time.Microsecond))

	if err := s.Append(t.Context(), want); err != nil {
		t.Fatalf("Append: %v", err)
	}
	got, err := s.Get(tenantCtx(t, tenant), tenant, want.DecisionID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.DecisionID != want.DecisionID || got.PolicyRevision != want.PolicyRevision ||
		got.InputDigest != want.InputDigest || got.Mode != want.Mode ||
		got.TenantID != want.TenantID || got.ActorID != want.ActorID ||
		got.Action != want.Action || got.Resource != want.Resource ||
		got.Allowed != want.Allowed || got.Reason != want.Reason ||
		got.SubjectTenantID != want.SubjectTenantID {
		t.Errorf("record = %+v, want %+v", got, want)
	}
	if len(got.SubjectRoles) != 1 || got.SubjectRoles[0] != "owner" {
		t.Errorf("SubjectRoles = %v, want [owner]", got.SubjectRoles)
	}
	if got.Context["protocol"] != "https" {
		t.Errorf("Context = %v, want the recorded attributes", got.Context)
	}
	if !got.DecidedAt.Equal(want.DecidedAt) {
		t.Errorf("DecidedAt = %v, want %v", got.DecidedAt, want.DecidedAt)
	}
}

// A decision ID this tenant already recorded cannot be appended again: the schema's PRIMARY KEY
// is the append-only rule, and the adapter must surface it as a refusal, not a silent replay.
func TestDuplicateDecisionIDIsRefused(t *testing.T) {
	s := store(t)
	tenant := tenantFor(t)
	rec := record(tenant, time.Now())

	if err := s.Append(t.Context(), rec); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if err := s.Append(t.Context(), rec); err == nil {
		t.Fatal("a duplicate decision ID was appended twice — the record is no longer append-only")
	}
}

// A cross-tenant read is exactly as not-found as a nonexistent one (SPEC-0030 AC6): one coarse
// shape, so a probe cannot enumerate which decision IDs exist in another tenant.
func TestCrossTenantGetIsNotFound(t *testing.T) {
	s := store(t)
	tenant := tenantFor(t)
	rec := record(tenant, time.Now())
	if err := s.Append(t.Context(), rec); err != nil {
		t.Fatalf("Append: %v", err)
	}

	other := tenant + "-other"
	if _, err := s.Get(tenantCtx(t, other), other, rec.DecisionID); err != api.ErrNotFound {
		t.Errorf("cross-tenant Get = %v, want ErrNotFound — absence and denial are one shape", err)
	}
	if _, err := s.Get(tenantCtx(t, tenant), tenant, ids.NewULID()); err != api.ErrNotFound {
		t.Errorf("nonexistent Get = %v, want the same ErrNotFound", err)
	}
}

// Range replays ENFORCED history only, within bounds, oldest first — and hands back one row
// beyond the limit so the service can reject an over-cap range instead of truncating it.
func TestRangeReplaysEnforcedHistoryWithinBounds(t *testing.T) {
	s := store(t)
	tenant := tenantFor(t)
	base := time.Now().UTC().Truncate(time.Microsecond)

	older := record(tenant, base.Add(-2*time.Hour))
	older.Action = "repo.read"
	within := record(tenant, base.Add(-1*time.Hour))
	within.Action = "merge_request.merge"
	latest := record(tenant, base)
	latest.Action = "merge_request.merge"
	dryRun := record(tenant, base)
	dryRun.Mode = api.ModeDryRun
	dryRun.Action = "merge_request.merge"
	for _, r := range []api.Record{older, within, latest, dryRun} {
		if err := s.Append(t.Context(), r); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}

	got, err := s.Range(tenantCtx(t, tenant), tenant, api.HistoricalRange{
		Action: "merge_request.merge",
		From:   base.Add(-90 * time.Minute),
		To:     base.Add(time.Minute),
	}, 10)
	if err != nil {
		t.Fatalf("Range: %v", err)
	}
	// `within` then `latest`; the older row is below From, and the DRY_RUN row is never replayed.
	if len(got) != 2 || got[0].DecisionID != within.DecisionID || got[1].DecisionID != latest.DecisionID {
		t.Fatalf("Range = %d records [%v], want within-then-latest enforced records",
			len(got), idsOf(got))
	}

	// One beyond the limit comes back, so an over-cap range is detectable.
	all, err := s.Range(tenantCtx(t, tenant), tenant, api.HistoricalRange{}, 2)
	if err != nil {
		t.Fatalf("Range: %v", err)
	}
	if len(all) != 3 {
		t.Errorf("Range(limit=2) returned %d records, want limit+1 so overflow is detectable", len(all))
	}
}

func idsOf(rs []api.Record) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.DecisionID
	}
	return out
}
