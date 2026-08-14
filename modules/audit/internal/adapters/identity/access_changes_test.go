package identity

import (
	"context"
	"errors"
	"testing"
	"time"

	auditapi "github.com/gitfrok/backend/modules/audit/api"
	identityapi "github.com/gitfrok/backend/modules/identity/api"
)

// SPEC-0032 assumption / SPEC-0033 AC4: the access-changes section cites the
// immutable audit records Identity&Access appended for every witnessed grant
// lifecycle transition — scope and lifecycle only, never pack contents.

type stubGrants struct {
	transitions []identityapi.GrantTransition
	err         error
	captured    struct {
		tenantID     string
		from, to     time.Time
		repositoryID string
	}
}

func (s *stubGrants) IssueGrant(context.Context, identityapi.GrantContext, identityapi.GrantIssue) (identityapi.AuditorGrant, error) {
	return identityapi.AuditorGrant{}, nil
}

func (s *stubGrants) RevokeGrant(context.Context, identityapi.GrantContext, string) (identityapi.AuditorGrant, error) {
	return identityapi.AuditorGrant{}, nil
}

func (s *stubGrants) ListGrants(context.Context, identityapi.GrantContext, string) ([]identityapi.AuditorGrant, error) {
	return nil, nil
}

func (s *stubGrants) GrantFacts(context.Context, string, string) (identityapi.GrantDecisionFacts, bool, error) {
	return identityapi.GrantDecisionFacts{}, false, nil
}

func (s *stubGrants) GrantTransitions(_ context.Context, tenantID string, from, to time.Time, repositoryID string) ([]identityapi.GrantTransition, error) {
	s.captured.tenantID, s.captured.from, s.captured.to, s.captured.repositoryID = tenantID, from, to, repositoryID
	return s.transitions, s.err
}

var at = time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)

func TestAccessChangesRendersEveryLifecycleKind(t *testing.T) {
	stub := &stubGrants{transitions: []identityapi.GrantTransition{
		{Kind: identityapi.GrantIssued, ChainSeq: 7, RecordHash: "h-7", GrantID: "g-1",
			ActorID: "admin-a", GrantedBy: "admin-a", AuditorPrincipalID: "auditor-1", OccurredAt: at},
		{Kind: identityapi.GrantRevocation, ChainSeq: 9, RecordHash: "h-9", GrantID: "g-1",
			ActorID: "admin-b", GrantedBy: "admin-a", AuditorPrincipalID: "auditor-1", OccurredAt: at.Add(time.Hour)},
		{Kind: identityapi.GrantExpiration, ChainSeq: 12, RecordHash: "h-12", GrantID: "g-2",
			GrantedBy: "admin-a", AuditorPrincipalID: "auditor-2", OccurredAt: at.Add(2 * time.Hour)},
	}}
	source := NewAccessChangesSource(stub)

	from, to := at.Add(-time.Minute), at.Add(3*time.Hour)
	records, err := source.AccessChanges(context.Background(), "tenant-a", from, to, "repo-1")
	if err != nil {
		t.Fatalf("access changes: %v", err)
	}
	if stub.captured.tenantID != "tenant-a" || !stub.captured.from.Equal(from) ||
		!stub.captured.to.Equal(to) || stub.captured.repositoryID != "repo-1" {
		t.Fatalf("scope forwarded = %+v", stub.captured)
	}
	if len(records) != 3 {
		t.Fatalf("records = %d, want one per transition", len(records))
	}

	// Issued: cites the chain record, names the auditor, carries the action
	// vocabulary the trail appended under.
	issued := records[0]
	if issued.ChainSeq != 7 || issued.RecordHash != "h-7" || issued.ActorID != "admin-a" ||
		issued.Resource != "auditor_grant/g-1" || issued.Action != auditapi.Action("identity.auditor_grant.issued") {
		t.Fatalf("issued record = %+v", issued)
	}
	if issued.AccessChange == nil || issued.AccessChange.AccessKind != KindGrantIssued ||
		issued.AccessChange.TargetPrincipalID != "auditor-1" || issued.AccessChange.GrantID != "g-1" {
		t.Fatalf("issued detail = %+v", issued.AccessChange)
	}
	if !issued.Allowed {
		t.Fatal("a witnessed transition must render as allowed — denials are the PDP's own records")
	}

	revoked := records[1]
	if revoked.Action != auditapi.Action("identity.auditor_grant.revoked") ||
		revoked.AccessChange.AccessKind != KindGrantRevoked || revoked.ActorID != "admin-b" {
		t.Fatalf("revoked record = %+v", revoked)
	}

	expired := records[2]
	if expired.Action != auditapi.Action("identity.auditor_grant.expired") ||
		expired.AccessChange.AccessKind != KindGrantExpired {
		t.Fatalf("expired record = %+v", expired)
	}
	// AC3: the actor of an expiry is the platform itself — no actor identity.
	if expired.ActorID != "" {
		t.Fatalf("expired record carries actor %q, want none", expired.ActorID)
	}
}

func TestAccessChangesDropsUnrenderableTransitions(t *testing.T) {
	stub := &stubGrants{transitions: []identityapi.GrantTransition{
		{Kind: identityapi.GrantTransitionKind("BOGUS"), GrantID: "g-1"},
		{Kind: identityapi.GrantIssued, ChainSeq: 1, RecordHash: "h-1", GrantID: "g-2"},
	}}
	records, err := NewAccessChangesSource(stub).AccessChanges(context.Background(), "tenant-a", time.Time{}, time.Time{}, "")
	if err != nil {
		t.Fatalf("access changes: %v", err)
	}
	if len(records) != 1 || records[0].Resource != "auditor_grant/g-2" {
		t.Fatalf("records = %+v, want the one renderable transition", records)
	}
}

func TestAccessChangesPropagatesSurfaceFailures(t *testing.T) {
	stub := &stubGrants{err: errors.New("surface down")}
	if _, err := NewAccessChangesSource(stub).AccessChanges(context.Background(), "tenant-a", time.Time{}, time.Time{}, ""); err == nil {
		t.Fatal("surface failure was swallowed — the evidence service must see it to degrade per contract")
	}
}
