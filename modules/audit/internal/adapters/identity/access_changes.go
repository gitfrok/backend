// Package identity adapts Identity&Access's auditor grant surface to the
// evidence pack's access-changes port (T-0027, SPEC-0032 assumption,
// SPEC-0033).
//
// It crosses the module boundary at the two api/ surfaces only — Audit reads
// the grant lifecycle through identityapi.AuditorGrants, never through
// Identity&Access's storage (ADR-0022) — and renders every transition it
// hands over with the chain position Identity&Access witnessed it at: the
// section's records are the immutable audit records AC4 appends, cited
// rather than copied (SPEC-0033 AC4, ADR-0007).
package identity

import (
	"context"
	"fmt"
	"time"

	auditapi "github.com/gitfrok/backend/modules/audit/api"
	identityapi "github.com/gitfrok/backend/modules/identity/api"
)

// The access-change kinds the section renders — one per lifecycle transition
// Identity&Access witnesses (SPEC-0033 AC4: granting, expiring and revoking
// are first-party audit events).
const (
	KindGrantIssued  = "auditor_grant_issued"
	KindGrantRevoked = "auditor_grant_revoked"
	KindGrantExpired = "auditor_grant_expired"
)

// The audited actions the rendered records carry — the vocabulary
// Identity&Access appends to the tenant's chain (platform/audit, T-0027).
const (
	actionGrantIssued  = "identity.auditor_grant.issued"
	actionGrantRevoked = "identity.auditor_grant.revoked"
	actionGrantExpired = "identity.auditor_grant.expired"
)

// AccessChangesSource supplies the access-changes section from Identity&
// Access's own contract surface (SPEC-0032 assumption). It carries no
// authorization of its own: the evidence service asks the PDP before it ever
// calls this, and the identity surface scopes every read to the tenant it is
// given (SPEC-0001).
type AccessChangesSource struct {
	grants identityapi.AuditorGrants
}

// NewAccessChangesSource wires the adapter over the grant surface.
func NewAccessChangesSource(grants identityapi.AuditorGrants) *AccessChangesSource {
	return &AccessChangesSource{grants: grants}
}

// AccessChanges implements auditapi.AccessChangesSource: the grant lifecycle
// transitions witnessed within the range, rendered as section records citing
// their immutable audit records. Scope and lifecycle only — never pack
// contents (SPEC-0033).
func (s *AccessChangesSource) AccessChanges(ctx context.Context, tenantID string, from, to time.Time, repositoryID string) ([]auditapi.SectionRecord, error) {
	transitions, err := s.grants.GrantTransitions(ctx, tenantID, from, to, repositoryID)
	if err != nil {
		return nil, fmt.Errorf("audit: reading the auditor grant lifecycle: %w", err)
	}
	out := make([]auditapi.SectionRecord, 0, len(transitions))
	for _, t := range transitions {
		record, ok := render(t)
		if !ok {
			continue // an unrenderable transition is dropped, never guessed at
		}
		out = append(out, record)
	}
	return out, nil
}

// render maps one witnessed transition to the section record it is evidence
// for. Every record carries the chain position of the immutable audit record
// that witnessed the transition, the actor whose action caused it, and the
// auditor principal the grant authorizes — the pairing SPEC-0033 AC4 names.
func render(t identityapi.GrantTransition) (auditapi.SectionRecord, bool) {
	var action, kind string
	switch t.Kind {
	case identityapi.GrantIssued:
		action, kind = actionGrantIssued, KindGrantIssued
	case identityapi.GrantRevocation:
		action, kind = actionGrantRevoked, KindGrantRevoked
	case identityapi.GrantExpiration:
		action, kind = actionGrantExpired, KindGrantExpired
	default:
		return auditapi.SectionRecord{}, false
	}
	return auditapi.SectionRecord{
		ChainSeq:   t.ChainSeq,
		RecordHash: t.RecordHash,
		ActorID:    t.ActorID,
		Resource:   "auditor_grant/" + t.GrantID,
		Action:     auditapi.Action(action),
		// A lifecycle transition is a witnessed, authorized fact: denials of
		// grant operations are the PDP's own denial records, not these.
		Allowed:    true,
		OccurredAt: t.OccurredAt,
		AccessChange: &auditapi.AccessChangeDetail{
			AccessKind:        kind,
			TargetPrincipalID: t.AuditorPrincipalID,
			GrantID:           t.GrantID,
		},
	}, true
}
