// Auditor grant lifecycle audit vocabulary (T-0027, SPEC-0033).
//
// Grant management is the act that lets an external party read the tenant's
// evidence, so its lifecycle is itself accountability evidence (SPEC-0033
// AC4, G5): issuing, revoking and expiring each append an immutable,
// first-party audit record naming the granting admin and the auditor
// principal. The manage action is the reviewed PDP vocabulary; the lifecycle
// actions are the `action` values the trail records carry.
package audit

const (
	// ActionAuditorGrantManage is the reviewed policy action for issuing,
	// revoking and listing auditor grants (governance/policies authz.rego,
	// T-0027). It is owner-only and asked about the tenant.
	ActionAuditorGrantManage = "auditor.grant.manage"
	// ActionAuditorGrantIssued records that an authorized admin issued a
	// scoped, read-only, time-boxed grant (SPEC-0033 AC4).
	ActionAuditorGrantIssued = "identity.auditor_grant.issued"
	// ActionAuditorGrantRevoked records that an authorized admin terminated
	// a grant before expiry (SPEC-0033 AC4/AC7).
	ActionAuditorGrantRevoked = "identity.auditor_grant.revoked"
	// ActionAuditorGrantExpired records that a grant passed its expiry
	// without an operator action (SPEC-0033 AC3/AC4). The actor is the
	// platform itself, so the record carries no actor identity.
	ActionAuditorGrantExpired = "identity.auditor_grant.expired"
)
