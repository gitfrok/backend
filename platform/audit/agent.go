// Package audit carries security-relevant events to whatever will eventually persist them.
//
// This file carries the agent enrolment lifecycle records (T-0030, SPEC-0038, ADR-0060):
// enrolment-token issuance and revocation, enrolment, certificate issuance and rotation,
// data-plane revocation, refused connections, and refused identity overrides. SPEC-0038 AC7
// requires exactly one immutable record per lifecycle act, including refused connections;
// the emission points in modules/agent are what make each act append exactly once.
//
// AC2 applies to every record in this file: an enrolment token and an issued certificate are
// credentials, so no field carries a token secret or a certificate PEM — IDs, tenants, data
// planes, actors and coarse reasons only.
package audit

import "time"

// Agent lifecycle actions (SPEC-0038 AC7). The dotted vocabulary lives in the audit contract's
// comment; adding one is additive by construction.
const (
	// ActionAgentTokenIssued records an operator issuing a one-time enrolment token.
	ActionAgentTokenIssued = "agent.enrolment_token.issued"
	// ActionAgentTokenRevoked records an operator revoking an unspent enrolment token.
	ActionAgentTokenRevoked = "agent.enrolment_token.revoked"
	// ActionAgentEnrolment records one enrolment attempt, allowed or refused.
	ActionAgentEnrolment = "agent.enrolment"
	// ActionAgentCertificateIssued records the control plane issuing a data plane's first
	// certificate on a successful enrolment.
	ActionAgentCertificateIssued = "agent.certificate.issued"
	// ActionAgentCertificateRotation records one rotation act over the established stream:
	// applied (ALLOWED) or failed/lapsed (DENIED).
	ActionAgentCertificateRotation = "agent.certificate.rotation"
	// ActionAgentDataPlaneRevoked records an operator revoking a data plane's identity.
	ActionAgentDataPlaneRevoked = "agent.dataplane.revoked"
	// ActionAgentConnectionRefused records a refused connection: expired or revoked
	// certificate, no credential at all, or a lapsed rotation (SPEC-0038 AC5, AC6).
	ActionAgentConnectionRefused = "agent.connection.refused"
	// ActionAgentIdentityOverrideRefused records a payload claiming an identity other than
	// the certificate's, ignored and audited (SPEC-0038 AC3, invariant 2 on the agent wire).
	ActionAgentIdentityOverrideRefused = "agent.identity.override.refused"
)

// AgentTokenIssued records one enrolment token issued for a tenant (SPEC-0038: token
// issuance is a lifecycle act). It names the token by ID only — the secret is a bearer
// credential and never enters the trail (SPEC-0038 AC2, ADR-0060).
type AgentTokenIssued struct {
	TenantID   string
	ActorID    string
	TokenID    string
	ExpiresAt  time.Time
	OccurredAt time.Time
}

func (AgentTokenIssued) EventName() string { return EventAudit }
func (AgentTokenIssued) Action() string    { return ActionAgentTokenIssued }
func (e AgentTokenIssued) Tenant() string  { return e.TenantID }

// AgentTokenRevoked records an operator revoking an enrolment token before it was spent.
type AgentTokenRevoked struct {
	TenantID   string
	ActorID    string
	TokenID    string
	OccurredAt time.Time
}

func (AgentTokenRevoked) EventName() string { return EventAudit }
func (AgentTokenRevoked) Action() string    { return ActionAgentTokenRevoked }
func (e AgentTokenRevoked) Tenant() string  { return e.TenantID }

// AgentEnrolment records one enrolment attempt. OutcomeAllowed carries the minted data-plane
// ID; OutcomeDenied carries the coarse refusal reason — the same coarse vocabulary the wire's
// EnrolmentRefusalReason defines, so a presenter learns nothing more from the trail than from
// the refusal itself (SPEC-0001). The token is named by ID when one resolved; an unresolvable
// token leaves TokenID empty rather than echoing any part of the secret.
type AgentEnrolment struct {
	TenantID    string
	DataPlaneID string
	TokenID     string
	Reason      string
	Outcome     string // "ALLOWED" or "DENIED", mirroring auditapi.Outcome
	OccurredAt  time.Time
}

func (AgentEnrolment) EventName() string { return EventAudit }
func (AgentEnrolment) Action() string    { return ActionAgentEnrolment }
func (e AgentEnrolment) Tenant() string  { return e.TenantID }

// AgentCertificateIssued records the control plane issuing a certificate that names the tenant
// and the data plane (ADR-0060 §3). The PEM never enters the trail — the credential travels
// only on the channel it authenticates (SPEC-0038 AC2).
type AgentCertificateIssued struct {
	TenantID      string
	DataPlaneID   string
	CertificateID string
	ExpiresAt     time.Time
	OccurredAt    time.Time
}

func (AgentCertificateIssued) EventName() string { return EventAudit }
func (AgentCertificateIssued) Action() string    { return ActionAgentCertificateIssued }
func (e AgentCertificateIssued) Tenant() string  { return e.TenantID }

// AgentCertificateRotation records one rotation act. Applied rotations name the new
// certificate; failed ones name the failure reason and, when the certificate lapsed without a
// successful rotation, the connection refusal that followed (SPEC-0038 AC4).
type AgentCertificateRotation struct {
	TenantID      string
	DataPlaneID   string
	CertificateID string
	Reason        string
	Outcome       string // "ALLOWED" when applied, "DENIED" when failed or lapsed
	OccurredAt    time.Time
}

func (AgentCertificateRotation) EventName() string { return EventAudit }
func (AgentCertificateRotation) Action() string    { return ActionAgentCertificateRotation }
func (e AgentCertificateRotation) Tenant() string  { return e.TenantID }

// AgentDataPlaneRevoked records the control-plane act of revoking a data plane's identity
// (ADR-0060 §5): the next connection is refused, and no access to the customer's cluster is
// needed for either.
type AgentDataPlaneRevoked struct {
	TenantID    string
	ActorID     string
	DataPlaneID string
	OccurredAt  time.Time
}

func (AgentDataPlaneRevoked) EventName() string { return EventAudit }
func (AgentDataPlaneRevoked) Action() string    { return ActionAgentDataPlaneRevoked }
func (e AgentDataPlaneRevoked) Tenant() string  { return e.TenantID }

// AgentConnectionRefused records a connection the gateway refused: an expired or revoked
// certificate, a stream that held neither certificate nor unspent token, or a certificate
// that lapsed mid-stream without rotation (SPEC-0038 AC5, AC6, AC4). The reason is coarse;
// there is no credential material anywhere in the record.
type AgentConnectionRefused struct {
	TenantID    string
	DataPlaneID string
	Reason      string
	OccurredAt  time.Time
}

func (AgentConnectionRefused) EventName() string { return EventAudit }
func (AgentConnectionRefused) Action() string    { return ActionAgentConnectionRefused }
func (e AgentConnectionRefused) Tenant() string  { return e.TenantID }

// AgentIdentityOverrideRefused records a message whose payload claimed a tenant other than
// the certificate's. The message is ignored — attribution stays with the certificate — and
// the attempt is audited (SPEC-0038 AC3). ClaimedTenantID is the tenant the payload tried to
// reach; the record itself is scoped to the certificate's tenant, which is the scope the
// attempt arrived under.
type AgentIdentityOverrideRefused struct {
	TenantID      string
	DataPlaneID   string
	ClaimedTenant string
	MessageID     string
	OccurredAt    time.Time
}

func (AgentIdentityOverrideRefused) EventName() string { return EventAudit }
func (AgentIdentityOverrideRefused) Action() string    { return ActionAgentIdentityOverrideRefused }
func (e AgentIdentityOverrideRefused) Tenant() string  { return e.TenantID }
