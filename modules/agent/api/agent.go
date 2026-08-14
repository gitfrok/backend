// Package api is the Agent context's in-process surface (T-0030, SPEC-0038, ADR-0060).
//
// The context owns the enrolment half of AgentGateway.Connect (ADR-0017): one-time
// enrolment tokens, the first-Connect handshake, control-plane-issued certificate rotation
// on the channel, connection admission, and the data-plane registry an operator sees and
// acts on. Nothing here imports infrastructure (invariant 20); the gRPC and TLS adapters
// live under internal/ and translate shapes only.
//
// SECRECY, stated once for every type in this package (SPEC-0038 AC2): an enrolment token
// secret and an issued certificate are credentials. The secret travels through EnrolRequest
// and is returned exactly once from IssueEnrolmentToken; it is never carried by any other
// type here, never formatted into a log line, an error message, or a metric label, and the
// audit trail names tokens and certificates by ID only.
package api

import (
	"context"
	"errors"
	"time"
)

// Identity is a data plane's identity as the control plane issued it: bound into the
// client certificate, never asserted by the agent (ADR-0060 §3).
type Identity struct {
	TenantID    string
	DataPlaneID string
}

// DataPlaneStatus is the operator-visible state of a provisioned data plane (SPEC-0038
// AC8). The four states are exhaustive and pairwise distinguishable; a stale data plane is
// never rendered as healthy anywhere this type appears.
type DataPlaneStatus string

const (
	// StatusNeverConnected: provisioned (an unspent enrolment token, or a partial
	// enrolment that never produced a certificate) but no data plane has come up.
	StatusNeverConnected DataPlaneStatus = "NEVER_CONNECTED"
	// StatusConnected: enrolled, and contact within the staleness window (or a stream
	// currently established).
	StatusConnected DataPlaneStatus = "CONNECTED"
	// StatusStale: enrolled, but no contact within the configured window. Distinct from
	// connected, and never rendered as healthy (SPEC-0038 AC8).
	StatusStale DataPlaneStatus = "STALE"
	// StatusRevoked: identity revoked by an operator; the next connection is refused.
	StatusRevoked DataPlaneStatus = "REVOKED"
)

// Healthy reports whether this status may be rendered as a healthy data plane. Only
// Connected qualifies — staleness is a fault an operator must see, not a shade of green
// (SPEC-0038 AC8).
func (s DataPlaneStatus) Healthy() bool { return s == StatusConnected }

// RefusalReason is the coarse enrolment refusal vocabulary — the in-process mirror of the
// wire's EnrolmentRefusalReason. Deliberately coarse: an invalid token, an unknown token
// and a token of another tenant are indistinguishable to the presenter (SPEC-0038 AC9,
// SPEC-0001).
type RefusalReason string

const (
	RefusalTokenInvalid RefusalReason = "TOKEN_INVALID" // malformed, unknown, or cross-tenant
	RefusalTokenSpent   RefusalReason = "TOKEN_SPENT"   // single-use, incl. after a failed first attempt
	RefusalTokenExpired RefusalReason = "TOKEN_EXPIRED"
	RefusalTokenRevoked RefusalReason = "TOKEN_REVOKED"
	RefusalDenied       RefusalReason = "DENIED" // control-plane admission decision or internal failure
)

// EnrolmentRefused reports a refused enrolment. Its message is coarse by construction and
// never contains the token (SPEC-0038 AC2, AC9).
type EnrolmentRefused struct{ Reason RefusalReason }

func (e *EnrolmentRefused) Error() string { return "enrolment refused" }

// ErrNotFound reports that no record exists for the caller's tenant. Cross-tenant reads
// yield the same shape (SPEC-0038 AC9, SPEC-0001): a caller cannot distinguish another
// tenant's record from a nonexistent one.
var ErrNotFound = errors.New("agent: no such record")

// ErrAuthorizationDenied is the one coarse denial for operator actions the PDP refused
// (invariant 2).
var ErrAuthorizationDenied = errors.New("agent: authorization denied")

// ErrTenantMismatch reports a request whose claimed tenant is not the caller's own.
var ErrTenantMismatch = errors.New("agent: tenant mismatch")

// ErrRevoked reports a data plane whose identity an operator revoked.
var ErrRevoked = errors.New("agent: data plane revoked")

// EnrolmentToken is one issued one-time enrolment token, named by ID. The secret is not
// part of this type on purpose: after issuance it exists only in the caller's hands and in
// the store's hash (SPEC-0038 AC2).
type EnrolmentToken struct {
	ID          string
	TenantID    string
	IssuedBy    string
	IssuedAt    time.Time
	ExpiresAt   time.Time
	SpentAt     time.Time // zero while unspent
	DataPlaneID string    // set once spent
	RevokedAt   time.Time // zero while unrevoked
}

// Spent reports whether the token was used or is otherwise unusable forever.
func (t EnrolmentToken) Spent() bool { return !t.SpentAt.IsZero() }

// Revoked reports whether an operator revoked the token before it was spent.
func (t EnrolmentToken) Revoked() bool { return !t.RevokedAt.IsZero() }

// DataPlane is one registry record (SPEC-0038 "Data owned"): tenant, data-plane ID, cloud,
// region, versions, last contact and the current certificate. Status is derived at read
// time — never stored — so a revocation or a stale window takes effect by construction.
type DataPlane struct {
	ID                   string
	TenantID             string
	Cloud                string
	Region               string
	AgentVersion         string
	K8sVersion           string
	Capabilities         []string
	EnrolledAt           time.Time
	LastSeenAt           time.Time
	CurrentCertificateID string
	CertificateExpiresAt time.Time
	RevokedAt            time.Time
	Status               DataPlaneStatus // derived at read time
}

// FleetView is one row of the operator's fleet visibility (SPEC-0038 AC8): either a data
// plane record with its derived status, or a still-unspent enrolment token — a provisioned
// data plane that never connected.
type FleetView struct {
	Status DataPlaneStatus
	// TokenID names the unspent token for StatusNeverConnected rows that have no data
	// plane record yet; empty otherwise.
	TokenID string
	// Plane is set for rows backed by a registry record; zero for token-only rows.
	Plane DataPlane
}

// EnrolRequest is the first-Connect presentation. Token is the one-time secret: a bearer
// credential, consumed here and never echoed anywhere downstream (SPEC-0038 AC2).
type EnrolRequest struct {
	Token        string
	Cloud        string
	Region       string
	AgentVersion string
	K8sVersion   string
	Capabilities []string
}

// IssuedCertificate is one control-plane-issued client certificate. PEM is the credential
// itself — chain plus private key — and travels only onto the channel it authenticates; it
// is never logged, stored in the registry, or placed in an audit record (SPEC-0038 AC2).
type IssuedCertificate struct {
	CertificateID string
	PEM           []byte
	ExpiresAt     time.Time
}

// Enrolment is the control plane's answer to a successful first Connect: the assigned
// identity, the first certificate, and the heartbeat cadence (SPEC-0038 AC3).
type Enrolment struct {
	Identity
	Certificate       IssuedCertificate
	HeartbeatInterval time.Duration
}

// Config is the per-environment enrolment configuration (invariant 13). No production value
// is compiled in: cmd/ supplies every field, and tests inject clocks and short windows.
type Config struct {
	// CertLifetime is how long an issued client certificate lives (SPEC-0038: short-lived).
	CertLifetime time.Duration
	// RotationLead is how long before expiry the next rotation is delivered (AC4).
	RotationLead time.Duration
	// RotationRetryInterval paces re-delivery after a failed or unacknowledged rotation.
	RotationRetryInterval time.Duration
	// StaleAfter is the contact window after which a data plane reads as stale (AC8).
	StaleAfter time.Duration
	// TokenMaxLifetime caps the lifetime an operator may grant an enrolment token.
	TokenMaxLifetime time.Duration
	// HeartbeatInterval is the cadence communicated to the agent on enrolment.
	HeartbeatInterval time.Duration
	// ClockSkewLeeway backdates issued certificates' validity so a mildly skewed customer
	// cluster clock does not reject a fresh certificate. Clock skew is a first-class failure
	// mode on this surface (SPEC-0038 non-functional).
	ClockSkewLeeway time.Duration
	// Now is the clock every decision reads. Injected so tests can age tokens and
	// certificates without waiting.
	Now func() time.Time
}

// CertificateIssuer is the control plane's CA role for agent identities (ADR-0060): issue
// short-lived client certificates naming tenant and data plane, and interpret presented
// ones. Key custody for a production CA is deliberately not decided here (ADR-0057
// follow-up); compositions supply whatever CA material their environment trusts.
type CertificateIssuer interface {
	// Issue mints one client certificate for id, valid from now (backdated by leeway) for
	// lifetime.
	Issue(ctx context.Context, id Identity, now time.Time, lifetime, leeway time.Duration) (IssuedCertificate, error)
	// Inspect parses one DER leaf certificate and returns the identity it names and its
	// expiry. Certificates not issued by this control plane are an error.
	Inspect(leafDER []byte) (Identity, time.Time, error)
	// VerifyChain checks rawCerts (leaf first) against this control plane's CA. It returns
	// the leaf's DER and whether the chain is trusted but the certificate expired — expiry
	// is the gateway's admission decision to make and audit, not the handshake's to fail
	// silently (SPEC-0038 AC5, AC7). An untrusted chain is an error.
	VerifyChain(rawCerts [][]byte, now time.Time) (leafDER []byte, expired bool, err error)
}

// StreamSession is the control-plane half of one established stream: the rotation state
// machine and the contact bookkeeping. The gRPC adapter drives it; all decisions and audit
// records live behind it (ADR-0060 §2, SPEC-0038 AC4).
type StreamSession interface {
	// Identity is the certificate's identity — the only identity this stream ever acts
	// under (AC3).
	Identity() Identity
	// RotationDueAt is the instant the adapter must next call Rotate: the current
	// certificate's expiry minus the rotation lead, or the next retry after a failed or
	// unacknowledged attempt.
	RotationDueAt() time.Time
	// Rotate issues (or re-issues, on retry) the next certificate and marks it pending the
	// agent's ack. The adapter delivers it as a CertificateRotation on the stream.
	Rotate(ctx context.Context) (IssuedCertificate, error)
	// AckRotation applies the agent's CertificateRotationAck for certificateID. applied is
	// whether the agent took the certificate; failureReason is the coarse wire vocabulary
	// when it did not. Unknown certificate IDs are ignored.
	AckRotation(ctx context.Context, certificateID string, applied bool, failureReason string) error
	// Lapsed reports whether the current certificate expired without a successful rotation.
	// A lapsed session must be refused, never extended (SPEC-0038 AC4).
	Lapsed(now time.Time) bool
	// Touch records contact now (AC8's staleness window reads from here).
	Touch(ctx context.Context)
	// Close releases the stream's registration. Idempotent.
	Close(ctx context.Context)
}

// Gateway is the agent-facing half of the context: everything Connect needs on the control
// plane side. Operator actions live on Operator; the two meet in one composition so they
// share the token store, the registry and the audit emission points.
type Gateway interface {
	// Enrol runs the first-Connect handshake for a stream that holds no certificate yet
	// (ADR-0060 §1). Refusals come back as *EnrolmentRefused with the coarse reason.
	Enrol(ctx context.Context, req EnrolRequest) (Enrolment, error)
	// AdmitPeerCertificates decides whether a client-certificate-authenticated connection
	// may proceed: chain trusted, certificate unexpired, identity registered and unrevoked.
	// Every refusal it makes is audited (AC5, AC7). Called from the TLS handshake hook.
	AdmitPeerCertificates(ctx context.Context, rawCerts [][]byte) (Identity, error)
	// IdentityOf returns the identity a presented leaf certificate names, without admission
	// checks — for a stream already admitted at the handshake.
	IdentityOf(leafDER []byte) (Identity, error)
	// OpenStream registers one admitted stream and returns its session.
	OpenStream(ctx context.Context, id Identity) (StreamSession, error)
	// TokenTenant resolves which tenant an unspent-or-not token was issued for, without
	// spending it. ok is false for malformed or unknown tokens. It exists so a payload
	// claiming another tenant's scope on a certified stream can be detected and audited
	// (AC3); it is never used to admit anything.
	TokenTenant(ctx context.Context, token string) (tenantID string, ok bool)
	// RefusedIdentityOverride appends the audit record for a payload that claimed a tenant
	// other than the certificate's (AC3: ignored and audited).
	RefusedIdentityOverride(ctx context.Context, id Identity, claimedTenant, messageID string) error
	// RefusedLapsed appends the audit records for a stream whose certificate lapsed without
	// rotation: the failed rotation and the refused connection (AC4). Called once per
	// lapsed stream.
	RefusedLapsed(ctx context.Context, id Identity) error
}

// Operator is the operator-facing half: token issuance and revocation, data-plane
// revocation, and the fleet visibility AC8 requires. Every action passes the PDP with the
// caller's identity (invariant 2).
type Operator interface {
	// IssueEnrolmentToken mints one single-use, tenant-scoped, time-bounded token (AC1).
	// The secret is returned exactly once, here; only its hash is stored. lifetime is
	// capped by Config.TokenMaxLifetime.
	IssueEnrolmentToken(ctx context.Context, tenantID, actorID string, lifetime time.Duration) (EnrolmentToken, string, error)
	// RevokeEnrolmentToken revokes an unspent token; a spent one cannot be revoked (its
	// enrolment already happened — revoke the data plane instead).
	RevokeEnrolmentToken(ctx context.Context, tenantID, actorID, tokenID string) error
	// RevokeDataPlane revokes a data plane's identity: the next connection is refused, and
	// nothing in the customer's cluster is touched (ADR-0060 §5, AC5).
	RevokeDataPlane(ctx context.Context, tenantID, actorID, dataPlaneID string) error
	// GetDataPlane reads one registry record. A missing or another tenant's ID yields
	// ErrNotFound — one coarse shape (AC9).
	GetDataPlane(ctx context.Context, tenantID, actorID, dataPlaneID string) (DataPlane, error)
	// Fleet lists the tenant's operator-visible state: data planes with derived status and
	// unspent tokens as never-connected rows (AC8).
	Fleet(ctx context.Context, tenantID, actorID string) ([]FleetView, error)
}
