// Package domain is the Agent context's inner layer: enrolment tokens and data-plane
// state as plain decisions, with no infrastructure (invariant 16). Store mechanics live in
// the adapters; the wire shapes live in the gRPC adapter; nothing here knows either.
package domain

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"time"

	"github.com/gitfrok/backend/modules/agent/api"
)

// ErrStoreNotFound is the miss sentinel every store port returns: unknown record, or
// another tenant's — one shape, so the api surface cannot leak existence across tenants
// (SPEC-0038 AC9). Adapters return it; the app layer maps it. It lives here — not in app —
// so adapters can report it without importing the layer that consumes it.
var ErrStoreNotFound = errors.New("agent store: no such record")

// ErrTokenSpent reports a revoke aimed at a token that was already used: its enrolment
// happened, so the operator's act is revoking the data plane, not the token.
var ErrTokenSpent = errors.New("agent: token already spent")

// SecretBytes is the token secret's entropy. 32 bytes makes the token a bearer credential
// that cannot be guessed within the lifetime anything here issues; the blast radius of one
// stolen token stays one tenant and one use (ADR-0060).
const SecretBytes = 32

// GenerateSecret draws one fresh token secret. It is shown exactly once — at issuance —
// and stored only as its hash from then on (SPEC-0038 AC2).
func GenerateSecret() (string, error) {
	var b [SecretBytes]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// HashSecret is the token's at-rest identity. The store keys tokens by this hash, so a
// stolen database yields no usable credential (SPEC-0038 AC2).
func HashSecret(secret string) [32]byte { return sha256.Sum256([]byte(secret)) }

// Token is one enrolment token's record. The secret itself is absent on purpose: nothing
// but the presenter and the hash ever see it.
type Token struct {
	ID          string
	TenantID    string
	IssuedBy    string
	TokenHash   [32]byte
	IssuedAt    time.Time
	ExpiresAt   time.Time
	SpentAt     time.Time // zero while unspent
	DataPlaneID string    // minted when the token is claimed
	RevokedAt   time.Time // zero while unrevoked
}

// Spent reports whether the token has been used once already.
func (t Token) Spent() bool { return !t.SpentAt.IsZero() }

// Revoked reports whether an operator revoked the token.
func (t Token) Revoked() bool { return !t.RevokedAt.IsZero() }

// PresentOutcome decides one presentation of this token at now. It returns "" when the
// presentation may proceed, otherwise the coarse refusal reason. The ordering is the
// security statement: a spent token stays spent whatever else is true of it — a retry
// after a partial enrolment must not be re-litigated into a second identity (SPEC-0038
// AC1).
func (t Token) PresentOutcome(now time.Time) api.RefusalReason {
	switch {
	case t.Revoked():
		return api.RefusalTokenRevoked
	case t.Spent():
		return api.RefusalTokenSpent
	case !now.Before(t.ExpiresAt):
		return api.RefusalTokenExpired
	}
	return ""
}

// DataPlane is one registry record as the domain sees it. Status is never stored: it is
// derived at read time from revocation, contact and the staleness window, so a revocation
// or a silent data plane changes what an operator sees without any writer remembering to
// update a field (SPEC-0038 AC8).
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
}

// Revoked reports whether an operator revoked this data plane's identity.
func (d DataPlane) Revoked() bool { return !d.RevokedAt.IsZero() }

// Certified reports whether the record ever received a certificate. An enrolled-but-
// uncertified record is a partial enrolment — visible as never connected, never as
// healthy.
func (d DataPlane) Certified() bool { return d.CurrentCertificateID != "" }

// DeriveStatus is the AC8 derivation: revoked wins over everything; an uncertified record
// never connected; otherwise contact within the window (or a live stream) reads connected
// and anything older reads stale — never healthy.
func DeriveStatus(d DataPlane, streamActive bool, now time.Time, staleAfter time.Duration) api.DataPlaneStatus {
	switch {
	case d.Revoked():
		return api.StatusRevoked
	case !d.Certified():
		return api.StatusNeverConnected
	case streamActive || !now.After(d.LastSeenAt.Add(staleAfter)):
		return api.StatusConnected
	default:
		return api.StatusStale
	}
}
