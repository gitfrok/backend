package app

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

// Cursors are the pagination state of a search. They are signed with a per-process key and bound
// to the tenant, the issuing principal, and the query that issued them (SPEC-0035 AC1): a forged
// or cross-tenant token fails signature verification, a token replayed by a different actor fails
// its principal binding, an expired one fails its deadline, and any of these yields no content
// rather than an error that distinguishes causes (L17).
//
// A cursor carries an offset into the authorization-derived result set plus the binding claims
// (tenant, actor, query shape, deadline) and nothing else — no repository scope and no permission
// outcome. Every page re-derives the caller's scope at query time, so a cursor issued before a
// revocation never serves the revoked content: paging through
// an old token simply re-runs the same enforcement (SPEC-0035 AC5). Its lifetime stays short
// enough that AC5's next-query revocation is not defeated by a long-lived cursor (SPEC-0035 open
// question): the constraint is the revocation binding, not a specific number.

type cursorClaims struct {
	Tenant string    `json:"t"`
	Actor  string    `json:"a"`
	Text   string    `json:"q"`
	Mode   int       `json:"m"`
	Offset int       `json:"o"`
	Exp    time.Time `json:"e"`
}

// encodeCursor signs one page position under the service's key, bound to the issuing principal.
func (s *Service) encodeCursor(tenant, actor, text string, mode, offset int, exp time.Time) string {
	claims := cursorClaims{Tenant: tenant, Actor: actor, Text: text, Mode: mode, Offset: offset, Exp: exp}
	payload, err := json.Marshal(claims)
	if err != nil {
		// The claims are plain data built one line above; a marshal failure would be a Go bug.
		return ""
	}
	body := base64.RawURLEncoding.EncodeToString(payload)
	return body + "." + base64.RawURLEncoding.EncodeToString(s.sign(payload))
}

// decodeCursor verifies and decodes one token. Any failure — malformed, forged, tampered —
// reports ok=false; the caller yields no content and does not distinguish causes.
func (s *Service) decodeCursor(token string) (cursorClaims, bool) {
	var zero cursorClaims
	body, sig, found := strings.Cut(token, ".")
	if !found {
		return zero, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return zero, false
	}
	want, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return zero, false
	}
	if !hmac.Equal(s.sign(payload), want) {
		return zero, false
	}
	var claims cursorClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return zero, false
	}
	return claims, true
}

// sign is HMAC-SHA256 under the service's per-process key. The key never leaves the process and
// is never derived from caller input, so a caller cannot mint tokens.
func (s *Service) sign(payload []byte) []byte {
	mac := hmac.New(sha256.New, s.cursorKey[:])
	mac.Write(payload)
	return mac.Sum(nil)
}
