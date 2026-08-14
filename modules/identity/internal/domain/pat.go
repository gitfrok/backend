package domain

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"sync"
	"time"
)

type Principal struct {
	TenantID, ActorID string
	Roles             []string
}
type PAT struct {
	ID, TenantID, ActorID, Label string
	Scopes, Roles                []string
	verifier                     string
	CreatedAt                    time.Time
	ExpiresAt, RevokedAt         *time.Time
}
type sshKey struct {
	principal Principal
	revokedAt *time.Time
}
type Service struct {
	mu           sync.RWMutex
	activeKeyID  string
	verifierKeys map[string][]byte
	now          func() time.Time
	pats         map[string]*PAT
	byVerifier   map[string]string
	keys         map[string]*sshKey
}

func NewService(key []byte) *Service {
	return NewServiceWithClock(key, time.Now)
}

// NewServiceWithClock exists for deterministic lifecycle tests. Production
// composition uses NewService and therefore the wall clock.
func NewServiceWithClock(key []byte, now func() time.Time) *Service {
	return NewServiceWithKeyRing("default", map[string][]byte{"default": key}, now)
}

// NewServiceWithKeyRing models the protected verifier-key-ring configuration.
// Key IDs are public selectors; only the keyed HMAC result reaches storage.
func NewServiceWithKeyRing(activeKeyID string, keys map[string][]byte, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	ring := make(map[string][]byte, len(keys))
	for id, key := range keys {
		if id != "" && len(key) != 0 {
			ring[id] = slices.Clone(key)
		}
	}
	if len(ring) == 0 {
		panic("identity: verifier key ring is empty")
	}
	if _, ok := ring[activeKeyID]; !ok {
		panic("identity: active verifier key is absent")
	}
	return &Service{activeKeyID: activeKeyID, verifierKeys: ring, now: now, pats: map[string]*PAT{}, byVerifier: map[string]string{}, keys: map[string]*sshKey{}}
}

func (s *Service) RegisterSSHKey(publicKey, verifierKeyID, tenant, actor string, roles []string) error {
	if publicKey == "" || verifierKeyID == "" || tenant == "" || actor == "" {
		return errors.New("key, verifier key id, tenant and actor required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	index, ok := s.sshKeyIndex(publicKey, verifierKeyID)
	if !ok {
		return errors.New("unknown verifier key id")
	}
	s.keys[index] = &sshKey{principal: Principal{TenantID: tenant, ActorID: actor, Roles: slices.Clone(roles)}}
	return nil
}
func (s *Service) AuthenticateSSHKey(publicKey, verifierKeyID string) (Principal, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	index, indexed := s.sshKeyIndex(publicKey, verifierKeyID)
	k, ok := s.keys[index]
	if !indexed || !ok || k.revokedAt != nil {
		return Principal{}, false
	}
	p := k.principal
	p.Roles = slices.Clone(p.Roles)
	return p, true
}
func (s *Service) RevokeSSHKey(tenant, actor, publicKey, verifierKeyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	index, ok := s.sshKeyIndex(publicKey, verifierKeyID)
	k := s.keys[index]
	if !ok || k == nil || k.principal.TenantID != tenant || k.principal.ActorID != actor {
		return errors.New("not found")
	}
	now := s.now().UTC()
	k.revokedAt = &now
	return nil
}

// ActivateVerifierKey switches issuance to a configured key. Existing keys
// stay available for lookup until RetireVerifierKey removes them.
func (s *Service) ActivateVerifierKey(keyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.verifierKeys[keyID]; !ok {
		return errors.New("unknown verifier key id")
	}
	s.activeKeyID = keyID
	return nil
}

// RetireVerifierKey removes a key from the lookup ring. It deliberately
// refuses the active key: callers must activate a replacement first.
func (s *Service) RetireVerifierKey(keyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if keyID == s.activeKeyID {
		return errors.New("cannot retire active verifier key")
	}
	if _, ok := s.verifierKeys[keyID]; !ok {
		return errors.New("unknown verifier key id")
	}
	delete(s.verifierKeys, keyID)
	return nil
}
func (s *Service) IssuePAT(tenant, actor, label string, scopes, roles []string, expiry ...*time.Time) (PAT, string, error) {
	if tenant == "" || actor == "" {
		return PAT{}, "", errors.New("tenant and actor required")
	}
	var expiresAt *time.Time
	if len(expiry) > 0 && expiry[0] != nil {
		expires := expiry[0].UTC()
		if !expires.After(s.now()) {
			return PAT{}, "", errors.New("expiry must be in the future")
		}
		expiresAt = &expires
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return PAT{}, "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key, ok := s.verifierKeys[s.activeKeyID]
	if !ok {
		return PAT{}, "", errors.New("active verifier key unavailable")
	}
	token := "gfp_" + s.activeKeyID + "_" + hex.EncodeToString(b)
	id := hex.EncodeToString(b[:16])
	createdAt := s.now().UTC()
	p := &PAT{ID: id, TenantID: tenant, ActorID: actor, Label: label, Scopes: slices.Clone(scopes), Roles: slices.Clone(roles), CreatedAt: createdAt, ExpiresAt: expiresAt, verifier: hashWithKey(key, token)}
	s.pats[id] = p
	s.byVerifier[p.verifier] = id
	return s.public(*p), token, nil
}
func (s *Service) AuthenticatePAT(token string) (Principal, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	keyID, ok := patKeyID(token)
	if !ok {
		return Principal{}, false
	}
	key, ok := s.verifierKeys[keyID]
	if !ok {
		return Principal{}, false
	}
	verifier := hashWithKey(key, token)
	id, found := s.byVerifier[verifier]
	if !found {
		return Principal{}, false
	}
	p := s.pats[id]
	if p != nil && p.RevokedAt == nil && (p.ExpiresAt == nil || s.now().Before(*p.ExpiresAt)) && hmac.Equal([]byte(p.verifier), []byte(verifier)) {
		return Principal{TenantID: p.TenantID, ActorID: p.ActorID, Roles: slices.Clone(p.Roles)}, true
	}
	return Principal{}, false
}
func (s *Service) RevokePAT(tenant, actor, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.pats[id]
	if p == nil || p.TenantID != tenant || p.ActorID != actor {
		return errors.New("not found")
	}
	now := s.now().UTC()
	p.RevokedAt = &now
	return nil
}
func (s *Service) ListPATs(tenant, actor string) []PAT {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []PAT{}
	for _, p := range s.pats {
		if p.TenantID == tenant && p.ActorID == actor {
			out = append(out, s.public(*p))
		}
	}
	slices.SortFunc(out, func(a, b PAT) int { return a.CreatedAt.Compare(b.CreatedAt) })
	return out
}
func hashWithKey(key []byte, value string) string {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write([]byte(value))
	return hex.EncodeToString(h.Sum(nil))
}

func patKeyID(token string) (string, bool) {
	const prefix = "gfp_"
	rest, found := strings.CutPrefix(token, prefix)
	if !found {
		return "", false
	}
	keyID, secret, ok := strings.Cut(rest, "_")
	if !ok || keyID == "" || len(secret) != 64 {
		return "", false
	}
	if _, err := hex.DecodeString(secret); err != nil {
		return "", false
	}
	return keyID, true
}

// sshKeyIndex binds the configured, public verifier-key-ring selector into one
// keyed lookup. The in-memory adapter mirrors the production tuple shape from
// ADR-0043; it never probes another selector when this key is absent.
func (s *Service) sshKeyIndex(publicKey, verifierKeyID string) (string, bool) {
	key, ok := s.verifierKeys[verifierKeyID]
	if !ok || publicKey == "" {
		return "", false
	}
	return hashWithKey(key, "ssh\x00"+verifierKeyID+"\x00"+publicKey), true
}
func (s *Service) public(p PAT) PAT {
	p.verifier = ""
	p.Scopes = slices.Clone(p.Scopes)
	if p.ExpiresAt != nil {
		expires := *p.ExpiresAt
		p.ExpiresAt = &expires
	}
	if p.RevokedAt != nil {
		revoked := *p.RevokedAt
		p.RevokedAt = &revoked
	}
	return p
}
