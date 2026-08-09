package domain

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"sync"
	"time"
)

type Principal struct {
	TenantID, ActorID string
	Roles             []string
}
type PAT struct {
	ID, TenantID, ActorID, Label, verifier string
	Scopes                                 []string
	CreatedAt                              time.Time
	ExpiresAt, RevokedAt                   *time.Time
}
type sshKey struct {
	principal Principal
	revokedAt *time.Time
}
type Service struct {
	mu         sync.RWMutex
	key        []byte
	now        func() time.Time
	pats       map[string]*PAT
	byVerifier map[string]string
	keys       map[string]*sshKey
}

func NewService(key []byte) *Service {
	return NewServiceWithClock(key, time.Now)
}

// NewServiceWithClock exists for deterministic lifecycle tests. Production
// composition uses NewService and therefore the wall clock.
func NewServiceWithClock(key []byte, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{key: append([]byte(nil), key...), now: now, pats: map[string]*PAT{}, byVerifier: map[string]string{}, keys: map[string]*sshKey{}}
}

func (s *Service) RegisterSSHKey(publicKey, tenant, actor string, roles []string) error {
	if publicKey == "" || tenant == "" || actor == "" {
		return errors.New("key, tenant and actor required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[s.hash(publicKey)] = &sshKey{principal: Principal{TenantID: tenant, ActorID: actor, Roles: append([]string(nil), roles...)}}
	return nil
}
func (s *Service) AuthenticateSSHKey(publicKey string) (Principal, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	k, ok := s.keys[s.hash(publicKey)]
	if !ok || k.revokedAt != nil {
		return Principal{}, false
	}
	p := k.principal
	p.Roles = append([]string(nil), p.Roles...)
	return p, true
}
func (s *Service) RevokeSSHKey(tenant, actor, publicKey string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := s.keys[s.hash(publicKey)]
	if k == nil || k.principal.TenantID != tenant || k.principal.ActorID != actor {
		return errors.New("not found")
	}
	now := s.now().UTC()
	k.revokedAt = &now
	return nil
}
func (s *Service) IssuePAT(tenant, actor, label string, scopes []string, expiry ...*time.Time) (PAT, string, error) {
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
	token := "gfp_" + hex.EncodeToString(b)
	id := hex.EncodeToString(b[:16])
	createdAt := s.now().UTC()
	p := &PAT{ID: id, TenantID: tenant, ActorID: actor, Label: label, Scopes: append([]string(nil), scopes...), CreatedAt: createdAt, ExpiresAt: expiresAt, verifier: s.hash(token)}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pats[id] = p
	s.byVerifier[p.verifier] = id
	return s.public(*p), token, nil
}
func (s *Service) AuthenticatePAT(token string) (Principal, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	verifier := s.hash(token)
	id, found := s.byVerifier[verifier]
	if !found {
		return Principal{}, false
	}
	p := s.pats[id]
	if p != nil && p.RevokedAt == nil && (p.ExpiresAt == nil || s.now().Before(*p.ExpiresAt)) && hmac.Equal([]byte(p.verifier), []byte(verifier)) {
		return Principal{TenantID: p.TenantID, ActorID: p.ActorID}, true
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
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}
func (s *Service) hash(token string) string {
	h := hmac.New(sha256.New, s.key)
	_, _ = h.Write([]byte(token))
	return hex.EncodeToString(h.Sum(nil))
}
func (s *Service) public(p PAT) PAT {
	p.verifier = ""
	p.Scopes = append([]string(nil), p.Scopes...)
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
