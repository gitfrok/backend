package domain

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
)

type Principal struct {
	TenantID, ActorID string
	Roles             []string
}
type PAT struct {
	ID, TenantID, ActorID, Label, verifier string
	Scopes                                 []string
	Revoked                                bool
}
type Service struct {
	mu   sync.RWMutex
	key  []byte
	pats map[string]*PAT
	keys map[string]Principal
}

func NewService(key []byte) *Service {
	return &Service{key: append([]byte(nil), key...), pats: map[string]*PAT{}, keys: map[string]Principal{}}
}

func (s *Service) RegisterSSHKey(publicKey, tenant, actor string, roles []string) error {
	if publicKey == "" || tenant == "" || actor == "" {
		return errors.New("key, tenant and actor required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[s.hash(publicKey)] = Principal{TenantID: tenant, ActorID: actor, Roles: append([]string(nil), roles...)}
	return nil
}
func (s *Service) AuthenticateSSHKey(publicKey string) (Principal, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.keys[s.hash(publicKey)]
	return p, ok
}
func (s *Service) IssuePAT(tenant, actor, label string, scopes []string) (PAT, string, error) {
	if tenant == "" || actor == "" {
		return PAT{}, "", errors.New("tenant and actor required")
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return PAT{}, "", err
	}
	token := "gfp_" + hex.EncodeToString(b)
	id := hex.EncodeToString(b[:16])
	p := &PAT{ID: id, TenantID: tenant, ActorID: actor, Label: label, Scopes: append([]string(nil), scopes...), verifier: s.hash(token)}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pats[id] = p
	return s.public(*p), token, nil
}
func (s *Service) AuthenticatePAT(token string) (Principal, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, p := range s.pats {
		if !p.Revoked && hmac.Equal([]byte(p.verifier), []byte(s.hash(token))) {
			return Principal{TenantID: p.TenantID, ActorID: p.ActorID}, true
		}
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
	p.Revoked = true
	return nil
}
func (s *Service) hash(token string) string {
	h := hmac.New(sha256.New, s.key)
	_, _ = h.Write([]byte(token))
	return hex.EncodeToString(h.Sum(nil))
}
func (s *Service) public(p PAT) PAT { p.verifier = ""; return p }
