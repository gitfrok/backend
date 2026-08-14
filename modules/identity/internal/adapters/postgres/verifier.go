package postgres

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
)

// verifierKeyRing holds process configuration only. It never stores a raw
// credential; persistent rows receive only the keyed verifier it produces.
type verifierKeyRing struct {
	activeKeyID string
	keys        map[string][]byte
}

func newVerifierKeyRing(activeKeyID string, keys map[string][]byte) verifierKeyRing {
	ring := verifierKeyRing{activeKeyID: activeKeyID, keys: make(map[string][]byte, len(keys))}
	for keyID, key := range keys {
		if keyID != "" && len(key) != 0 {
			ring.keys[keyID] = slices.Clone(key)
		}
	}
	if len(ring.keys) == 0 {
		panic("identity postgres: verifier key ring is empty")
	}
	if _, ok := ring.keys[activeKeyID]; !ok {
		panic("identity postgres: active verifier key is absent")
	}
	return ring
}

func (r verifierKeyRing) issuePAT() (id, token, verifier string, err error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", "", "", err
	}
	key, ok := r.keys[r.activeKeyID]
	if !ok {
		return "", "", "", errors.New("identity postgres: active verifier key unavailable")
	}
	token = "gfp_" + r.activeKeyID + "_" + hex.EncodeToString(secret)
	return hex.EncodeToString(secret[:16]), token, hashWithKey(key, token), nil
}

func (r verifierKeyRing) patVerifier(token string) (keyID, verifier string, ok bool) {
	keyID, _, ok = patKeyID(token)
	if !ok {
		return "", "", false
	}
	key, ok := r.keys[keyID]
	if !ok {
		return "", "", false
	}
	return keyID, hashWithKey(key, token), true
}

func (r verifierKeyRing) sshVerifier(publicKey, keyID string) (string, bool) {
	key, ok := r.keys[keyID]
	if !ok || publicKey == "" {
		return "", false
	}
	return hashWithKey(key, "ssh\x00"+keyID+"\x00"+publicKey), true
}

func hashWithKey(key []byte, value string) string {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write([]byte(value))
	return hex.EncodeToString(h.Sum(nil))
}

func patKeyID(token string) (string, string, bool) {
	const prefix = "gfp_"
	rest, found := strings.CutPrefix(token, prefix)
	if !found {
		return "", "", false
	}
	keyID, secret, ok := strings.Cut(rest, "_")
	if !ok || keyID == "" || len(secret) != 64 {
		return "", "", false
	}
	if _, err := hex.DecodeString(secret); err != nil {
		return "", "", false
	}
	return keyID, secret, true
}
