package postgres

import (
	"strings"
	"testing"
)

// ADR-0043: the public PAT key ID selects exactly one configured verifier
// key. Authentication must not probe the rest of the ring.
func TestPATVerifierUsesSelectedConfiguredKeyOnly(t *testing.T) {
	ring := newVerifierKeyRing("old", map[string][]byte{
		"old": []byte("old-key"),
		"new": []byte("new-key"),
	})
	_, token, verifier, err := ring.issuePAT()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(token, "gfp_old_") {
		t.Fatalf("token = %q, want old key ID prefix", token)
	}
	keyID, got, ok := ring.patVerifier(token)
	if !ok || keyID != "old" || got != verifier {
		t.Fatalf("resolved key=%q verifier=%q ok=%v", keyID, got, ok)
	}
	if _, _, ok := ring.patVerifier("gfp_unknown_" + strings.TrimPrefix(token, "gfp_old_")); ok {
		t.Fatal("unknown key ID resolved a verifier")
	}
}

func TestSSHVerifierBindsConfiguredKeyID(t *testing.T) {
	ring := newVerifierKeyRing("default", map[string][]byte{
		"default": []byte("default-key"),
		"next":    []byte("next-key"),
	})
	got, ok := ring.sshVerifier("ssh-ed25519 AAA", "default")
	if !ok || got == "" {
		t.Fatalf("default verifier=%q ok=%v", got, ok)
	}
	if other, ok := ring.sshVerifier("ssh-ed25519 AAA", "next"); !ok || other == got {
		t.Fatalf("next verifier=%q ok=%v, want distinct configured verifier", other, ok)
	}
	if _, ok := ring.sshVerifier("ssh-ed25519 AAA", "unknown"); ok {
		t.Fatal("unknown SSH verifier key ID resolved")
	}
}
