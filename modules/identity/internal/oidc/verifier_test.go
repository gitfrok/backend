package oidc

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// issuer is a stand-in OIDC provider: it publishes a discovery document and a
// JWKS, mints ID tokens, and answers the token endpoint. Driving the verifier
// through a real HTTP provider is the point — a test that called the parsing
// helpers directly would not prove that discovery, key lookup, and the exchange
// hold together.
type issuer struct {
	server    *httptest.Server
	key       *rsa.PrivateKey
	kid       string
	idToken   string
	tokenCode int
}

// Generating a 2048-bit key costs seconds, and these tests want dozens of
// providers. Two keys are generated once for the whole package: one the stand-in
// issuer publishes, and one nobody published, for the forged-signature test.
var (
	signingKeys sync.Once
	issuerKey   *rsa.PrivateKey
	attackerKey *rsa.PrivateKey
)

func testKeys(t *testing.T) (*rsa.PrivateKey, *rsa.PrivateKey) {
	t.Helper()
	signingKeys.Do(func() {
		var err error
		if issuerKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic("generating the issuer key: " + err.Error())
		}
		if attackerKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic("generating the unpublished key: " + err.Error())
		}
	})
	return issuerKey, attackerKey
}

func newIssuer(t *testing.T) *issuer {
	t.Helper()
	key, _ := testKeys(t)
	provider := &issuer{key: key, kid: "key-1", tokenCode: http.StatusOK}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]string{
			"issuer":         provider.url(),
			"jwks_uri":       provider.url() + "/keys",
			"token_endpoint": provider.url() + "/token",
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"keys": []map[string]string{{
			"kid": provider.kid, "kty": "RSA", "alg": "RS256", "use": "sig",
			"n": base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		if provider.tokenCode != http.StatusOK {
			w.WriteHeader(provider.tokenCode)
			return
		}
		writeJSON(w, map[string]string{"id_token": provider.idToken})
	})

	provider.server = httptest.NewServer(mux)
	t.Cleanup(provider.server.Close)
	return provider
}

func (p *issuer) url() string {
	if p.server == nil {
		return ""
	}
	return p.server.URL
}

func writeJSON(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}

func (p *issuer) sign(t *testing.T, header map[string]string, payload map[string]any) string {
	t.Helper()
	encode := func(value any) string {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("encoding a token segment: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	signing := encode(header) + "." + encode(payload)
	digest := sha256Sum(signing)
	signature, err := rsa.SignPKCS1v15(rand.Reader, p.key, cryptoSHA256, digest)
	if err != nil {
		t.Fatalf("signing the token: %v", err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(signature)
}

const testNonce = "nonce-a"

// claimSet is the payload a well-formed login produces.
func (p *issuer) claimSet(now time.Time) map[string]any {
	return map[string]any{
		"iss":              p.url(),
		"sub":              "actor-a",
		"aud":              "client-a",
		"azp":              "client-a",
		"nonce":            testNonce,
		"exp":              now.Add(time.Hour).Unix(),
		"iat":              now.Unix(),
		resourceOwnerClaim: "org-a",
		"gitfrok:roles":    map[string]any{"member": nil, "not-in-vocabulary": nil},
	}
}

func testVerifier(t *testing.T, p *issuer, now time.Time) *Verifier {
	t.Helper()
	return New(Config{
		Issuer:        p.url(),
		ClientID:      "client-a",
		ClientSecret:  "secret-a",
		RedirectURI:   "https://app.gitsaas.test/callback",
		RoleClaim:     "gitfrok:roles",
		AllowedRoles:  []string{"owner", "member", "reader"},
		TenantMapping: map[string]string{"org-a": "tenant-a"},
	}, p.server.Client()).WithNow(func() time.Time { return now })
}

func header(kid string) map[string]string { return map[string]string{"alg": "RS256", "kid": kid} }

func TestVerifyMapsAVerifiedTokenToATenantScopedPrincipal(t *testing.T) {
	now := time.Now()
	provider := newIssuer(t)
	verifier := testVerifier(t, provider, now)
	token := provider.sign(t, header(provider.kid), provider.claimSet(now))

	principal, ok := verifier.VerifyIDToken(t.Context(), token, testNonce)
	if !ok {
		t.Fatal("a well-formed token was refused")
	}
	if principal.TenantID != "tenant-a" {
		t.Errorf("tenant = %q, want the mapped tenant, not the resource owner", principal.TenantID)
	}
	if principal.ActorID != "actor-a" {
		t.Errorf("actor = %q, want the verified sub", principal.ActorID)
	}
	// Only the reviewed vocabulary survives, whatever the provider asserted.
	//arch:allow-inline-authz asserts which claimed roles survive the vocabulary filter, not access
	if len(principal.Roles) != 1 || principal.Roles[0] != "member" {
		t.Errorf("roles = %v, want only the reviewed ones", principal.Roles)
	}
}

// Each of these is a token that differs from a valid one in exactly one way. Any
// of them being accepted is a way in.
func TestVerifyRefusesEveryWayATokenCanBeWrong(t *testing.T) {
	now := time.Now()

	for name, mutate := range map[string]func(*issuer, map[string]any, map[string]string){
		"another issuer": func(_ *issuer, c map[string]any, _ map[string]string) {
			c["iss"] = "https://evil.example"
		},
		"another audience": func(_ *issuer, c map[string]any, _ map[string]string) {
			c["aud"] = "client-b"
		},
		"authorized party is another client": func(_ *issuer, c map[string]any, _ map[string]string) {
			c["azp"] = "client-b"
		},
		"expired": func(_ *issuer, c map[string]any, _ map[string]string) {
			c["exp"] = now.Add(-time.Second).Unix()
		},
		"not yet valid": func(_ *issuer, c map[string]any, _ map[string]string) {
			c["nbf"] = now.Add(time.Hour).Unix()
		},
		"issued in the future": func(_ *issuer, c map[string]any, _ map[string]string) {
			c["iat"] = now.Add(time.Hour).Unix()
		},
		"nonce from another flow": func(_ *issuer, c map[string]any, _ map[string]string) {
			c["nonce"] = "nonce-b"
		},
		"no nonce at all": func(_ *issuer, c map[string]any, _ map[string]string) {
			delete(c, "nonce")
		},
		"no subject": func(_ *issuer, c map[string]any, _ map[string]string) {
			delete(c, "sub")
		},
		"unregistered resource owner": func(_ *issuer, c map[string]any, _ map[string]string) {
			c[resourceOwnerClaim] = "org-nobody-mapped"
		},
		"no resource owner": func(_ *issuer, c map[string]any, _ map[string]string) {
			delete(c, resourceOwnerClaim)
		},
		"unsigned": func(_ *issuer, _ map[string]any, h map[string]string) {
			h["alg"] = "none"
		},
		"symmetric algorithm": func(_ *issuer, _ map[string]any, h map[string]string) {
			h["alg"] = "HS256"
		},
		"unknown key": func(_ *issuer, _ map[string]any, h map[string]string) {
			h["kid"] = "key-nobody-published"
		},
		"no key named": func(_ *issuer, _ map[string]any, h map[string]string) {
			delete(h, "kid")
		},
	} {
		t.Run(name, func(t *testing.T) {
			provider := newIssuer(t)
			verifier := testVerifier(t, provider, now)
			claimSet := provider.claimSet(now)
			tokenHeader := header(provider.kid)
			mutate(provider, claimSet, tokenHeader)

			if _, ok := verifier.VerifyIDToken(t.Context(), provider.sign(t, tokenHeader, claimSet), testNonce); ok {
				t.Fatalf("accepted a token that was %s", name)
			}
		})
	}
}

// A token signed by a different key than the issuer publishes is the whole reason
// signatures are checked, so it gets its own test rather than a table row.
func TestVerifyRefusesATokenSignedByAnotherKey(t *testing.T) {
	now := time.Now()
	provider := newIssuer(t)
	verifier := testVerifier(t, provider, now)

	_, unpublished := testKeys(t)
	attacker := &issuer{key: unpublished, kid: provider.kid}
	forged := attacker.sign(t, header(provider.kid), provider.claimSet(now))

	if _, ok := verifier.VerifyIDToken(t.Context(), forged, testNonce); ok {
		t.Fatal("accepted a token signed by a key the issuer never published")
	}
}

// Discovery is trusted only when it names the configured issuer: otherwise a
// substituted or redirected document could point key lookup somewhere else. The
// impostor is a local server, because a test that reaches the network is a test
// that measures someone else's DNS.
func TestVerifyRefusesDiscoveryThatNamesAnotherIssuer(t *testing.T) {
	now := time.Now()
	provider := newIssuer(t)

	impostor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]string{
			// Names the real issuer while serving from somewhere else.
			"issuer":         provider.url(),
			"jwks_uri":       provider.url() + "/keys",
			"token_endpoint": provider.url() + "/token",
		})
	}))
	t.Cleanup(impostor.Close)

	verifier := New(Config{
		Issuer:        impostor.URL,
		ClientID:      "client-a",
		RedirectURI:   "https://app.gitsaas.test/callback",
		RoleClaim:     "gitfrok:roles",
		AllowedRoles:  []string{"member"},
		TenantMapping: map[string]string{"org-a": "tenant-a"},
	}, impostor.Client()).WithNow(func() time.Time { return now })

	if _, ok := verifier.VerifyIDToken(t.Context(), provider.sign(t, header(provider.kid), provider.claimSet(now)), testNonce); ok {
		t.Fatal("accepted a discovery document that named an issuer other than the configured one")
	}
}

// The reverse: a document that names the configured issuer but points its
// endpoints at another host. Key lookup must not follow it.
func TestVerifyRefusesDiscoveryPointingOutsideTheIssuer(t *testing.T) {
	now := time.Now()
	elsewhere := newIssuer(t)

	var host *httptest.Server
	host = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]string{
			"issuer":         host.URL,
			"jwks_uri":       elsewhere.url() + "/keys",
			"token_endpoint": elsewhere.url() + "/token",
		})
	}))
	t.Cleanup(host.Close)

	verifier := New(Config{
		Issuer:        host.URL,
		ClientID:      "client-a",
		RedirectURI:   "https://app.gitsaas.test/callback",
		RoleClaim:     "gitfrok:roles",
		AllowedRoles:  []string{"member"},
		TenantMapping: map[string]string{"org-a": "tenant-a"},
	}, host.Client()).WithNow(func() time.Time { return now })

	claimSet := elsewhere.claimSet(now)
	claimSet["iss"] = host.URL
	if _, ok := verifier.VerifyIDToken(t.Context(), elsewhere.sign(t, header(elsewhere.kid), claimSet), testNonce); ok {
		t.Fatal("followed discovery endpoints outside the configured issuer")
	}
}

func TestExchangeCodeReturnsThePrincipalFromTheIssuedToken(t *testing.T) {
	now := time.Now()
	provider := newIssuer(t)
	verifier := testVerifier(t, provider, now)
	provider.idToken = provider.sign(t, header(provider.kid), provider.claimSet(now))

	principal, ok := verifier.ExchangeCode(t.Context(), "code-a", "verifier-a", "https://app.gitsaas.test/callback", testNonce)
	if !ok {
		t.Fatal("a valid code exchange was refused")
	}
	if principal.TenantID != "tenant-a" || principal.ActorID != "actor-a" {
		t.Fatalf("principal = %+v", principal)
	}
}

// The caller states which redirect URI its flow used; it does not choose one.
func TestExchangeCodeRefusesAnotherRedirectURI(t *testing.T) {
	now := time.Now()
	provider := newIssuer(t)
	verifier := testVerifier(t, provider, now)
	provider.idToken = provider.sign(t, header(provider.kid), provider.claimSet(now))

	if _, ok := verifier.ExchangeCode(t.Context(), "code-a", "verifier-a", "https://evil.example/callback", testNonce); ok {
		t.Fatal("accepted a redirect URI this deployment never registered")
	}
}

func TestExchangeCodeRefusesAnIncompleteFlow(t *testing.T) {
	now := time.Now()
	provider := newIssuer(t)
	verifier := testVerifier(t, provider, now)
	provider.idToken = provider.sign(t, header(provider.kid), provider.claimSet(now))
	redirect := "https://app.gitsaas.test/callback"

	for name, call := range map[string]func() (Principal, bool){
		"no code": func() (Principal, bool) {
			return verifier.ExchangeCode(t.Context(), "", "verifier-a", redirect, testNonce)
		},
		"no verifier": func() (Principal, bool) {
			return verifier.ExchangeCode(t.Context(), "code-a", "", redirect, testNonce)
		},
		"no nonce": func() (Principal, bool) {
			return verifier.ExchangeCode(t.Context(), "code-a", "verifier-a", redirect, "")
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, ok := call(); ok {
				t.Fatalf("accepted a flow with %s", name)
			}
		})
	}
}

func TestExchangeCodeRefusesARejectedCode(t *testing.T) {
	now := time.Now()
	provider := newIssuer(t)
	provider.tokenCode = http.StatusBadRequest
	verifier := testVerifier(t, provider, now)

	if _, ok := verifier.ExchangeCode(t.Context(), "code-a", "verifier-a", "https://app.gitsaas.test/callback", testNonce); ok {
		t.Fatal("a code the issuer rejected produced a principal")
	}
}

// A half-configured deployment must fail its rollout, not deny every login for a
// reason nobody can see.
func TestConfigRefusesAHalfConfiguredDeployment(t *testing.T) {
	complete := Config{
		Issuer: "https://issuer.example", ClientID: "client-a",
		RedirectURI: "https://app.gitsaas.test/callback", RoleClaim: "gitfrok:roles",
		AllowedRoles: []string{"member"}, TenantMapping: map[string]string{"org-a": "tenant-a"},
	}
	if err := complete.Configured(); err != nil {
		t.Fatalf("a complete configuration was refused: %v", err)
	}

	for name, break_ := range map[string]func(*Config){
		"no issuer":        func(c *Config) { c.Issuer = "" },
		"plaintext issuer": func(c *Config) { c.Issuer = "http://issuer.example" },
		"no client":        func(c *Config) { c.ClientID = "" },
		"no redirect URI":  func(c *Config) { c.RedirectURI = "" },
		"no role claim":    func(c *Config) { c.RoleClaim = "" },
		"no vocabulary":    func(c *Config) { c.AllowedRoles = nil },
		"no tenant map":    func(c *Config) { c.TenantMapping = nil },
	} {
		t.Run(name, func(t *testing.T) {
			broken := complete
			break_(&broken)
			if err := broken.Configured(); err == nil {
				t.Fatalf("accepted a configuration with %s", name)
			}
		})
	}
}

// Small helpers so the test signs tokens the same way the verifier checks them.
func sha256Sum(value string) []byte {
	digest := sha256.Sum256([]byte(value))
	return digest[:]
}

const cryptoSHA256 = crypto.SHA256
