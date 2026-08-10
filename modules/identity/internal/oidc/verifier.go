// Package oidc verifies OIDC ID tokens and maps their verified claims onto a
// tenant-scoped principal (ADR-0045, SPEC-0006).
//
// Everything here is deliberately strict, because this is where an external
// identity provider's assertion becomes a principal the PDP and RLS will trust.
// A token that is merely well-formed is worth nothing: it must be signed by a key
// the configured issuer publishes, issued by that issuer, addressed to this client,
// current, bound to the login flow that asked for it, and mapped to a tenant this
// deployment has explicitly registered.
//
// Every failure returns the same coarse denial — a false second return and no
// principal. A caller cannot tell an expired token from a wrong audience from an
// unregistered tenant, so the surface cannot be used to enumerate any of them.
package oidc

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Principal is the verified caller: which tenant, which actor, which roles.
type Principal struct {
	TenantID string
	ActorID  string
	Roles    []string
}

// Config is per-environment, never compiled in (invariant 13). No value here is
// something a caller can supply: a caller that could name its own issuer, its own
// audience, or its own tenant mapping could name ones it controls.
type Config struct {
	// Issuer is the OIDC issuer URL. Discovery, keys, and the token endpoint all
	// come from it, and the discovery document must agree that it is the issuer.
	Issuer string
	// ClientID is this deployment's OIDC client. It is the audience an ID token
	// must be addressed to, and the client the code exchange authenticates as.
	ClientID string
	// ClientSecret authenticates the code exchange. It lives here so it never
	// reaches the BFF (ADR-0045).
	ClientSecret string
	// RedirectURI is the one registered for this deployment. A caller's redirect
	// URI is checked against it rather than trusted.
	RedirectURI string
	// RoleClaim names the claim carrying project roles. Roles are read from it and
	// from nowhere else.
	RoleClaim string
	// AllowedRoles is the reviewed role vocabulary. A role outside it is dropped
	// rather than carried into a principal the PDP will evaluate.
	AllowedRoles []string
	// TenantMapping maps a verified resource-owner claim to a tenant ID. It is
	// required: without an entry there is no tenant, because a provider must not
	// be able to mint tenants by asserting new resource owners (ADR-0045).
	TenantMapping map[string]string
	// Leeway absorbs clock skew between this process and the issuer. Zero means
	// none, which is the safe default.
	Leeway time.Duration
}

// Verifier validates ID tokens against one configured issuer.
type Verifier struct {
	config Config
	client *http.Client
	now    func() time.Time

	mu        sync.Mutex
	discovery *discoveryDocument
	keys      map[string]*rsa.PublicKey
}

// New builds a verifier. It performs no network access; discovery happens on the
// first verification and is cached.
func New(config Config, client *http.Client) *Verifier {
	if client == nil {
		client = http.DefaultClient
	}
	return &Verifier{config: config, client: client, now: time.Now, keys: map[string]*rsa.PublicKey{}}
}

// WithNow overrides the clock. Tests use it; nothing else should.
func (v *Verifier) WithNow(now func() time.Time) *Verifier {
	if now != nil {
		v.now = now
	}
	return v
}

// Configured reports whether this verifier has everything it needs. A partially
// configured OIDC deployment must fail its rollout rather than deny every login
// for reasons an operator cannot see.
func (c Config) Configured() error {
	switch {
	case c.Issuer == "":
		return errors.New("oidc: no issuer configured")
	case !strings.HasPrefix(c.Issuer, "https://"):
		return errors.New("oidc: the issuer must be https")
	case c.ClientID == "":
		return errors.New("oidc: no client ID configured")
	case c.RedirectURI == "":
		return errors.New("oidc: no redirect URI configured")
	case c.RoleClaim == "":
		return errors.New("oidc: no role claim configured")
	case len(c.AllowedRoles) == 0:
		return errors.New("oidc: no allowed role vocabulary configured")
	case len(c.TenantMapping) == 0:
		return errors.New("oidc: no tenant mapping configured — no login could map to a tenant")
	}
	return nil
}

// ExchangeCode completes the Authorization Code Flow and returns the principal
// the resulting ID token maps to. The exchange happens here so the client secret
// never reaches the BFF.
func (v *Verifier) ExchangeCode(ctx context.Context, code, codeVerifier, redirectURI, nonce string) (Principal, bool) {
	// The caller states which redirect URI its flow used; it does not choose one.
	// A mismatch means this is not the flow this deployment registered.
	if code == "" || codeVerifier == "" || nonce == "" ||
		subtle.ConstantTimeCompare([]byte(redirectURI), []byte(v.config.RedirectURI)) != 1 {
		return Principal{}, false
	}
	idToken, err := v.exchange(ctx, code, codeVerifier)
	if err != nil {
		return Principal{}, false
	}
	return v.VerifyIDToken(ctx, idToken, nonce)
}

// VerifyIDToken validates a token and maps it. The nonce is required: without it
// a token minted for one login flow could be replayed into another.
func (v *Verifier) VerifyIDToken(ctx context.Context, idToken, nonce string) (Principal, bool) {
	if idToken == "" || nonce == "" {
		return Principal{}, false
	}
	claims, err := v.parseAndVerify(ctx, idToken)
	if err != nil {
		return Principal{}, false
	}

	now := v.now()
	switch {
	case claims.string("iss") != v.config.Issuer:
		return Principal{}, false
	case !claims.audienceIs(v.config.ClientID):
		return Principal{}, false
	// azp identifies the party the token was issued to. When present it must be
	// this client, or a token addressed to several audiences could be replayed
	// here by one of the others.
	case claims.string("azp") != "" && claims.string("azp") != v.config.ClientID:
		return Principal{}, false
	case claims.string("sub") == "":
		return Principal{}, false
	case subtle.ConstantTimeCompare([]byte(claims.string("nonce")), []byte(nonce)) != 1:
		return Principal{}, false
	}

	expiry, ok := claims.time("exp")
	if !ok || !now.Add(-v.config.Leeway).Before(expiry) {
		return Principal{}, false
	}
	if notBefore, present := claims.time("nbf"); present && now.Add(v.config.Leeway).Before(notBefore) {
		return Principal{}, false
	}
	if issuedAt, present := claims.time("iat"); present && issuedAt.After(now.Add(v.config.Leeway)) {
		return Principal{}, false
	}

	// The tenant must be one this deployment registered. A provider cannot mint
	// tenants by asserting resource owners nobody mapped.
	tenantID, mapped := v.config.TenantMapping[claims.string(resourceOwnerClaim)]
	if !mapped || tenantID == "" {
		return Principal{}, false
	}

	return Principal{
		TenantID: tenantID,
		ActorID:  claims.string("sub"),
		Roles:    v.allowedRoles(claims.strings(v.config.RoleClaim)),
	}, true
}

// resourceOwnerClaim is the Zitadel claim naming the organization a user belongs
// to (ADR-0045). It is the only input to tenant mapping.
const resourceOwnerClaim = "urn:zitadel:iam:user:resourceowner:id"

// allowedRoles keeps only roles in the reviewed vocabulary, de-duplicated and in
// the order the vocabulary declares — so a principal's roles cannot vary with the
// order a provider happened to emit them.
func (v *Verifier) allowedRoles(claimed []string) []string {
	present := make(map[string]struct{}, len(claimed))
	for _, role := range claimed {
		present[role] = struct{}{}
	}
	roles := make([]string, 0, len(v.config.AllowedRoles))
	for _, role := range v.config.AllowedRoles {
		if _, ok := present[role]; ok {
			roles = append(roles, role)
		}
	}
	return roles
}

// claims is the decoded payload. It is read through accessors rather than a
// struct so the configured role claim — whose name is not known at compile time —
// is read the same way as every other claim.
type claims map[string]any

func (c claims) string(name string) string {
	value, _ := c[name].(string)
	return value
}

func (c claims) time(name string) (time.Time, bool) {
	seconds, ok := c[name].(float64)
	if !ok {
		return time.Time{}, false
	}
	return time.Unix(int64(seconds), 0), true
}

// audienceIs accepts both shapes the spec allows: one audience, or several.
func (c claims) audienceIs(want string) bool {
	switch value := c["aud"].(type) {
	case string:
		return subtle.ConstantTimeCompare([]byte(value), []byte(want)) == 1
	case []any:
		for _, entry := range value {
			if audience, ok := entry.(string); ok &&
				subtle.ConstantTimeCompare([]byte(audience), []byte(want)) == 1 {
				return true
			}
		}
	}
	return false
}

// strings reads a claim that may be a single value or a list. A role claim that
// is neither yields no roles rather than a parse error, because a malformed claim
// must not become a principal with unexpected authority.
func (c claims) strings(name string) []string {
	switch value := c[name].(type) {
	case string:
		return []string{value}
	case []any:
		out := make([]string, 0, len(value))
		for _, entry := range value {
			if role, ok := entry.(string); ok {
				out = append(out, role)
			}
		}
		return out
	case map[string]any:
		// Zitadel emits project roles as an object keyed by role name.
		out := make([]string, 0, len(value))
		for role := range value {
			out = append(out, role)
		}
		return out
	}
	return nil
}

type jwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

// parseAndVerify checks the signature before anything reads the claims, so no
// decision is ever made on an unverified payload.
func (v *Verifier) parseAndVerify(ctx context.Context, token string) (claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("oidc: malformed token")
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	var header jwtHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, err
	}
	// One algorithm, named explicitly. Accepting whatever the token declares is
	// how "alg: none" and HMAC-with-the-public-key confusion get in.
	if header.Alg != "RS256" {
		return nil, fmt.Errorf("oidc: unsupported algorithm %q", header.Alg)
	}
	if header.Kid == "" {
		return nil, errors.New("oidc: token names no key")
	}

	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}
	key, err := v.publicKey(ctx, header.Kid)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature); err != nil {
		return nil, fmt.Errorf("oidc: signature: %w", err)
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var decoded claims
	if err := json.Unmarshal(payload, &decoded); err != nil {
		return nil, err
	}
	return decoded, nil
}

type discoveryDocument struct {
	Issuer        string `json:"issuer"`
	JWKSURI       string `json:"jwks_uri"`
	TokenEndpoint string `json:"token_endpoint"`
}

// discover reads the issuer's own OpenID configuration rather than assuming URL
// shapes. The document must name the configured issuer, so a redirect to another
// host cannot substitute its endpoints.
func (v *Verifier) discover(ctx context.Context) (*discoveryDocument, error) {
	v.mu.Lock()
	cached := v.discovery
	v.mu.Unlock()
	if cached != nil {
		return cached, nil
	}

	document, err := fetchJSON[discoveryDocument](ctx, v.client, strings.TrimSuffix(v.config.Issuer, "/")+"/.well-known/openid-configuration")
	if err != nil {
		return nil, err
	}
	if document.Issuer != v.config.Issuer {
		return nil, fmt.Errorf("oidc: discovery names issuer %q, configured %q", document.Issuer, v.config.Issuer)
	}
	if !strings.HasPrefix(document.JWKSURI, v.config.Issuer) || !strings.HasPrefix(document.TokenEndpoint, v.config.Issuer) {
		return nil, errors.New("oidc: discovery points outside the configured issuer")
	}

	v.mu.Lock()
	v.discovery = &document
	v.mu.Unlock()
	return &document, nil
}

type jwksDocument struct {
	Keys []struct {
		Kid string `json:"kid"`
		Kty string `json:"kty"`
		Alg string `json:"alg"`
		Use string `json:"use"`
		N   string `json:"n"`
		E   string `json:"e"`
	} `json:"keys"`
}

// publicKey resolves a key ID against the issuer's JWKS, refetching once when the
// ID is unknown so a rotated key is picked up without a restart.
func (v *Verifier) publicKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	v.mu.Lock()
	key, cached := v.keys[kid]
	v.mu.Unlock()
	if cached {
		return key, nil
	}
	if err := v.refreshKeys(ctx); err != nil {
		return nil, err
	}
	v.mu.Lock()
	key, cached = v.keys[kid]
	v.mu.Unlock()
	if !cached {
		return nil, fmt.Errorf("oidc: the issuer publishes no key %q", kid)
	}
	return key, nil
}

func (v *Verifier) refreshKeys(ctx context.Context) error {
	document, err := v.discover(ctx)
	if err != nil {
		return err
	}
	jwks, err := fetchJSON[jwksDocument](ctx, v.client, document.JWKSURI)
	if err != nil {
		return err
	}
	resolved := make(map[string]*rsa.PublicKey, len(jwks.Keys))
	for _, entry := range jwks.Keys {
		if entry.Kty != "RSA" || entry.Kid == "" || (entry.Use != "" && entry.Use != "sig") {
			continue
		}
		modulus, err := base64.RawURLEncoding.DecodeString(entry.N)
		if err != nil {
			continue
		}
		exponent, err := base64.RawURLEncoding.DecodeString(entry.E)
		if err != nil || len(exponent) == 0 || len(exponent) > 8 {
			continue
		}
		padded := make([]byte, 8)
		copy(padded[8-len(exponent):], exponent)
		resolved[entry.Kid] = &rsa.PublicKey{
			N: new(big.Int).SetBytes(modulus),
			E: int(binary.BigEndian.Uint64(padded)),
		}
	}
	if len(resolved) == 0 {
		return errors.New("oidc: the issuer publishes no usable signing key")
	}
	v.mu.Lock()
	v.keys = resolved
	v.mu.Unlock()
	return nil
}

// exchange trades the authorization code for an ID token at the issuer's own
// token endpoint, authenticating as this deployment's client.
func (v *Verifier) exchange(ctx context.Context, code, codeVerifier string) (string, error) {
	document, err := v.discover(ctx)
	if err != nil {
		return "", err
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {codeVerifier},
		"redirect_uri":  {v.config.RedirectURI},
		"client_id":     {v.config.ClientID},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, document.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if v.config.ClientSecret != "" {
		request.SetBasicAuth(url.QueryEscape(v.config.ClientID), url.QueryEscape(v.config.ClientSecret))
	}

	response, err := v.client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("oidc: token endpoint returned %d", response.StatusCode)
	}
	var token struct {
		IDToken string `json:"id_token"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&token); err != nil {
		return "", err
	}
	if token.IDToken == "" {
		return "", errors.New("oidc: the token response carried no ID token")
	}
	return token.IDToken, nil
}

func fetchJSON[T any](ctx context.Context, client *http.Client, endpoint string) (T, error) {
	var zero T
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return zero, err
	}
	response, err := client.Do(request)
	if err != nil {
		return zero, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return zero, fmt.Errorf("oidc: %s returned %d", endpoint, response.StatusCode)
	}
	var decoded T
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&decoded); err != nil {
		return zero, err
	}
	return decoded, nil
}
