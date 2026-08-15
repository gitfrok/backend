package custody

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// TokenSource yields one short-lived OpenBao client token per call. It is the
// seam ADR-0066 decision 5 fixes: the control plane authenticates by
// exchanging a credential it already holds for a token, and NO static custody
// credential is persisted anywhere — the only shape consistent with ADR-0064
// decision 3's posture.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// StaticToken wraps one pre-obtained token. It exists for the documented
// TLS-auth fallback and for env-gated live tests; a production in-cluster
// composition uses KubernetesAuth, never a static value (ADR-0066 decision 5
// rejects delivering static secrets to the workload).
type StaticToken string

// Token returns the wrapped token.
func (t StaticToken) Token(context.Context) (string, error) {
	if string(t) == "" {
		return "", errors.New("custody: openbao: empty token")
	}
	return string(t), nil
}

// KubernetesAuth is the production TokenSource (ADR-0066 decision 5): the
// pod's service-account JWT, read fresh from its projected file on every
// call, exchanged for a short-lived OpenBao token via Kubernetes auth. No
// static credential exists anywhere in this path.
type KubernetesAuth struct {
	// Address is the OpenBao server base URL (same as Config.Address).
	Address string
	// Role is the OpenBao Kubernetes-auth role the CA service logs in with.
	Role string
	// JWTFile is the service-account token path; empty means the standard
	// in-cluster projection.
	JWTFile string
	// Client performs the login call; nil means a default client.
	Client *http.Client
	// AllowHTTPForLocalTests relaxes the https requirement for a LOOPBACK
	// address only — the shape the in-process wire tests serve. Production
	// compositions never set it (validateAddress states the boundary).
	AllowHTTPForLocalTests bool
}

const defaultServiceAccountTokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"

// validateAddress enforces the transport posture every custody call leaves
// on: https, always. The single relaxation — plain http to a LOOPBACK
// address — exists because in-process wire tests and the dev cluster's
// port-forward serve plain HTTP; it is opt-in behind the explicit flag and
// never widens beyond loopback.
func validateAddress(addr string, allowHTTPForLocalTests bool) error {
	u, err := url.Parse(addr)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("custody: openbao: address %q is not an absolute URL", addr)
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" && allowHTTPForLocalTests {
		switch u.Hostname() {
		case "127.0.0.1", "localhost", "::1":
			return nil
		}
	}
	return fmt.Errorf("custody: openbao: address %q must be https — plain http is allowed only on loopback behind the explicit local-test flag", addr)
}

// Token exchanges a freshly-read service-account JWT for a short-lived
// OpenBao client token.
func (k KubernetesAuth) Token(ctx context.Context) (string, error) {
	if err := validateAddress(k.Address, k.AllowHTTPForLocalTests); err != nil {
		return "", err
	}
	file := k.JWTFile
	if file == "" {
		file = defaultServiceAccountTokenFile
	}
	jwt, err := os.ReadFile(file)
	if err != nil {
		return "", fmt.Errorf("custody: openbao: read service-account token: %w", err)
	}
	body, err := json.Marshal(map[string]string{"role": k.Role, "jwt": string(jwt)})
	if err != nil {
		return "", fmt.Errorf("custody: openbao: encode login: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(k.Address, "/")+"/v1/auth/kubernetes/login", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("custody: openbao: build login request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	client := k.Client
	if client == nil {
		client = defaultHTTPClient()
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("custody: openbao: kubernetes login: %w: %v", ErrUnavailable, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("custody: openbao: kubernetes login refused (%s): %s: %w",
			resp.Status, errorText(raw), ErrUnavailable)
	}
	var out struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", fmt.Errorf("custody: openbao: decode login response: %w", err)
	}
	if out.Auth.ClientToken == "" {
		return "", fmt.Errorf("custody: openbao: login returned no token: %w", ErrUnavailable)
	}
	return out.Auth.ClientToken, nil
}

// Config wires one OpenBao transit signer (ADR-0066). Address and Token are
// required; Mount defaults to "transit".
type Config struct {
	// Address is the OpenBao server base URL, e.g.
	// "https://openbao.control-plane.svc:8200".
	Address string
	// Mount is the transit engine's mount path.
	Mount string
	// Token supplies one short-lived client token per call.
	Token TokenSource
	// Client performs the HTTP calls; nil means a default client with a
	// bounded timeout.
	Client *http.Client
	// AllowHTTPForLocalTests relaxes the https requirement for a LOOPBACK
	// Address only, so in-process wire tests and the dev cluster's
	// port-forward can serve plain HTTP. Production compositions never set
	// it; NewOpenBao refuses every other non-https address outright.
	AllowHTTPForLocalTests bool
}

// OpenBao is the production Signer: OpenBao's transit engine over its HTTP
// API (ADR-0066 decision 1). It holds a server address and an auth source —
// references and configuration, never key material: the signing key was
// generated inside transit, is non-exportable by default, and no OpenBao API
// returns it.
type OpenBao struct {
	addr   string
	mount  string
	token  TokenSource
	client *http.Client
}

var _ Signer = (*OpenBao)(nil)

func defaultHTTPClient() *http.Client { return &http.Client{Timeout: 10 * time.Second} }

// NewOpenBao validates the configuration and returns the signer. It contacts
// nothing: construction from configuration alone is a property AC1's fitness
// story relies on — no key, file or env secret participates.
func NewOpenBao(cfg Config) (*OpenBao, error) {
	if cfg.Address == "" {
		return nil, errors.New("custody: openbao: Address is required")
	}
	if err := validateAddress(cfg.Address, cfg.AllowHTTPForLocalTests); err != nil {
		return nil, err
	}
	if cfg.Token == nil {
		return nil, errors.New("custody: openbao: Token source is required")
	}
	mount := cfg.Mount
	if mount == "" {
		mount = "transit"
	}
	client := cfg.Client
	if client == nil {
		client = defaultHTTPClient()
	}
	return &OpenBao{
		addr:   strings.TrimRight(cfg.Address, "/"),
		mount:  strings.Trim(mount, "/"),
		token:  cfg.Token,
		client: client,
	}, nil
}

// keyPath builds the URL path segment for one key name, refusing anything
// that is not a plain identifier: a key name reaches a URL path here, and a
// name carrying slashes or traversal would address a different endpoint than
// the one the caller asked for.
func keyPath(name string) (string, error) {
	if name == "" {
		return "", errors.New("custody: openbao: empty key name")
	}
	for _, r := range name {
		if !(r == '-' || r == '_' ||
			('a' <= r && r <= 'z') || ('A' <= r && r <= 'Z') || ('0' <= r && r <= '9')) {
			return "", fmt.Errorf("custody: openbao: key name %q is not a plain identifier", name)
		}
	}
	return name, nil
}

// GenerateKey creates one non-exportable ECDSA P-256 key in transit and
// returns ONLY its reference. An existing key by that name is refused
// (ErrKeyExists): rotation stages a NEW key, never re-signs with a reused
// name.
func (o *OpenBao) GenerateKey(ctx context.Context, name string) (KeyRef, error) {
	path, err := keyPath(name)
	if err != nil {
		return "", err
	}
	if _, status, err := o.get(ctx, "/v1/"+o.mount+"/keys/"+path); err == nil && status == http.StatusOK {
		return "", fmt.Errorf("custody: openbao: %q: %w", name, ErrKeyExists)
	} else if err != nil {
		return "", err
	}
	req := map[string]any{
		"type":       "ecdsa-p256", // ADR-0066 decision 1: the key type this posture fixes
		"exportable": false,        // non-exportable is transit's default; stated for review
	}
	if _, status, err := o.post(ctx, "/v1/"+o.mount+"/keys/"+path, req); err != nil {
		return "", err
	} else if status != http.StatusOK && status != http.StatusNoContent {
		// Transit refuses a name it already holds with a 4xx; a lost
		// check-then-create race lands exactly there. Probe the read: when
		// the key now exists the refusal is the deterministic ErrKeyExists,
		// whatever status the create returned (Wave-3 review S1).
		if _, probeStatus, probeErr := o.get(ctx, "/v1/"+o.mount+"/keys/"+path); probeErr == nil && probeStatus == http.StatusOK {
			return "", fmt.Errorf("custody: openbao: create key %q lost the race - the key now exists: %w", name, ErrKeyExists)
		}
		return "", fmt.Errorf("custody: openbao: create key %q: unexpected status %d: %w", name, status, ErrUnavailable)
	}
	return KeyRef(name), nil
}

// PublicKey reads the public half of the referenced transit key and asserts
// the key's posture: ECDSA P-256 and non-exportable. A key that reports
// itself exportable is refused — signing through it would silently weaken
// the posture this adapter exists to fix.
func (o *OpenBao) PublicKey(ctx context.Context, ref KeyRef) (*ecdsa.PublicKey, error) {
	path, err := keyPath(string(ref))
	if err != nil {
		return nil, err
	}
	raw, status, err := o.get(ctx, "/v1/"+o.mount+"/keys/"+path)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, fmt.Errorf("custody: openbao: %q: %w", ref, ErrNoKey)
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("custody: openbao: read key %q: status %s: %w", ref, http.StatusText(status), ErrUnavailable)
	}
	var out struct {
		Data struct {
			Type       string `json:"type"`
			Exportable bool   `json:"exportable"`
			Keys       map[string]struct {
				PublicKey string `json:"public_key"`
			} `json:"keys"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("custody: openbao: decode key %q: %w", ref, err)
	}
	if out.Data.Type != "ecdsa-p256" {
		return nil, fmt.Errorf("custody: openbao: key %q has type %q: %w", ref, out.Data.Type, ErrNotECDSAP256)
	}
	if out.Data.Exportable {
		return nil, fmt.Errorf("custody: openbao: key %q is exportable: %w", ref, ErrNotECDSAP256)
	}
	// Transit numbers key versions as strings; take the newest — the version
	// the rotation story signs with.
	best, pub := -1, ""
	for v, info := range out.Data.Keys {
		n, err := strconv.Atoi(v)
		if err != nil {
			continue
		}
		if n > best {
			best, pub = n, info.PublicKey
		}
	}
	if pub == "" {
		return nil, fmt.Errorf("custody: openbao: key %q exposes no public half: %w", ref, ErrNoKey)
	}
	// Real transit serves the public half as a PEM block; bare base64 DER
	// is the older-wire fallback. PEM first — a decoder that only knew bare
	// base64 failed on every real response (the mock's bare-base64 shape
	// masked this until the live round-trip).
	var der []byte
	if block, _ := pem.Decode([]byte(pub)); block != nil {
		der = block.Bytes
	} else {
		var err error
		der, err = base64.StdEncoding.DecodeString(pub)
		if err != nil {
			return nil, fmt.Errorf("custody: openbao: decode public key %q: %w", ref, err)
		}
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("custody: openbao: parse public key %q: %w", ref, err)
	}
	ecdsaPub, ok := parsed.(*ecdsa.PublicKey)
	if !ok || ecdsaPub.Curve != elliptic.P256() {
		return nil, fmt.Errorf("custody: openbao: key %q public half is not ECDSA P-256: %w", ref, ErrNotECDSAP256)
	}
	return ecdsaPub, nil
}

// SignDigest signs one SHA-256 digest via POST /transit/sign/:name. The
// digest is presented pre-hashed: transit's hash_algorithm "none" only
// admits a digest-in request when prehashed is set, and the provider's
// literal pkcs1v15 signature_algorithm is what it requires alongside for
// ECDSA keys (it still returns ASN.1 DER for ecdsa-p256, the marshaling x509
// verification expects). Only the signature comes back.
func (o *OpenBao) SignDigest(ctx context.Context, ref KeyRef, digest []byte) ([]byte, error) {
	if len(digest) != 32 {
		return nil, fmt.Errorf("custody: openbao: digest is %d bytes, not a SHA-256 digest", len(digest))
	}
	path, err := keyPath(string(ref))
	if err != nil {
		return nil, err
	}
	req := map[string]any{
		"input":                base64.StdEncoding.EncodeToString(digest),
		"hash_algorithm":       "none",     // the input already IS the SHA-256 digest
		"prehashed":            true,       // required by transit to admit hash_algorithm "none"
		"signature_algorithm":  "pkcs1v15", // transit's required companion for a prehashed digest
		"marshaling_algorithm": "asn1",     // x509 verifies ASN.1 DER ECDSA signatures
	}
	raw, status, err := o.post(ctx, "/v1/"+o.mount+"/sign/"+path, req)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, fmt.Errorf("custody: openbao: sign: %q: %w", ref, ErrNoKey)
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("custody: openbao: sign %q: status %s: %w", ref, http.StatusText(status), ErrUnavailable)
	}
	var out struct {
		Data struct {
			Signature string `json:"signature"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("custody: openbao: decode sign response: %w", err)
	}
	// Transit returns signatures as TYPE-PREFIXED strings — "ecdsa-p256:<base64-DER>"
	// for this key type, or multi-part shapes like "vault:v1:<b64>" elsewhere.
	// ':' is outside the base64 alphabet, so the parsable payload is the
	// substring after the LAST ':'; a response without a prefix decodes whole.
	wire := out.Data.Signature
	if i := strings.LastIndex(wire, ":"); i >= 0 {
		wire = wire[i+1:]
	}
	sig, err := base64.StdEncoding.DecodeString(wire)
	if err != nil || len(sig) == 0 {
		return nil, fmt.Errorf("custody: openbao: sign %q returned no parsable signature: %w", ref, ErrUnavailable)
	}
	return sig, nil
}

// get performs one authenticated GET and returns the body and status.
func (o *OpenBao) get(ctx context.Context, path string) ([]byte, int, error) {
	return o.do(ctx, http.MethodGet, path, nil)
}

// post performs one authenticated JSON POST and returns the body and status.
func (o *OpenBao) post(ctx context.Context, path string, req any) ([]byte, int, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, 0, fmt.Errorf("custody: openbao: encode request: %w", err)
	}
	return o.do(ctx, http.MethodPost, path, body)
}

func (o *OpenBao) do(ctx context.Context, method, path string, body []byte) ([]byte, int, error) {
	token, err := o.token.Token(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, o.addr+path, reader)
	if err != nil {
		return nil, 0, fmt.Errorf("custody: openbao: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", token) // OpenBao accepts the Vault token header
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := o.client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 500 {
		// 503 is the sealed shape; any 5xx means custody cannot serve now.
		return raw, resp.StatusCode, fmt.Errorf("%w: %s: %s", ErrUnavailable, resp.Status, errorText(raw))
	}
	return raw, resp.StatusCode, nil
}

// errorText extracts the coarse errors[] list an OpenBao error body carries,
// for messages only — a response body is never logged whole.
func errorText(raw []byte) string {
	var out struct {
		Errors []string `json:"errors"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || len(out.Errors) == 0 {
		return "no detail"
	}
	return strings.Join(out.Errors, "; ")
}
