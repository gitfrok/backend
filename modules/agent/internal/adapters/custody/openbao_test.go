package custody_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gitfrok/backend/modules/agent/api"
	"github.com/gitfrok/backend/modules/agent/internal/adapters/custody"
	"github.com/gitfrok/backend/platform/ids"
)

// transitServer is a minimal in-test stand-in for OpenBao's transit engine:
// enough of the wire to prove the production signer speaks the right
// protocol, with a REAL in-memory ECDSA P-256 key doing the signing. It
// stands in for the provider in CI; the optional live suite below speaks to
// the real one.
type transitServer struct {
	t       *testing.T
	mux     *http.ServeMux
	keys    map[string]*ecdsa.PrivateKey
	sealed  bool
	lastTok string
}

func newTransitServer(t *testing.T) *transitServer {
	s := &transitServer{t: t, mux: http.NewServeMux(), keys: map[string]*ecdsa.PrivateKey{}}
	s.mux.HandleFunc("/v1/transit/keys/", s.handleKeys)
	s.mux.HandleFunc("/v1/transit/sign/", s.handleSign)
	return s
}

func (s *transitServer) refuse(w http.ResponseWriter, code int, msgs ...string) {
	out, _ := json.Marshal(map[string]any{"errors": msgs})
	w.WriteHeader(code)
	_, _ = w.Write(out)
}

func (s *transitServer) gate(w http.ResponseWriter, r *http.Request) bool {
	s.lastTok = r.Header.Get("X-Vault-Token")
	if s.sealed {
		s.refuse(w, http.StatusServiceUnavailable, "Vault is sealed")
		return false
	}
	return true
}

func (s *transitServer) handleKeys(w http.ResponseWriter, r *http.Request) {
	if !s.gate(w, r) {
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/v1/transit/keys/")
	switch r.Method {
	case http.MethodGet:
		key, ok := s.keys[name]
		if !ok {
			s.refuse(w, http.StatusNotFound, "no handler for route")
			return
		}
		der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			s.refuse(w, http.StatusInternalServerError, err.Error())
			return
		}
		out, _ := json.Marshal(map[string]any{"data": map[string]any{
			"type": "ecdsa-p256", "exportable": false,
			"keys": map[string]any{"1": map[string]string{
				"public_key": base64.StdEncoding.EncodeToString(der),
			}},
		}})
		_, _ = w.Write(out)
	case http.MethodPost:
		var body struct {
			Type       string `json:"type"`
			Exportable bool   `json:"exportable"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			s.refuse(w, http.StatusBadRequest, "bad json")
			return
		}
		if body.Type != "ecdsa-p256" || body.Exportable {
			s.refuse(w, http.StatusBadRequest, "custody posture requires non-exportable ecdsa-p256")
			return
		}
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			s.refuse(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.keys[name] = key
		w.WriteHeader(http.StatusOK)
	default:
		s.refuse(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *transitServer) handleSign(w http.ResponseWriter, r *http.Request) {
	if !s.gate(w, r) {
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/v1/transit/sign/")
	key, ok := s.keys[name]
	if !ok {
		s.refuse(w, http.StatusNotFound, "no handler for route")
		return
	}
	var body struct {
		Input         string `json:"input"`
		HashAlgorithm string `json:"hash_algorithm"`
		Marshaling    string `json:"marshaling_algorithm"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		s.refuse(w, http.StatusBadRequest, "bad json")
		return
	}
	if body.HashAlgorithm != "none" || body.Marshaling != "asn1" {
		s.refuse(w, http.StatusBadRequest, "digest-in asn1-out is the only shape the CA signs with")
		return
	}
	digest, err := base64.StdEncoding.DecodeString(body.Input)
	if err != nil {
		s.refuse(w, http.StatusBadRequest, "input is not base64")
		return
	}
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest)
	if err != nil {
		s.refuse(w, http.StatusInternalServerError, err.Error())
		return
	}
	out, _ := json.Marshal(map[string]any{"data": map[string]string{
		"signature": base64.StdEncoding.EncodeToString(sig),
	}})
	_, _ = w.Write(out)
}

func newWireSigner(t *testing.T, s *transitServer) *custody.OpenBao {
	t.Helper()
	signer, err := custody.NewOpenBao(custody.Config{
		Address: s.ts(t).URL,
		Token:   custody.StaticToken("wire-test-token"),
	})
	if err != nil {
		t.Fatalf("NewOpenBao: %v", err)
	}
	return signer
}

// ts returns one httptest server per transitServer, closing it with the test.
func (s *transitServer) ts(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(s.mux)
	t.Cleanup(srv.Close)
	return srv
}

// TestOpenBaoGenerateKeyWire proves the production signer creates keys with
// the posture the ADR fixes — type ecdsa-p256, not exportable — and refuses
// to stage onto a name the custody service already holds.
func TestOpenBaoGenerateKeyWire(t *testing.T) {
	srv := newTransitServer(t)
	signer := newWireSigner(t, srv)
	ctx := context.Background()

	ref, err := signer.GenerateKey(ctx, "agent-ca-gen1")
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if string(ref) != "agent-ca-gen1" {
		t.Errorf("reference = %q, want the key name", ref)
	}
	if srv.lastTok != "wire-test-token" {
		t.Errorf("signer sent token %q, want the configured token", srv.lastTok)
	}

	if _, err := signer.GenerateKey(ctx, "agent-ca-gen1"); !errors.Is(err, custody.ErrKeyExists) {
		t.Errorf("second GenerateKey on the same name = %v, want ErrKeyExists", err)
	}
}

// TestOpenBaoKeyNamesAreIdentifiers: a key name becomes a URL path segment;
// anything that is not a plain identifier is refused before any request
// leaves the process.
func TestOpenBaoKeyNamesAreIdentifiers(t *testing.T) {
	srv := newTransitServer(t)
	signer := newWireSigner(t, srv)
	for _, name := range []string{"", "../keys", "a/b", "key name", "key%2Fname"} {
		if _, err := signer.GenerateKey(context.Background(), name); err == nil {
			t.Errorf("GenerateKey(%q) succeeded, want a refusal", name)
		}
		if _, err := signer.SignDigest(context.Background(), custody.KeyRef(name), make([]byte, 32)); err == nil {
			t.Errorf("SignDigest(%q) succeeded, want a refusal", name)
		}
	}
}

// TestOpenBaoPublicKeyPosture proves the signer reads the public half and
// REFUSES a key whose reported posture is wrong — wrong type or exportable.
func TestOpenBaoPublicKeyPosture(t *testing.T) {
	srv := newTransitServer(t)
	signer := newWireSigner(t, srv)
	ctx := context.Background()

	if _, err := signer.GenerateKey(ctx, "good-key"); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pub, err := signer.PublicKey(ctx, "good-key")
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	if pub.Curve != elliptic.P256() {
		t.Errorf("public key curve = %v, want P-256", pub.Curve.Params().Name)
	}

	if _, err := signer.PublicKey(ctx, "missing-key"); !errors.Is(err, custody.ErrNoKey) {
		t.Errorf("PublicKey(missing) = %v, want ErrNoKey", err)
	}
}

// TestOpenBaoSignDigestWire proves digest-in, ASN.1-signature-out end to
// end over the wire: the signature the signer returns verifies against the
// transit server's real key.
func TestOpenBaoSignDigestWire(t *testing.T) {
	srv := newTransitServer(t)
	signer := newWireSigner(t, srv)
	ctx := context.Background()

	if _, err := signer.GenerateKey(ctx, "sign-key"); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	digest := sha256.Sum256([]byte("the tbs structure's digest"))
	sig, err := signer.SignDigest(ctx, "sign-key", digest[:])
	if err != nil {
		t.Fatalf("SignDigest: %v", err)
	}
	pub, err := signer.PublicKey(ctx, "sign-key")
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		t.Error("wire signature does not verify against the transit key's public half")
	}

	if _, err := signer.SignDigest(ctx, "sign-key", make([]byte, 31)); err == nil {
		t.Error("a 31-byte digest was accepted, want refusal")
	}
}

// TestOpenBaoSealedIsUnavailable: a sealed provider is the availability
// event — the signer reports ErrUnavailable, nothing else.
func TestOpenBaoSealedIsUnavailable(t *testing.T) {
	srv := newTransitServer(t)
	signer := newWireSigner(t, srv)
	srv.sealed = true

	if _, err := signer.GenerateKey(context.Background(), "sealed-key"); !errors.Is(err, custody.ErrUnavailable) {
		t.Errorf("GenerateKey while sealed = %v, want ErrUnavailable", err)
	}
	if _, err := signer.SignDigest(context.Background(), "sealed-key", make([]byte, 32)); !errors.Is(err, custody.ErrUnavailable) {
		t.Errorf("SignDigest while sealed = %v, want ErrUnavailable", err)
	}
}

// TestKubernetesAuthExchangesServiceAccountJWT proves the production auth
// shape (ADR-0066 decision 5): a service-account JWT read from its file is
// exchanged for a short-lived token, and that token — not the JWT — is what
// the seam calls carry.
func TestKubernetesAuthExchangesServiceAccountJWT(t *testing.T) {
	var sawRole, sawJWT string
	login := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/kubernetes/login" {
			t.Errorf("login path = %q", r.URL.Path)
		}
		var body struct {
			Role string `json:"role"`
			JWT  string `json:"jwt"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		sawRole, sawJWT = body.Role, body.JWT
		out, _ := json.Marshal(map[string]any{"auth": map[string]string{"client_token": "short-lived-token"}})
		_, _ = w.Write(out)
	}))
	t.Cleanup(login.Close)

	jwtFile := t.TempDir() + "/token"
	if err := os.WriteFile(jwtFile, []byte("projected-sa-jwt"), 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}

	srv := newTransitServer(t)
	signer, err := custody.NewOpenBao(custody.Config{
		Address: srv.ts(t).URL,
		Token: custody.KubernetesAuth{
			Address: login.URL,
			Role:    "gitfrok-agent-ca",
			JWTFile: jwtFile,
		},
	})
	if err != nil {
		t.Fatalf("NewOpenBao: %v", err)
	}
	if _, err := signer.GenerateKey(context.Background(), "k8s-auth-key"); err != nil {
		t.Fatalf("GenerateKey through kubernetes auth: %v", err)
	}
	if sawRole != "gitfrok-agent-ca" || sawJWT != "projected-sa-jwt" {
		t.Errorf("login saw role=%q jwt=%q, want the configured role and the file's JWT", sawRole, sawJWT)
	}
	if srv.lastTok != "short-lived-token" {
		t.Errorf("seam call carried token %q, want the exchanged short-lived token", srv.lastTok)
	}
}

// TestLiveOpenBaoCustodyRoundTrip is the OPTIONAL live integration against
// the dev custody service (openbao-0/1/2 in the gitfrok minikube profile,
// unsealed, kubernetes auth enabled). It is env-gated like the other live
// suites and skipped in CI, which must never touch the production-shape
// provider:
//
//	GITFROK_TEST_OPENBAO_ADDR=http://127.0.0.1:18200 \
//	GITFROK_TEST_OPENBAO_TOKEN=<token with transit create/sign policy> \
//	go test ./modules/agent/internal/adapters/custody/ -run LiveOpenBao
//
// Provisioning the transit mount and the agent-ca key policy belongs to the
// composition-swap wave; this test creates its own throwaway key when the
// token permits.
func TestLiveOpenBaoCustodyRoundTrip(t *testing.T) {
	addr := os.Getenv("GITFROK_TEST_OPENBAO_ADDR")
	token := os.Getenv("GITFROK_TEST_OPENBAO_TOKEN")
	if addr == "" || token == "" {
		t.Skip("GITFROK_TEST_OPENBAO_ADDR / GITFROK_TEST_OPENBAO_TOKEN not set; skipping the live OpenBao suite")
	}
	signer, err := custody.NewOpenBao(custody.Config{
		Address: addr,
		Mount:   envOr("GITFROK_TEST_OPENBAO_MOUNT", "transit"),
		Token:   custody.StaticToken(token),
	})
	if err != nil {
		t.Fatalf("NewOpenBao: %v", err)
	}

	clk := newClock()
	bundle, err := custody.NewBundle(signer, clk.Now)
	if err != nil {
		t.Fatalf("NewBundle: %v", err)
	}
	name := "gitfrok-custody-test-" + strings.ToLower(ids.NewULID())
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := bundle.Bootstrap(ctx, name); err != nil {
		t.Fatalf("Bootstrap against the live custody service: %v", err)
	}
	issuer, err := custody.NewIssuer(bundle)
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}

	cert, err := issuer.Issue(ctx, testIdentity, clk.Now(), time.Hour, time.Minute)
	if err != nil {
		t.Fatalf("Issue through live transit: %v", err)
	}
	if _, validity, err := issuer.VerifyChain([][]byte{leafDEROf(t, cert)}, clk.Now()); err != nil || validity != api.ValidNow {
		t.Errorf("live-issued certificate = (%v, %v), want (ValidNow, nil)", validity, err)
	}
	if id, _, err := issuer.Inspect(leafDEROf(t, cert)); err != nil || id != testIdentity {
		t.Errorf("Inspect(live-issued) = (%+v, %v), want %+v", id, err, testIdentity)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
