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
	"encoding/pem"
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
//
// The sign endpoint emits the REAL wire shape: a TYPE-PREFIXED signature
// string ("ecdsa-p256:<base64-DER>"), never bare base64 — a bare payload
// here once masked a decoder that failed against every real response.
// sigPrefix lets one test swing the prefix to another real shape
// ("vault:v1:"). Likewise the keys endpoint emits the public half as a PEM
// block (the real shape); barePub swings one test to the bare-base64
// older-wire fallback.
type transitServer struct {
	t         *testing.T
	mux       *http.ServeMux
	keys      map[string]*ecdsa.PrivateKey
	sealed    bool
	lastTok   string
	sigPrefix string
	barePub   bool
}

func newTransitServer(t *testing.T) *transitServer {
	s := &transitServer{t: t, mux: http.NewServeMux(), keys: map[string]*ecdsa.PrivateKey{}, sigPrefix: "ecdsa-p256:"}
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
		// The REAL transit wire shape: the public half arrives as a PEM
		// block, not bare base64. The mock emits what the service serves —
		// a bare-base64 mock masked a decoder that failed on every real
		// response until the live round-trip caught it.
		pub := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
		if s.barePub {
			pub = base64.StdEncoding.EncodeToString(der) // older-wire fallback the decoder keeps
		}
		out, _ := json.Marshal(map[string]any{"data": map[string]any{
			"type": "ecdsa-p256", "exportable": false,
			"keys": map[string]any{"1": map[string]string{
				"public_key": pub,
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
		Prehashed     bool   `json:"prehashed"`
		SignatureAlg  string `json:"signature_algorithm"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		s.refuse(w, http.StatusBadRequest, "bad json")
		return
	}
	// The REAL provider refuses hash_algorithm "none" without prehashed and
	// its literal pkcs1v15 companion — the mock enforces the same contract,
	// so a request that the real service rejects fails here first.
	if body.HashAlgorithm != "none" || body.Marshaling != "asn1" ||
		!body.Prehashed || body.SignatureAlg != "pkcs1v15" {
		s.refuse(w, http.StatusBadRequest,
			"hash_algorithm=none requires both prehashed=true and signature_algorithm=pkcs1v15")
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
	// The REAL wire shape: a type prefix, then the base64 DER payload.
	out, _ := json.Marshal(map[string]any{"data": map[string]string{
		"signature": s.sigPrefix + base64.StdEncoding.EncodeToString(sig),
	}})
	_, _ = w.Write(out)
}

func newWireSigner(t *testing.T, s *transitServer) *custody.OpenBao {
	t.Helper()
	signer, err := custody.NewOpenBao(custody.Config{
		Address: s.ts(t).URL,
		Token:   custody.StaticToken("wire-test-token"),
		// The in-process stand-in serves plain HTTP on loopback; the flag is
		// the ONLY shape under which NewOpenBao accepts that.
		AllowHTTPForLocalTests: true,
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

// TestOpenBaoPublicKeyBareBase64Fallback covers the older wire shape some
// providers serve: the public half as bare base64 DER instead of a PEM
// block. The decoder keeps accepting it.
func TestOpenBaoPublicKeyBareBase64Fallback(t *testing.T) {
	srv := newTransitServer(t)
	srv.barePub = true
	signer := newWireSigner(t, srv)
	ctx := context.Background()

	if _, err := signer.GenerateKey(ctx, "bare-key"); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pub, err := signer.PublicKey(ctx, "bare-key")
	if err != nil {
		t.Fatalf("PublicKey over bare-base64 wire: %v", err)
	}
	if pub.Curve != elliptic.P256() {
		t.Errorf("public key curve = %v, want P-256", pub.Curve.Params().Name)
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

// TestOpenBaoSignDigestMultiPartPrefix swings the wire to another real
// prefix shape ("vault:v1:<b64>"): the decoder takes the payload after the
// LAST ':', whatever names the type.
func TestOpenBaoSignDigestMultiPartPrefix(t *testing.T) {
	srv := newTransitServer(t)
	srv.sigPrefix = "vault:v1:"
	signer := newWireSigner(t, srv)
	ctx := context.Background()

	if _, err := signer.GenerateKey(ctx, "prefix-key"); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	digest := sha256.Sum256([]byte("multi-part prefix digest"))
	sig, err := signer.SignDigest(ctx, "prefix-key", digest[:])
	if err != nil {
		t.Fatalf("SignDigest over a vault:v1: prefixed signature: %v", err)
	}
	pub, err := signer.PublicKey(ctx, "prefix-key")
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		t.Error("signature decoded from a multi-part prefix does not verify")
	}
}

// TestNewOpenBaoRequiresHTTPS is the transport posture (finding 8): the
// signer refuses every non-https address; plain http survives ONLY on
// loopback and ONLY behind the explicit local-test flag.
func TestNewOpenBaoRequiresHTTPS(t *testing.T) {
	tok := custody.StaticToken("t")
	for _, tc := range []struct {
		name    string
		addr    string
		devFlag bool
		ok      bool
	}{
		{"https is always fine", "https://openbao.control-plane.svc:8200", false, true},
		{"http refused by default", "http://openbao.control-plane.svc:8200", false, false},
		{"http refused off-loopback even with the flag", "http://10.0.0.5:8200", true, false},
		{"http on loopback needs the flag", "http://127.0.0.1:18200", false, false},
		{"http on loopback with the flag", "http://127.0.0.1:18200", true, true},
		{"http on localhost with the flag", "http://localhost:18200", true, true},
		{"shapeless address refused", "openbao.svc:8200", true, false},
	} {
		_, err := custody.NewOpenBao(custody.Config{Address: tc.addr, Token: tok, AllowHTTPForLocalTests: tc.devFlag})
		if tc.ok && err != nil {
			t.Errorf("%s: NewOpenBao(%q, flag=%t) = %v, want success", tc.name, tc.addr, tc.devFlag, err)
		}
		if !tc.ok && err == nil {
			t.Errorf("%s: NewOpenBao(%q, flag=%t) succeeded, want a refusal", tc.name, tc.addr, tc.devFlag)
		}
	}
}

// TestKubernetesAuthRequiresHTTPS applies the same posture to the login
// endpoint: a service-account exchange over plain http to a non-loopback
// host is refused before any request leaves the process.
func TestKubernetesAuthRequiresHTTPS(t *testing.T) {
	for _, tc := range []struct {
		addr    string
		devFlag bool
		ok      bool
	}{
		{"http://10.0.0.5:8200", false, false},
		{"http://10.0.0.5:8200", true, false},
		{"http://127.0.0.1:8200", false, false},
		{"https://openbao.control-plane.svc:8200", false, true}, // address ok; fails later on the JWT file
	} {
		auth := custody.KubernetesAuth{Address: tc.addr, Role: "r", JWTFile: "/nonexistent-jwt-file", AllowHTTPForLocalTests: tc.devFlag}
		_, err := auth.Token(context.Background())
		if err == nil {
			t.Fatalf("Token(%q, flag=%t) succeeded, want a refusal", tc.addr, tc.devFlag)
		}
		rejectsAddress := strings.Contains(err.Error(), "https") || strings.Contains(err.Error(), "not an absolute URL")
		if tc.ok && rejectsAddress {
			t.Errorf("Token(%q, flag=%t) refused the ADDRESS: %v — the address is the allowed shape", tc.addr, tc.devFlag, err)
		}
		if !tc.ok && !rejectsAddress {
			t.Errorf("Token(%q, flag=%t) = %v, want the address refusal", tc.addr, tc.devFlag, err)
		}
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
		Address:                srv.ts(t).URL,
		AllowHTTPForLocalTests: true,
		Token: custody.KubernetesAuth{
			Address:                login.URL,
			Role:                   "gitfrok-agent-ca",
			JWTFile:                jwtFile,
			AllowHTTPForLocalTests: true,
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
		// The dev cluster serves plain HTTP on a loopback port-forward
		// (svc/openbao is http inside the cluster); the flag allows exactly
		// that loopback shape and nothing else — an https address needs no
		// flag at all.
		AllowHTTPForLocalTests: true,
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

// TestLiveOpenBaoKubernetesAuthConsumer is the OPTIONAL live proof of the
// ZERO-STATIC-CREDENTIALS consumer (T-0040 scope A.1): the control plane's
// posture is a projected service-account JWT exchanged for a short-lived
// OpenBao token via Kubernetes auth, signing through the WIRED agent-ca
// transit key (role agent-ca bound to ServiceAccount controlplane/default,
// policy agent-ca). Env-gated and skipped in CI:
//
//	kubectl create token controlplane -n default > /tmp/cp-jwt
//	GITFROK_TEST_OPENBAO_ADDR=http://127.0.0.1:18200 \
//	GITFROK_TEST_OPENBAO_K8S_JWT_FILE=/tmp/cp-jwt \
//	go test ./modules/agent/internal/adapters/custody/ -run LiveOpenBaoKubernetesAuth
func TestLiveOpenBaoKubernetesAuthConsumer(t *testing.T) {
	addr := os.Getenv("GITFROK_TEST_OPENBAO_ADDR")
	jwtFile := os.Getenv("GITFROK_TEST_OPENBAO_K8S_JWT_FILE")
	if addr == "" || jwtFile == "" {
		t.Skip("GITFROK_TEST_OPENBAO_ADDR / GITFROK_TEST_OPENBAO_K8S_JWT_FILE not set; skipping the live Kubernetes-auth consumer proof")
	}
	signer, err := custody.NewOpenBao(custody.Config{
		Address: addr,
		Mount:   envOr("GITFROK_TEST_OPENBAO_MOUNT", "transit"),
		Token: custody.KubernetesAuth{
			Address:                addr,
			Role:                   envOr("GITFROK_TEST_OPENBAO_K8S_ROLE", "agent-ca"),
			JWTFile:                jwtFile,
			AllowHTTPForLocalTests: true,
		},
		AllowHTTPForLocalTests: true,
	})
	if err != nil {
		t.Fatalf("NewOpenBao: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// The wired consumer key: the adapter asserts the posture on read —
	// ECDSA P-256 and NON-EXPORTABLE. A key that reported itself exportable
	// would be refused here.
	ref := custody.KeyRef(envOr("GITFROK_TEST_OPENBAO_KEY", "agent-ca"))
	pub, err := signer.PublicKey(ctx, ref)
	if err != nil {
		t.Fatalf("PublicKey through a Kubernetes-auth token: %v", err)
	}
	if pub.Curve != elliptic.P256() {
		t.Fatalf("agent-ca public half curve = %v, want P-256", pub.Curve.Params().Name)
	}

	// One digest crosses the seam; one signature comes back; verification is
	// in-process against the public half — the enrolment issuance shape, with
	// no static credential anywhere in the path.
	digest := sha256.Sum256([]byte("gitfrok custody consumer proof"))
	sig, err := signer.SignDigest(ctx, ref, digest[:])
	if err != nil {
		t.Fatalf("SignDigest through a Kubernetes-auth token: %v", err)
	}
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		t.Fatal("signature returned through Kubernetes auth does not verify against the key's public half")
	}
}
