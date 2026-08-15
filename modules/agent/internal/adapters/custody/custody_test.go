package custody_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gitfrok/backend/modules/agent/api"
	"github.com/gitfrok/backend/modules/agent/internal/adapters/custody"
)

// clock is the injectable clock every window decision in these tests reads.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock {
	return &clock{t: time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)}
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

var testIdentity = api.Identity{TenantID: "tenant-a", DataPlaneID: "plane-1"}

// newTestCA bootstraps one custody-backed issuer over the CI fake — the
// shape SPEC-0044's KMS-fake tests exercise: never the production provider.
func newTestCA(t *testing.T, keyName string) (*custody.FakeSigner, *custody.Bundle, *custody.Issuer, *clock) {
	t.Helper()
	fake := custody.NewFakeSigner()
	clk := newClock()
	bundle, err := custody.NewBundle(fake, clk.Now)
	if err != nil {
		t.Fatalf("NewBundle: %v", err)
	}
	if _, err := bundle.Bootstrap(context.Background(), keyName); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	issuer, err := custody.NewIssuer(bundle)
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	return fake, bundle, issuer, clk
}

// issueOne mints one certificate through the custody seam and returns it
// with its parsed leaf.
func issueOne(t *testing.T, issuer *custody.Issuer, clk *clock, lifetime time.Duration) (api.IssuedCertificate, *x509.Certificate) {
	t.Helper()
	cert, err := issuer.Issue(context.Background(), testIdentity, clk.Now(), lifetime, time.Minute)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	block, _ := pem.Decode(cert.PEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("issued bundle does not begin with a CERTIFICATE block")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse issued leaf: %v", err)
	}
	return cert, leaf
}

// privateMaterialType reports whether typ is, or contains, ECDSA private key
// material — the one type the references-not-material posture forbids in any
// state this package holds or returns.
func privateMaterialType(typ reflect.Type) bool {
	priv := reflect.TypeOf((*ecdsa.PrivateKey)(nil))
	var walk func(t reflect.Type, seen map[reflect.Type]bool) bool
	walk = func(t reflect.Type, seen map[reflect.Type]bool) bool {
		if seen[t] {
			return false
		}
		seen[t] = true
		if t == priv || t == priv.Elem() {
			return true
		}
		switch t.Kind() {
		case reflect.Pointer, reflect.Slice, reflect.Array, reflect.Chan, reflect.Map:
			return walk(t.Elem(), seen)
		case reflect.Struct:
			for i := 0; i < t.NumField(); i++ {
				if walk(t.Field(i).Type, seen) {
					return true
				}
			}
		}
		return false
	}
	return walk(typ, map[reflect.Type]bool{})
}

// TestSeamNeverReturnsPrivateMaterial is AC1's shape assertion over the seam
// itself (ADR-0064 decision 2): no exported method of either Signer
// implementation — nor of the Bundle/Issuer state they build — can return
// ECDSA private key material. References in, public halves and signatures
// out; that is the whole surface.
func TestSeamNeverReturnsPrivateMaterial(t *testing.T) {
	impls := []any{custody.NewFakeSigner(), &custody.OpenBao{}}
	for _, impl := range impls {
		typ := reflect.TypeOf(impl)
		for i := 0; i < typ.NumMethod(); i++ {
			m := typ.Method(i)
			for j := 0; j < m.Type.NumOut(); j++ {
				if privateMaterialType(m.Type.Out(j)) {
					t.Errorf("%T.%s returns private key material — the seam must stay references-only", impl, m.Name)
				}
			}
		}
	}
	// The state the CA holds between calls: bundle, roots, snapshots, issuer.
	state := []any{custody.Bundle{}, custody.Root{}, custody.Snapshot{}, custody.SnapshotRoot{}, custody.Issuer{}}
	for _, s := range state {
		if privateMaterialType(reflect.TypeOf(s)) {
			t.Errorf("%T carries private key material — the CA must hold references only", s)
		}
	}
}

// TestOpenBaoConfigCarriesNoKeyMaterial: the production signer is
// constructed from an address and an auth source alone — there is no field a
// private key could arrive through. A file path or env var carrying key
// material has nowhere to plug in (AC1's fitness shape; the full
// composition-root fitness assertion lands with the composition swap wave).
func TestOpenBaoConfigCarriesNoKeyMaterial(t *testing.T) {
	if privateMaterialType(reflect.TypeOf(custody.Config{})) {
		t.Fatal("custody.Config carries private key material fields")
	}
	if privateMaterialType(reflect.TypeOf(&custody.OpenBao{}).Elem()) {
		t.Fatal("custody.OpenBao holds private key material")
	}
}

// TestIssuancePathHoldsReferencesNotMaterial is AC1 against the fake
// (SPEC-0044 Test plan): one issuance generates exactly one custody key,
// reads its public half, ships one 32-byte digest across the seam, and gets
// one signature back — and the issuer's own state names the key by
// REFERENCE only.
func TestIssuancePathHoldsReferencesNotMaterial(t *testing.T) {
	fake, bundle, issuer, clk := newTestCA(t, "agent-ca-gen1")

	gen, pub, sig := fake.Counts()
	if gen != 1 {
		t.Fatalf("bootstrap generated %d keys, want exactly 1", gen)
	}

	cert, leaf := issueOne(t, issuer, clk, 24*time.Hour)

	// The seam saw a digest, never a whole credential: 32 bytes, SHA-256.
	if got := fake.LastDigestLength(); got != 32 {
		t.Errorf("seam saw %d bytes for signing, want a 32-byte SHA-256 digest", got)
	}
	if gen2, pub2, sig2 := fake.Counts(); gen2 != gen || pub2 <= pub || sig2 != sig+1 {
		t.Errorf("one issuance must add exactly one public read and one signature (gen %d->%d, pub %d->%d, sig %d->%d)",
			gen, gen2, pub, pub2, sig, sig2)
	}

	// The issuer names its signing key by reference, and the custody service
	// resolves that reference — the key itself never crossed.
	ref, caCert, err := bundle.IssuanceRoot()
	if err != nil {
		t.Fatalf("IssuanceRoot: %v", err)
	}
	if string(ref) != "agent-ca-gen1" {
		t.Errorf("issuance root reference = %q, want %q", ref, "agent-ca-gen1")
	}
	if !fake.HasKey(ref) {
		t.Error("custody service does not resolve the reference the issuer holds")
	}
	if leaf.CheckSignatureFrom(caCert) != nil {
		t.Error("issued leaf does not chain to the custody-backed root")
	}
	if cert.ExpiresAt != clk.Now().Add(24*time.Hour) {
		t.Errorf("ExpiresAt = %v, want %v", cert.ExpiresAt, clk.Now().Add(24*time.Hour))
	}

	// The issued bundle carries leaf, chain and the DATA PLANE's key — and
	// nothing else: three PEM blocks, no CA private key among them.
	blocks := pemBlocks(cert.PEM)
	if len(blocks) != 3 {
		t.Fatalf("issued bundle has %d PEM blocks, want 3 (leaf, ca, leaf key)", len(blocks))
	}
	if blocks[2].Type != "EC PRIVATE KEY" {
		t.Errorf("third block is %q, want the data plane's EC PRIVATE KEY", blocks[2].Type)
	}
	// Exactly one private key in the bundle: the data plane's. "PRIVATE KEY"
	// appears twice per block (BEGIN and END), so two occurrences, no more.
	if got := strings.Count(string(cert.PEM), "PRIVATE KEY"); got != 2 {
		t.Errorf("issued bundle names %d private-key markers, want exactly one key block (2)", got)
	}
}

func pemBlocks(pemBytes []byte) []*pem.Block {
	var out []*pem.Block
	rest := pemBytes
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			return out
		}
		out = append(out, b)
	}
}

// TestCustodyIssuerDropInSemantics proves the custody issuer is a peer of
// pki.DevCA on the api.CertificateIssuer surface: identity round-trips
// through the subject encoding, trust precedes window classification, and a
// forged chain is an error, never a validity classification.
func TestCustodyIssuerDropInSemantics(t *testing.T) {
	_, _, issuer, clk := newTestCA(t, "agent-ca-semantics")

	cert, leaf := issueOne(t, issuer, clk, time.Hour)

	id, expiry, err := issuer.Inspect(leaf.Raw)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if id != testIdentity {
		t.Errorf("Inspect identity = %+v, want %+v", id, testIdentity)
	}
	if !expiry.Equal(cert.ExpiresAt) {
		t.Errorf("Inspect expiry = %v, want %v", expiry, cert.ExpiresAt)
	}

	leafDER, validity, err := issuer.VerifyChain([][]byte{leaf.Raw}, clk.Now())
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if validity != api.ValidNow || !reflect.DeepEqual(leafDER, leaf.Raw) {
		t.Errorf("VerifyChain = (%v, %v), want (ValidNow, leaf)", validity, leafDER)
	}

	// A trusted leaf past its window is CLASSIFIED, not errored.
	clk.Advance(2 * time.Hour)
	_, validity, err = issuer.VerifyChain([][]byte{leaf.Raw}, clk.Now())
	if err != nil || validity != api.ValidityExpired {
		t.Errorf("expired trusted leaf = (%v, %v), want (ValidityExpired, nil)", validity, err)
	}
	clk.Advance(-2 * time.Hour)

	// A forged, self-signed leaf with a victim subject is an ERROR: trust is
	// established before the window is classified (SPEC-0038 AC5/AC7).
	_, forged := issueOne(t, issuer, clk, time.Hour)
	forged.Raw[len(forged.Raw)-1] ^= 0x01 // corrupt, keep it parsable-looking
	if _, _, err := issuer.VerifyChain([][]byte{forged.Raw}, clk.Now()); err == nil {
		t.Error("forged chain verified — trust must precede window classification")
	}
}

// TestIdentityMustNameTenantAndDataPlane guards the issuance precondition
// DevCA states: a certificate names both halves of the identity or nothing.
func TestIdentityMustNameTenantAndDataPlane(t *testing.T) {
	_, _, issuer, clk := newTestCA(t, "agent-ca-identity")
	for _, id := range []api.Identity{{}, {TenantID: "only-tenant"}, {DataPlaneID: "only-plane"}} {
		if _, err := issuer.Issue(context.Background(), id, clk.Now(), time.Hour, 0); err == nil {
			t.Errorf("Issue(%+v) succeeded, want refusal", id)
		}
	}
}

// TestStagingOntoAnExistingKeyNameRefused: rotation stages a NEW key; a
// second Bootstrap/Stage onto the same name is the fake's ErrKeyExists
// refusal, loud rather than silent.
func TestStagingOntoAnExistingKeyNameRefused(t *testing.T) {
	_, bundle, _, _ := newTestCA(t, "agent-ca-once")
	if _, err := bundle.Bootstrap(context.Background(), "somewhere-else"); err == nil {
		t.Fatal("second Bootstrap succeeded, want refusal")
	}
	if _, err := bundle.Stage(context.Background(), "agent-ca-once"); !errors.Is(err, custody.ErrKeyExists) {
		t.Errorf("Stage onto an existing name = %v, want ErrKeyExists", err)
	}
}
