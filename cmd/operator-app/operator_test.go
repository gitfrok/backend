// T-0041 / SPEC-0045 AC1: the operator applies only SIGNED, digest-pinned
// releases, verifying against a pinned release trust bundle it refuses to
// start without. The signing key these tests generate is THROWAWAY material,
// created inside the test's temp directory and never written into the tree —
// the same posture scripts/sign-release.sh takes with the real key.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// --- fakes -------------------------------------------------------------------

type fakeApplier struct {
	current string
	exists  bool
	applied []string // every digest pin handed to ApplyWorkloadImage
	fail    error
}

func (f *fakeApplier) CurrentWorkloadImage(context.Context) (string, bool, error) {
	return f.current, f.exists, nil
}

func (f *fakeApplier) ApplyWorkloadImage(_ context.Context, image string) error {
	if f.fail != nil {
		return f.fail
	}
	f.applied = append(f.applied, image)
	f.current, f.exists = image, true
	return nil
}

type fakeStatus struct{ reports []StatusReport }

func (f *fakeStatus) WriteStatus(_ context.Context, r StatusReport) error {
	f.reports = append(f.reports, r)
	return nil
}

type fixedVersion string

func (v fixedVersion) DesiredVersion(context.Context) (string, error) { return string(v), nil }

type memManifests map[string]Release

func (m memManifests) Manifest(_ context.Context, component, version string) (Release, error) {
	r, ok := m[component+"@"+version]
	if !ok {
		return Release{}, fmt.Errorf("no manifest for %s@%s", component, version)
	}
	return r, nil
}

// --- signing helpers (throwaway key, test-local) ------------------------------

func writePubKey(t *testing.T, dir string, pub *ecdsa.PublicKey) {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	if err := os.WriteFile(filepath.Join(dir, "release-signing-test.pub"), pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
}

func signIdentity(t *testing.T, key *ecdsa.PrivateKey, identity string) []byte {
	t.Helper()
	h := sha256.Sum256([]byte(identity))
	sig, err := ecdsa.SignASN1(rand.Reader, key, h[:])
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func newTrustDir(t *testing.T) (dir string, key *ecdsa.PrivateKey) {
	t.Helper()
	dir = t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	writePubKey(t, dir, &key.PublicKey)
	return dir, key
}

func signedRelease(key *ecdsa.PrivateKey, component, version, ociRef, digest string) Release {
	rel := Release{Component: component, Version: version, OCIRef: ociRef, Digest: digest}
	sig := signIdentityNoFatal(key, rel.CanonicalIdentity())
	rel.SignatureDER = sig
	return rel
}

func signIdentityNoFatal(key *ecdsa.PrivateKey, identity string) []byte {
	h := sha256.Sum256([]byte(identity))
	sig, _ := ecdsa.SignASN1(rand.Reader, key, h[:])
	return sig
}

func newReconciler(bundle *ReleaseTrustBundle, rel Release, applier *fakeApplier, status *fakeStatus) *Reconciler {
	return &Reconciler{
		Bundle:    bundle,
		Manifests: memManifests{rel.Component + "@" + rel.Version: rel},
		Desired:   fixedVersion(rel.Version),
		Applier:   applier,
		Status:    status,
		Component: rel.Component,
		Now:       time.Now,
		Logf:      func(string, ...any) {},
		SyncEvery: time.Second,
	}
}

// --- the AC1 assertions --------------------------------------------------------

// TestStartupRefusesWithoutPinnedTrustBundle: the trust bundle is a STARTUP
// requirement. An absent directory, an empty one, and one holding private
// material all refuse — an operator with no verification key cannot run.
func TestStartupRefusesWithoutPinnedTrustBundle(t *testing.T) {
	if _, err := LoadReleaseTrustBundle(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("an absent trust directory must refuse startup")
	}
	if _, err := LoadReleaseTrustBundle(t.TempDir()); err == nil {
		t.Fatal("an empty trust directory must refuse startup — the operator cannot verify anything")
	}

	// Private material in the bundle is a custody breach and is refused.
	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "leaked.pub"),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadReleaseTrustBundle(dir); err == nil {
		t.Fatal("private key material in the verification bundle must be refused")
	}

	// A well-formed bundle loads.
	goodDir, _ := newTrustDir(t)
	b, err := LoadReleaseTrustBundle(goodDir)
	if err != nil || b.Size() != 1 {
		t.Fatalf("well-formed bundle = (%v, %v), want one key", b, err)
	}
}

// TestVerifyBeforeApplyAndDigestPin: a correctly signed release is verified
// BEFORE apply, and the applier receives the DIGEST PIN — never a tag.
func TestVerifyBeforeApplyAndDigestPin(t *testing.T) {
	dir, key := newTrustDir(t)
	bundle, err := LoadReleaseTrustBundle(dir)
	if err != nil {
		t.Fatal(err)
	}
	const digest = "sha256:ab12"
	rel := signedRelease(key, "dataplane-app", "0.2.0", "docker.io/gitfrok/dataplane-app", digest)

	applier, status := &fakeApplier{}, &fakeStatus{}
	r := newReconciler(bundle, rel, applier, status)
	if err := r.ReconcileOnce(context.Background()); err != nil {
		t.Fatalf("ReconcileOnce: %v", err)
	}
	if len(applier.applied) != 1 || applier.applied[0] != "docker.io/gitfrok/dataplane-app@"+digest {
		t.Fatalf("applied = %v, want exactly the digest pin docker.io/gitfrok/dataplane-app@%s", applier.applied, digest)
	}
	last := status.reports[len(status.reports)-1]
	if last.Phase != PhaseApplied || last.ObservedVersion != "0.2.0" {
		t.Fatalf("status = %+v, want Applied/0.2.0", last)
	}
}

// TestMisSignedReleaseRefusedBeforeApply: a release signed by a key OUTSIDE
// the pinned bundle never reaches the applier; the CR reads Failed.
func TestMisSignedReleaseRefusedBeforeApply(t *testing.T) {
	dir, _ := newTrustDir(t)
	bundle, err := LoadReleaseTrustBundle(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Signed by an attacker key the bundle does not trust.
	attacker, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rel := signedRelease(attacker, "dataplane-app", "6.6.6", "docker.io/attacker/dataplane-app", "sha256:dead")

	applier, status := &fakeApplier{}, &fakeStatus{}
	r := newReconciler(bundle, rel, applier, status)
	if err := r.ReconcileOnce(context.Background()); err == nil {
		t.Fatal("a mis-signed release must be refused")
	}
	if len(applier.applied) != 0 {
		t.Fatalf("the applier was called %d times for a mis-signed release — verification must precede application", len(applier.applied))
	}
	last := status.reports[len(status.reports)-1]
	if last.Phase != PhaseFailed || last.ObservedVersion != "" {
		t.Fatalf("status = %+v, want Failed with no observed version", last)
	}
}

// TestUnsignedManifestRefused: a manifest with no signature line is unsigned
// and not applicable — the exact refusal the super-repo gate asserts.
func TestUnsignedManifestRefused(t *testing.T) {
	_, err := ParseRelease([]byte("component=x\nversion=1\noci_ref=r\ndigest=sha256:d\n"))
	if err == nil {
		t.Fatal("a manifest without a signature line must be refused as unsigned")
	}
	_, err = ParseRelease([]byte("component=x\nversion=1\ndigest=sha256:d\nsignature=QUJD\n"))
	if err == nil {
		t.Fatal("a manifest missing its oci_ref must be refused as malformed")
	}
}

// TestIdempotentConvergence: applying the SAME signed release twice causes no
// second rollout — the second pass observes and heartbeats only.
func TestIdempotentConvergence(t *testing.T) {
	dir, key := newTrustDir(t)
	bundle, err := LoadReleaseTrustBundle(dir)
	if err != nil {
		t.Fatal(err)
	}
	rel := signedRelease(key, "dataplane-app", "0.2.0", "docker.io/gitfrok/dataplane-app", "sha256:ab12")

	applier, status := &fakeApplier{}, &fakeStatus{}
	r := newReconciler(bundle, rel, applier, status)
	if err := r.ReconcileOnce(context.Background()); err != nil {
		t.Fatalf("first pass: %v", err)
	}
	if err := r.ReconcileOnce(context.Background()); err != nil {
		t.Fatalf("second pass: %v", err)
	}
	if len(applier.applied) != 1 {
		t.Fatalf("the workload was applied %d times, want 1 — convergence is idempotent", len(applier.applied))
	}
	last := status.reports[len(status.reports)-1]
	if last.Phase != PhaseUpToDate {
		t.Fatalf("second pass phase = %q, want UpToDate", last.Phase)
	}
}

// TestReleaseManifestRoundTrip: the manifest parser accepts exactly the shape
// scripts/sign-release.sh writes (component/version/oci_ref/digest/signature).
func TestReleaseManifestRoundTrip(t *testing.T) {
	manifest := "component=dataplane-app\nversion=0.1.0\n" +
		"oci_ref=docker.io/gitfrok/dataplane-app\n" +
		"digest=sha256:e936\n" +
		"signature=" + base64.StdEncoding.EncodeToString([]byte("sig-bytes")) + "\n"
	rel, err := ParseRelease([]byte(manifest))
	if err != nil {
		t.Fatalf("ParseRelease: %v", err)
	}
	if rel.CanonicalIdentity() != "docker.io/gitfrok/dataplane-app@sha256:e936" {
		t.Fatalf("canonical identity = %q", rel.CanonicalIdentity())
	}
}

// TestReleaseLookupRefusesPathShapedVersions: spec.version is desired state,
// not a path — separators and traversal are refused before any file read.
func TestReleaseLookupRefusesPathShapedVersions(t *testing.T) {
	src := DirManifestSource(t.TempDir())
	for _, bad := range []string{"../etc/passwd", "a/b", ".."} {
		if _, err := src.Manifest(context.Background(), "dataplane-app", bad); err == nil {
			t.Fatalf("version %q must be refused", bad)
		}
	}
}
