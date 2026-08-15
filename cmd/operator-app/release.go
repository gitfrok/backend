package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Release is one signed release manifest — the exact artifact
// deploy/releases/*.release carries and scripts/sign-release.sh writes:
// component, version, oci_ref, digest, signature. The signature covers the
// canonical identity `oci_ref@digest` (ECDSA over SHA-256, DER, base64) — the
// same string the control-plane rollout verifier hashes and
// check-signed-releases.sh re-verifies, so one identity has three verifiers
// and no drift (T-0032).
type Release struct {
	Component string
	Version   string
	OCIRef    string
	Digest    string
	// SignatureDER is the decoded signature bytes; empty means UNSIGNED.
	SignatureDER []byte
}

// CanonicalIdentity is the string the signature covers. It is also the exact
// image reference the applier converges the workload onto: a digest pin,
// never a mutable tag (ADR-0065 decision 1).
func (r Release) CanonicalIdentity() string { return r.OCIRef + "@" + r.Digest }

// ParseRelease parses the key=value manifest shape. Any missing identity
// field is malformed; an empty signature is unsigned. Both are refusals the
// reconciler renders on the CR status — a release that does not say what it
// is cannot be applied.
func ParseRelease(data []byte) (Release, error) {
	var r Release
	var sigB64 string
	for line := range strings.SplitSeq(string(data), "\n") {
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key, val = strings.TrimSpace(key), strings.TrimSpace(val)
		switch key {
		case "component":
			r.Component = val
		case "version":
			r.Version = val
		case "oci_ref":
			r.OCIRef = val
		case "digest":
			r.Digest = val
		case "signature":
			sigB64 = val
		}
	}
	for name, v := range map[string]string{
		"component": r.Component, "version": r.Version, "oci_ref": r.OCIRef, "digest": r.Digest,
	} {
		if v == "" {
			return Release{}, fmt.Errorf("malformed release manifest: missing %s", name)
		}
	}
	if sigB64 == "" {
		return Release{}, fmt.Errorf("unsigned release %s@%s: no signature line — not applicable (SPEC-0039 AC3)", r.Component, r.Version)
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return Release{}, fmt.Errorf("signature is not valid base64: %w", err)
	}
	r.SignatureDER = sig
	return r, nil
}

// ManifestSource yields the release manifest for one component and version.
// The agent channel delivers manifests onto the data plane; where they land is
// a deployment detail the reconciler does not care about.
type ManifestSource interface {
	Manifest(ctx context.Context, component, version string) (Release, error)
}

// DirManifestSource reads manifests from a directory, one
// `<component>-<version>.release` file each — the shape deploy/releases uses.
type DirManifestSource string

// Manifest implements ManifestSource over the directory. The version arrives
// from the CR's spec.version — control-plane-published desired state — so it
// is sanitized before it may name a file: no separators, no traversal.
func (d DirManifestSource) Manifest(_ context.Context, component, version string) (Release, error) {
	for _, v := range []string{component, version} {
		if strings.ContainsAny(v, "/\\") || v == ".." || v == "" {
			return Release{}, fmt.Errorf("refusing release lookup for %q@%q: identity fields may not name paths", component, version)
		}
	}
	name := fmt.Sprintf("%s-%s.release", component, version)
	data, err := os.ReadFile(filepath.Join(string(d), name))
	if err != nil {
		return Release{}, fmt.Errorf("release manifest for %s@%s: %w", component, version, err)
	}
	return ParseRelease(data)
}
