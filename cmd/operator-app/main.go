// Command operator-app is the first-party data-plane operator (T-0041, SPEC-0045 AC1,
// ADR-0065 decision 1): a narrow reconciler that converges the data-plane workload onto
// SIGNED, digest-pinned releases and reports what it observes back on the DataPlane CR.
//
// The shape it re-asserts is the outbound-only boundary (ADR-0011): the operator opens no
// listener, no Service, no inbound path of any kind. Its desired state arrives as release
// manifests the agent channel delivered; its only network conversation is with the
// cluster's own API server. It ships as a vendor-signed, digest-pinned image itself —
// deploy/releases/operator-app-*.release — so the install no longer depends on a
// customer-supplied operator image.
//
// Startup is fail-closed: without a PINNED release trust bundle (GITFROK_RELEASE_TRUST_DIR)
// the operator refuses to start, because an operator that cannot verify a release has no
// business applying one (SPEC-0039 AC3).
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("operator-app: %v", err)
	}
}

func run() error {
	// The pinned trust bundle is a STARTUP requirement, not a lazy lookup: without it the
	// operator cannot tell a signed release from an unsigned one, so it must not run.
	trustDir := os.Getenv("GITFROK_RELEASE_TRUST_DIR")
	if trustDir == "" {
		return fmt.Errorf("GITFROK_RELEASE_TRUST_DIR is required: the operator applies only releases verified against a pinned release trust bundle (SPEC-0039 AC3)")
	}
	bundle, err := LoadReleaseTrustBundle(trustDir)
	if err != nil {
		return fmt.Errorf("release trust bundle: %w", err)
	}
	log.Printf("operator-app: release trust bundle pinned from %s (%d verification key(s))", trustDir, bundle.Size())

	manifestDir := envOr("GITFROK_RELEASE_MANIFEST_DIR", "/var/gitfrok/releases")
	namespace := os.Getenv("GITFROK_OPERATOR_NAMESPACE")
	if namespace == "" {
		return fmt.Errorf("GITFROK_OPERATOR_NAMESPACE is required")
	}
	workload := envOr("GITFROK_WORKLOAD_DEPLOYMENT", "gitfrok-dataplane")
	crName := envOr("GITFROK_DATAPLANE_NAME", "gitfrok-dataplane")
	container := envOr("GITFROK_WORKLOAD_CONTAINER", "dataplane")

	ctx := context.Background()
	plane, err := newKubePlane(ctx, namespace, workload, container, crName)
	if err != nil {
		return fmt.Errorf("kubernetes client: %w", err)
	}

	r := &Reconciler{
		Bundle:    bundle,
		Manifests: DirManifestSource(manifestDir),
		Desired:   plane,
		Applier:   plane,
		Status:    plane,
		Component: "dataplane-app",
		Now:       time.Now,
		Logf:      log.Printf,
		SyncEvery: 30 * time.Second,
	}
	log.Printf("operator-app: reconciling %s/%s onto signed releases of %s (outbound-only; no inbound surface)", namespace, workload, manifestDir)
	return r.Run(ctx)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
