package main

import (
	"fmt"
	"strconv"
	"time"

	"github.com/gitfrok/backend/modules/agent"
)

// The custody-backed CA's per-environment configuration (invariant 13, T-0040,
// SPEC-0044, ADR-0066): the OpenBao address and transit mount, the
// Kubernetes-auth role bound to this binary's ServiceAccount, and the
// bootstrap key name. The control plane authenticates with its projected
// service-account JWT — zero static credentials anywhere in this posture.
const (
	// custodyOpenBaoAddrEnv is the OpenBao custody service base URL, e.g.
	// "https://openbao.control-plane.svc:8200". Required when the agent door
	// is open: the production composition constructs ONLY the custody-backed
	// issuer (SPEC-0044 AC1, AC3).
	custodyOpenBaoAddrEnv = "GITFROK_CUSTODY_OPENBAO_ADDR"
	// custodyTransitMountEnv names the transit engine's mount path.
	custodyTransitMountEnv = "GITFROK_CUSTODY_TRANSIT_MOUNT"
	// custodyKubernetesRoleEnv is the OpenBao Kubernetes-auth role the
	// control plane logs in with.
	custodyKubernetesRoleEnv = "GITFROK_CUSTODY_KUBERNETES_ROLE"
	// custodyJWTFileEnv overrides the service-account token path; empty means
	// the standard in-cluster projection.
	custodyJWTFileEnv = "GITFROK_CUSTODY_JWT_FILE"
	// custodyKeyNameEnv is the bundle's bootstrap key name in transit.
	custodyKeyNameEnv = "GITFROK_CUSTODY_KEY_NAME"
	// custodyAllowLoopbackHTTPEnv relaxes the https transport requirement for
	// a LOOPBACK address only — the dev cluster's port-forward posture. Plain
	// http to any other address is refused outright.
	custodyAllowLoopbackHTTPEnv = "GITFROK_CUSTODY_ALLOW_LOOPBACK_HTTP"
	// custodySnapshotFileEnv is the path of the bundle's durable snapshot —
	// where the staged CA trust bundle's window state lives across a
	// control-plane restart (Wave-3 review C1). The snapshot is a tenant-less
	// platform singleton: it holds only key REFERENCES and public CA
	// certificates, and no tenant-isolated store can carry it honestly, so it
	// is an operator-configured file on the control plane's own filesystem.
	// Required when the agent door is open: an issuer with nowhere to persist
	// its window would crash-loop on the first restart.
	custodySnapshotFileEnv = "GITFROK_CUSTODY_SNAPSHOT_FILE"
)

// loadCustodyConfig reads the custody posture from the environment. An unset
// GITFROK_CUSTODY_OPENBAO_ADDR is a configuration error when the agent door
// is open: there is no dev-CA fallback in the production composition root.
func loadCustodyConfig(getenv func(string) string) (agent.CustodyCAConfig, error) {
	addr := getenv(custodyOpenBaoAddrEnv)
	if addr == "" {
		return agent.CustodyCAConfig{}, fmt.Errorf("%s is not set: the agent door issues every "+
			"identity credential through the custody service, and the production composition "+
			"constructs no other CA (SPEC-0044 AC1)", custodyOpenBaoAddrEnv)
	}
	snapshotFile := getenv(custodySnapshotFileEnv)
	if snapshotFile == "" {
		return agent.CustodyCAConfig{}, fmt.Errorf("%s is not set: the custody bundle's durable state "+
			"(key references, staged roots, issuance ledger — no private material) must persist across a "+
			"control-plane restart, and an issuer with nowhere to save it would crash-loop on one", custodySnapshotFileEnv)
	}
	allowLoopback := false
	if v := getenv(custodyAllowLoopbackHTTPEnv); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return agent.CustodyCAConfig{}, fmt.Errorf("%s must be a boolean: %w", custodyAllowLoopbackHTTPEnv, err)
		}
		allowLoopback = b
	}
	return agent.CustodyCAConfig{
		OpenBaoAddress:    addr,
		TransitMount:      getenv(custodyTransitMountEnv),
		KubernetesRole:    getenv(custodyKubernetesRoleEnv),
		JWTFile:           getenv(custodyJWTFileEnv),
		KeyName:           getenv(custodyKeyNameEnv),
		AllowHTTPLoopback: allowLoopback,
		SnapshotFile:      snapshotFile,
		Now:               time.Now,
	}, nil
}
