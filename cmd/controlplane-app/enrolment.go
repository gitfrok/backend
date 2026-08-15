package main

import (
	"encoding/base64"
	"fmt"
)

// enrolmentGRPCAddrEnv opens the operator enrolment-token issuance door
// (SPEC-0038 AC1) when set; an empty value means the control plane serves no
// enrolment surface and the health-only plane is unchanged. Like the residency
// Declare door it mirrors (SPEC-0043, ADR-0063), this one verifies its caller
// before any policy decision — the subject is a verified principal, never a
// wire claim (ADR-0045).
const enrolmentGRPCAddrEnv = "GITFROK_ENROLMENT_GRPC_ADDR"

// enrolmentDoorConfig is the enrolment issuance door's configuration as one
// unit: a door address without a verifier key is a half-configured boundary
// and fails the rollout (ADR-0006 fail-fast), exactly like the residency
// Declare door's.
type enrolmentDoorConfig struct {
	addr   string
	patKey []byte
}

// loadEnrolmentDoorConfig validates the door's environment: the PAT verifier
// key (the SAME credential shape the residency Declare door and the data
// plane's Git front door verify, ADR-0043) is REQUIRED whenever the door is
// open, because a door that cannot verify its caller has no business serving
// a surface that mints credentials (SPEC-0038 AC1). An unconfigured door is
// fine — the plane then serves no enrolment surface.
func loadEnrolmentDoorConfig(getenv func(string) string) (enrolmentDoorConfig, error) {
	cfg := enrolmentDoorConfig{addr: getenv(enrolmentGRPCAddrEnv)}
	if cfg.addr == "" {
		return cfg, nil
	}
	key, err := base64.StdEncoding.DecodeString(getenv(patVerifierKeyEnv))
	if err != nil || len(key) < 32 {
		return cfg, fmt.Errorf("%s requires %s holding base64 of at least 32 bytes: the enrolment "+
			"door verifies its caller before any policy decision (SPEC-0038 AC1)", enrolmentGRPCAddrEnv, patVerifierKeyEnv)
	}
	cfg.patKey = key
	return cfg, nil
}
