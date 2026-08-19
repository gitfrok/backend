package main

// The admin area's fleet report door is configured by one address, and its own
// (T-0071, SPEC-0058).
//
// A separate variable from the usage door's rather than a second service on it,
// because the two are separate promises: a deployment may serve usage without
// serving a fleet report, and a BFF that was never given this address must be
// able to say "unavailable" rather than "this tenant has no data planes". An
// empty fleet and an unreachable door are different facts, and one env var for
// both would have made them the same one.

// fleetGRPCAddrEnv names the control-plane door serving
// contracts/proto/agent/v1's FleetReader. Unset means the door is not served,
// which is a configuration choice and not a degraded state.
const fleetGRPCAddrEnv = "GITFROK_FLEET_GRPC_ADDR"

// fleetGRPCAddr reads the door's listen address. It is read through getenv rather
// than os.Getenv directly so a test can compose a plane without touching the
// process environment, which is how every other door here is configured.
func fleetGRPCAddr(getenv func(string) string) string {
	return getenv(fleetGRPCAddrEnv)
}
