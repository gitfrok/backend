// Command dataplane-app is the single data-plane binary (invariant 19). Modules are
// packages composed here; they are not separate services (ADR-0025).
package main

import (
	"fmt"

	agentv1 "github.com/gitfrok/backend/gen/proto/agent/v1"
	repoapi "github.com/gitfrok/backend/modules/repository/api"
)

func main() {
	// Compile-time proof that generated contracts and the module api/ compose here.
	var _ repoapi.Reader
	_ = agentv1.HealthState_HEALTHY
	fmt.Println("gitfrok dataplane-app: baseline (T-0001)")
}
