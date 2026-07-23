// Command controlplane-app is the single control-plane binary (invariant 19).
package main

import (
	"fmt"

	agentv1 "github.com/gitfrok/backend/gen/proto/agent/v1"
)

func main() {
	// The CP terminates the agent gateway stream (agent.proto); referenced to keep the
	// contract wired into the plane from commit one.
	_ = agentv1.Cloud_GKE
	fmt.Println("gitfrok controlplane-app: baseline (T-0001)")
}
