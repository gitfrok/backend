// Command controlplane-app is the single control-plane binary (invariant 19).
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/gitfrok/backend/cmd/internal/health"
	agentv1 "github.com/gitfrok/backend/gen/proto/agent/v1"
)

const listenAddrEnv = "GITFROK_LISTEN_ADDR"

func main() {
	// The CP terminates the agent gateway stream (agent.proto); referenced to keep the
	// contract wired into the plane from commit one.
	_ = agentv1.Cloud_CLOUD_GKE
	fmt.Println("gitfrok controlplane-app: baseline (T-0001)")
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := health.Run(ctx, health.ListenAddr(os.Getenv(listenAddrEnv))); err != nil {
		fmt.Fprintf(os.Stderr, "controlplane health server: %v\n", err)
		os.Exit(1)
	}
}
