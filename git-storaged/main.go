package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	gitv1 "github.com/gitfrok/backend/gen/proto/git/v1"
	repositoryv1 "github.com/gitfrok/backend/gen/proto/repository/v1"
	"github.com/gitfrok/backend/git-storaged/protection"
	"github.com/gitfrok/backend/modules/policy"
	"github.com/gitfrok/backend/modules/repository"
	"github.com/gitfrok/backend/platform/bus"
	"github.com/gitfrok/backend/platform/ids"
	"google.golang.org/grpc"
)

const (
	repositoryRootEnv = "GITFROK_GIT_STORAGE_ROOT"
	policyBundleEnv   = "GITFROK_POLICY_BUNDLE_DIR"
	listenAddressEnv  = "GITFROK_GIT_STORAGE_LISTEN_ADDR"
	nodeIDEnv         = "GITFROK_NODE_ID"
)

func main() {
	runtime, err := loadRuntime(os.Getenv)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	events := bus.NewInProcess()
	pdp, err := policy.NewOPADecisionPoint(runtime.policyBundle, events)
	if err != nil {
		fmt.Fprintf(os.Stderr, "git-storaged: policy bundle is unusable: %v\n", err)
		os.Exit(1)
	}
	// Node identity for replica coordination: explicit env, else hostname, else a fresh ULID so a
	// stray deployment never silently shares an identity with another node.
	nodeID := os.Getenv(nodeIDEnv)
	if nodeID == "" {
		if h, herr := os.Hostname(); herr == nil && h != "" {
			nodeID = h
		} else {
			nodeID = ids.NewULID()
		}
	}
	// Branch protection reaches this node only as BranchProtectionChanged. The
	// projection is subscribed before the server accepts traffic, so a rule that
	// arrives is in effect for the next push rather than the one after it.
	protectionProjection := protection.New()
	protectionProjection.Subscribe(events)

	server, err := NewServer(Config{
		RepositoryRoot: runtime.repositoryRoot,
		PDP:            pdp,
		Events:         events,
		Coordinator:    repository.NewInMemoryCoordinator(nodeID, events),
		NodeID:         nodeID,
		Protection:     protectionProjection,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	listener, err := net.Listen("tcp", runtime.listenAddress)
	if err != nil {
		fmt.Fprintf(os.Stderr, "git-storaged: listen %s: %v\n", runtime.listenAddress, err)
		os.Exit(1)
	}

	grpcServer := grpc.NewServer()
	gitv1.RegisterGitStorageServer(grpcServer, server)
	repositoryv1.RegisterRepositoryReaderServer(grpcServer, server)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		if serveErr := grpcServer.Serve(listener); serveErr != nil && !errors.Is(serveErr, grpc.ErrServerStopped) {
			fmt.Fprintf(os.Stderr, "git-storaged: serve: %v\n", serveErr)
			stop()
		}
	}()
	<-ctx.Done()
	grpcServer.GracefulStop()
}

type runtimeConfig struct {
	repositoryRoot string
	policyBundle   string
	listenAddress  string
}

func loadRuntime(getenv func(string) string) (runtimeConfig, error) {
	config := runtimeConfig{
		repositoryRoot: getenv(repositoryRootEnv),
		policyBundle:   getenv(policyBundleEnv),
		listenAddress:  getenv(listenAddressEnv),
	}
	if config.repositoryRoot == "" {
		return runtimeConfig{}, fmt.Errorf("git-storaged: %s is required", repositoryRootEnv)
	}
	if config.policyBundle == "" {
		return runtimeConfig{}, fmt.Errorf("git-storaged: %s is required", policyBundleEnv)
	}
	if config.listenAddress == "" {
		return runtimeConfig{}, fmt.Errorf("git-storaged: %s is required", listenAddressEnv)
	}
	return config, nil
}
