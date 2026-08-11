package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"

	gitv1 "github.com/gitfrok/backend/gen/proto/git/v1"
	repositoryv1 "github.com/gitfrok/backend/gen/proto/repository/v1"
	"github.com/gitfrok/backend/git-storaged/protection"
	"github.com/gitfrok/backend/modules/policy"
	"github.com/gitfrok/backend/modules/repository"
	auditsink "github.com/gitfrok/backend/platform/auditsink"
	"github.com/gitfrok/backend/platform/bus"
	"github.com/gitfrok/backend/platform/db"
	"github.com/gitfrok/backend/platform/ids"
	"github.com/gitfrok/backend/platform/objectstore"
	"google.golang.org/grpc"
)

const (
	repositoryRootEnv = "GITFROK_GIT_STORAGE_ROOT"
	policyBundleEnv   = "GITFROK_POLICY_BUNDLE_DIR"
	listenAddressEnv  = "GITFROK_GIT_STORAGE_LISTEN_ADDR"
	nodeIDEnv         = "GITFROK_NODE_ID"

	// The SeaweedFS-S3 large-object tier (SPEC-0023, ADR-0020, ADR-0033 decision
	// 4). SeaweedFS is the object store — the variables name it so a deployment
	// cannot be pointed at another provider by accident and discover the fact
	// later. All five are required together: a node configured with some of them
	// has an operator who intended LFS and a deployment that would refuse it,
	// which is worse than one that never had it.
	// The FUSE mount is the preferred tier (ADR-0050). When it is set, the S3
	// variables are ignored: two live paths to the same bytes is how one of them
	// quietly stops being tested.
	objectMountEnv = "GITFROK_SEAWEEDFS_MOUNT"

	objectEndpointEnv  = "GITFROK_SEAWEEDFS_S3_ENDPOINT"
	objectRegionEnv    = "GITFROK_SEAWEEDFS_S3_REGION"
	objectBucketEnv    = "GITFROK_SEAWEEDFS_S3_BUCKET"
	objectAccessKeyEnv = "GITFROK_SEAWEEDFS_S3_ACCESS_KEY"
	objectSecretKeyEnv = "GITFROK_SEAWEEDFS_S3_SECRET_KEY"

	// databaseURLEnv is the tenant-scoped application DSN. When set, this node
	// persists the audit events it emits (PDP refusals, RLS violations) onto the
	// Postgres trail; when absent, events are published and dropped as before.
	// The DSN must be the gitfrok_app role — a superuser would pass db.Open's
	// RLS check for the wrong reason.
	databaseURLEnv = "GITFROK_DATABASE_URL"
)

// objectTier builds the SeaweedFS-S3 store, or returns nil when this node is not
// configured for LFS.
//
// Partial configuration is an error rather than a silent fallback: an operator who
// set three of five variables meant to enable LFS, and a node that quietly served
// none would fail imports later with nothing pointing at the cause. A node with
// none of them set serves no LFS, which is a deployment choice.
func objectTier(getenv func(string) string) (ObjectStore, error) {
	// ADR-0050: large objects come from the SeaweedFS FUSE mount. The S3 adapter
	// stays for a deployment that has no mount, and stays the reference the mount
	// is compared against.
	if mount := getenv(objectMountEnv); mount != "" {
		return objectstore.NewMount(objectstore.MountConfig{Root: mount})
	}
	values := map[string]string{
		objectEndpointEnv:  getenv(objectEndpointEnv),
		objectRegionEnv:    getenv(objectRegionEnv),
		objectBucketEnv:    getenv(objectBucketEnv),
		objectAccessKeyEnv: getenv(objectAccessKeyEnv),
		objectSecretKeyEnv: getenv(objectSecretKeyEnv),
	}
	set := 0
	for _, value := range values {
		if value != "" {
			set++
		}
	}
	switch set {
	case 0:
		return nil, nil
	case len(values):
		return objectstore.New(objectstore.Config{
			Endpoint:  values[objectEndpointEnv],
			Region:    values[objectRegionEnv],
			Bucket:    values[objectBucketEnv],
			AccessKey: values[objectAccessKeyEnv],
			SecretKey: values[objectSecretKeyEnv],
		})
	default:
		missing := make([]string, 0, len(values))
		for name, value := range values {
			if value == "" {
				missing = append(missing, name)
			}
		}
		sort.Strings(missing)
		return nil, fmt.Errorf("git-storaged: the SeaweedFS-S3 tier is partly configured; missing %s", strings.Join(missing, ", "))
	}
}

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

	objects, err := objectTier(os.Getenv)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// The audit sink rides the same bus the PDP audits its refusals to. A node
	// without a database URL persists nothing — the events are still published,
	// still dropped, exactly as before. A node with one but a broken write fails
	// loudly: the PDP reports an unaudited denial as an error (ADR-0007).
	if dsn := os.Getenv(databaseURLEnv); dsn != "" {
		pool, err := db.Open(context.Background(), dsn)
		if err != nil {
			fmt.Fprintf(os.Stderr, "git-storaged: audit database: %v\n", err)
			os.Exit(1)
		}
		defer pool.Close()
		auditsink.NewSink(pool, events).Subscribe(events)
		fmt.Fprintln(os.Stderr, "git-storaged: audit sink on GITFROK_DATABASE_URL")
	}

	server, err := NewServer(Config{
		RepositoryRoot: runtime.repositoryRoot,
		PDP:            pdp,
		Events:         events,
		Coordinator:    repository.NewInMemoryCoordinator(nodeID, events),
		NodeID:         nodeID,
		Protection:     protectionProjection,
		Objects:        objects,
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
