package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	gitv1 "github.com/gitfrok/backend/gen/proto/git/v1"
	policyv1 "github.com/gitfrok/backend/gen/proto/policy/v1"
	"github.com/gitfrok/backend/internal/gitfrontdoor"
	identityapi "github.com/gitfrok/backend/modules/identity/api"
	"github.com/gitfrok/backend/modules/policy"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
	"github.com/gitfrok/backend/platform/ids"
	"github.com/gitfrok/backend/platform/objectstore"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Git front-door and policy-door configuration (ADR-0041). Every value is
// per-environment configuration (invariant 13); an unconfigured plane serves
// only health.
const (
	gitStorageAddrEnv   = "GITFROK_GIT_STORAGE_ADDR"
	gitHTTPAddrEnv      = "GITFROK_GIT_HTTP_ADDR"
	gitSSHAddrEnv       = "GITFROK_GIT_SSH_ADDR"
	gitSSHHostKeyEnv    = "GITFROK_GIT_SSH_HOST_KEY_PATH"
	sshVerifierKeyIDEnv = "GITFROK_SSH_VERIFIER_KEY_ID"
	patVerifierKeyEnv   = "GITFROK_PAT_VERIFIER_KEY"
	policyGRPCAddrEnv   = "GITFROK_POLICY_GRPC_ADDR"

	// The SeaweedFS-S3 tier the LFS batch endpoint hands credentials for
	// (SPEC-0023, ADR-0020). SeaweedFS is the object store, and the variable names
	// say so. All five together, or none.
	// The FUSE mount is the tier (ADR-0050); the S3 variables below serve a plane
	// that has no mount.
	objectMountEnv = "GITFROK_SEAWEEDFS_MOUNT"

	objectEndpointEnv  = "GITFROK_SEAWEEDFS_S3_ENDPOINT"
	objectRegionEnv    = "GITFROK_SEAWEEDFS_S3_REGION"
	objectBucketEnv    = "GITFROK_SEAWEEDFS_S3_BUCKET"
	objectAccessKeyEnv = "GITFROK_SEAWEEDFS_S3_ACCESS_KEY"
	objectSecretKeyEnv = "GITFROK_SEAWEEDFS_S3_SECRET_KEY"
)

// objectTier is the shape both large-object adapters satisfy. It lives here
// rather than in the platform package because it is this composition root's
// requirement — the batch surface needs a presigner, and the proxied path needs
// bytes (ADR-0050).
type objectTier interface {
	Stat(ctx context.Context, key string) (int64, error)
	Presign(method, key string, ttl time.Duration) (string, error)
	Get(ctx context.Context, key string) (io.ReadCloser, int64, error)
	Put(ctx context.Context, key string, size int64, sha256Hex string, body io.Reader) (int64, error)
}

type frontDoorConfig struct {
	storageAddr   string
	httpAddr      string
	sshAddr       string
	sshHostKey    string
	verifierKeyID string
	patKey        []byte
	policyAddr    string
	// objects is the large-object tier: a SeaweedFS FUSE mount (ADR-0050), or the
	// S3 gateway when no mount is configured. Nil means this plane serves no LFS
	// batch endpoint at all, rather than one that answers with actions nothing can
	// honour.
	objects objectTier
}

func (c frontDoorConfig) enabled() bool {
	return c.httpAddr != "" || c.sshAddr != "" || c.policyAddr != ""
}

// loadFrontDoorConfig validates the front-door environment as one unit: a
// partially configured door fails the rollout rather than serving half a
// boundary (ADR-0006 fail-fast posture).
func loadFrontDoorConfig(getenv func(string) string) (frontDoorConfig, error) {
	cfg := frontDoorConfig{
		storageAddr:   getenv(gitStorageAddrEnv),
		httpAddr:      getenv(gitHTTPAddrEnv),
		sshAddr:       getenv(gitSSHAddrEnv),
		sshHostKey:    getenv(gitSSHHostKeyEnv),
		verifierKeyID: getenv(sshVerifierKeyIDEnv),
		policyAddr:    getenv(policyGRPCAddrEnv),
	}
	if !cfg.enabled() {
		if cfg.storageAddr != "" {
			return cfg, fmt.Errorf("%s is set but no listener is configured (%s, %s, or %s)", gitStorageAddrEnv, gitHTTPAddrEnv, gitSSHAddrEnv, policyGRPCAddrEnv)
		}
		return cfg, nil
	}
	if cfg.httpAddr != "" || cfg.sshAddr != "" {
		if cfg.storageAddr == "" {
			return cfg, fmt.Errorf("a Git transport listener requires %s", gitStorageAddrEnv)
		}
		key, err := base64.StdEncoding.DecodeString(getenv(patVerifierKeyEnv))
		if err != nil || len(key) < 32 {
			return cfg, fmt.Errorf("%s must hold base64 of at least 32 bytes when a Git transport is configured", patVerifierKeyEnv)
		}
		cfg.patKey = key
	}
	if cfg.sshAddr != "" && cfg.verifierKeyID == "" {
		return cfg, fmt.Errorf("the SSH listener requires %s", sshVerifierKeyIDEnv)
	}

	// ADR-0050: the mount is the tier when it is configured, and the S3 variables
	// are then ignored rather than quietly forming a second live path to the same
	// bytes.
	if mount := getenv(objectMountEnv); mount != "" {
		tier, err := objectstore.NewMount(objectstore.MountConfig{Root: mount})
		if err != nil {
			return cfg, err
		}
		cfg.objects = tier
		return cfg, nil
	}

	// The SeaweedFS-S3 tier, all-or-nothing for the same reason the doors are: a plane
	// configured with three of five values has an operator who intended LFS and a
	// deployment that would refuse it (SPEC-0023).
	objectValues := map[string]string{
		objectEndpointEnv:  getenv(objectEndpointEnv),
		objectRegionEnv:    getenv(objectRegionEnv),
		objectBucketEnv:    getenv(objectBucketEnv),
		objectAccessKeyEnv: getenv(objectAccessKeyEnv),
		objectSecretKeyEnv: getenv(objectSecretKeyEnv),
	}
	set, missing := 0, []string{}
	for name, value := range objectValues {
		if value != "" {
			set++
		} else {
			missing = append(missing, name)
		}
	}
	switch set {
	case 0:
	case len(objectValues):
		store, err := objectstore.New(objectstore.Config{
			Endpoint:  objectValues[objectEndpointEnv],
			Region:    objectValues[objectRegionEnv],
			Bucket:    objectValues[objectBucketEnv],
			AccessKey: objectValues[objectAccessKeyEnv],
			SecretKey: objectValues[objectSecretKeyEnv],
		})
		if err != nil {
			return cfg, err
		}
		cfg.objects = store
	default:
		sort.Strings(missing)
		return cfg, fmt.Errorf("the SeaweedFS-S3 tier is partly configured; missing %s", strings.Join(missing, ", "))
	}
	return cfg, nil
}

// gitFrontDoors owns the listeners the data plane serves for ADR-0041's
// boundary: Smart-HTTP, SSH, and the PDP's gRPC door for out-of-process PEPs.
type gitFrontDoors struct {
	httpListener   net.Listener
	httpServer     *http.Server
	sshListener    net.Listener
	policyListener net.Listener
	policyServer   *grpc.Server
	conn           *grpc.ClientConn
	// storageClient is the Git storage contract this plane already dials for the
	// front doors. Code Review completes a merge over the same connection, so the
	// plane keeps exactly one route to storage.
	storageClient gitv1.GitStorageClient
}

func (d *gitFrontDoors) HTTPAddr() string {
	if d.httpListener == nil {
		return ""
	}
	return d.httpListener.Addr().String()
}

func (d *gitFrontDoors) SSHAddr() string {
	if d.sshListener == nil {
		return ""
	}
	return d.sshListener.Addr().String()
}

func (d *gitFrontDoors) PolicyAddr() string {
	if d.policyListener == nil {
		return ""
	}
	return d.policyListener.Addr().String()
}

func (d *gitFrontDoors) Close() {
	if d.httpServer != nil {
		_ = d.httpServer.Close()
	}
	if d.sshListener != nil {
		_ = d.sshListener.Close()
	}
	if d.policyServer != nil {
		d.policyServer.Stop()
	}
	if d.conn != nil {
		_ = d.conn.Close()
	}
}

// startGitFrontDoors binds the configured doors. The authenticator is built
// by the caller so credential lifecycle and transport share one Identity
// composition; pdp serves the policy door and must be the plane's decision
// point. records is the decision-provenance surface served alongside it
// (T-0025): nil on a composition without one, in which case the provenance
// RPCs report Unimplemented while Decide still serves.
func startGitFrontDoors(ctx context.Context, cfg frontDoorConfig, authenticator identityapi.Authenticator, pdp policyapi.DecisionPoint, records policyapi.DecisionRecords) (*gitFrontDoors, error) {
	doors := &gitFrontDoors{}
	if !cfg.enabled() {
		return doors, nil
	}

	var storage gitfrontdoor.Storage
	if cfg.storageAddr != "" {
		conn, err := grpc.NewClient(cfg.storageAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			doors.Close()
			return nil, fmt.Errorf("git storage connection: %w", err)
		}
		doors.conn = conn
		doors.storageClient = gitv1.NewGitStorageClient(conn)
		storage = gitfrontdoor.GRPCStorage{Client: doors.storageClient}
	}
	router := gitfrontdoor.Router{Authenticator: authenticator}

	if cfg.httpAddr != "" {
		listener, err := net.Listen("tcp", cfg.httpAddr)
		if err != nil {
			doors.Close()
			return nil, fmt.Errorf("smart-http listen %s: %w", cfg.httpAddr, err)
		}
		doors.httpListener = listener
		// One mux: the Smart-HTTP surface, plus the LFS batch endpoint when this
		// plane has an object tier. The LFS pattern is more specific than the Git
		// prefix, so Go's mux routes it first.
		mux := http.NewServeMux()
		mux.Handle("/", gitfrontdoor.SmartHTTP{Router: router, Storage: storage, RequestID: ids.NewULID})
		if cfg.objects != nil {
			tier, err := gitfrontdoor.NewObjectTier(pdp, cfg.objects)
			if err != nil {
				doors.Close()
				return nil, fmt.Errorf("lfs object tier: %w", err)
			}
			mux.Handle("POST /git/{tenant}/{repository}/info/lfs/objects/batch",
				gitfrontdoor.LFS{Router: router, Objects: tier, RequestID: ids.NewULID})
		}
		doors.httpServer = &http.Server{Handler: mux}
		go func() {
			if err := doors.httpServer.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				fmt.Fprintf(os.Stderr, "dataplane smart-http: %v\n", err)
			}
		}()
	}

	if cfg.sshAddr != "" {
		signer, err := loadHostSigner(cfg.sshHostKey)
		if err != nil {
			doors.Close()
			return nil, fmt.Errorf("ssh host key: %w", err)
		}
		listener, err := net.Listen("tcp", cfg.sshAddr)
		if err != nil {
			doors.Close()
			return nil, fmt.Errorf("ssh listen %s: %w", cfg.sshAddr, err)
		}
		doors.sshListener = listener
		server := gitfrontdoor.SSH{Router: router, Storage: storage, HostSigner: signer, VerifierKeyID: cfg.verifierKeyID}
		go func() { _ = server.Serve(ctx, listener) }()
	}

	if cfg.policyAddr != "" {
		listener, err := net.Listen("tcp", cfg.policyAddr)
		if err != nil {
			doors.Close()
			return nil, fmt.Errorf("policy grpc listen %s: %w", cfg.policyAddr, err)
		}
		doors.policyListener = listener
		doors.policyServer = grpc.NewServer()
		policyv1.RegisterPolicyDecisionPointServer(doors.policyServer, policy.NewGRPCServer(pdp, records))
	}

	go func() {
		<-ctx.Done()
		doors.Close()
	}()
	return doors, nil
}

// ServePolicy starts the policy gRPC door. It is called by the plane's owner
// after every service that shares the door has been registered, so a late
// RegisterService can never race Serve — gRPC makes that a fatal error.
func (d *gitFrontDoors) ServePolicy() {
	if d.policyServer == nil {
		return
	}
	go func() {
		if err := d.policyServer.Serve(d.policyListener); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			fmt.Fprintf(os.Stderr, "dataplane policy grpc: %v\n", err)
		}
	}()
}

// loadHostSigner loads a PEM private key from path, or generates an ephemeral
// ed25519 host key when path is empty. An ephemeral key changes the host
// identity on every restart; production deployments must mount one.
func loadHostSigner(path string) (ssh.Signer, error) {
	if path != "" {
		pemBytes, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		return ssh.ParsePrivateKey(pemBytes)
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	fmt.Fprintln(os.Stderr, "dataplane ssh: no GITFROK_GIT_SSH_HOST_KEY_PATH set; using an ephemeral host key")
	return ssh.NewSignerFromKey(private)
}
