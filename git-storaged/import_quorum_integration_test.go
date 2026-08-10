package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	gitv1 "github.com/gitfrok/backend/gen/proto/git/v1"
	"github.com/gitfrok/backend/modules/repository"
	repoapi "github.com/gitfrok/backend/modules/repository/api"
	"github.com/gitfrok/backend/platform/bus"
)

// SPEC-0011 AC1 and AC3 through the real surface: a real remote over HTTPS, the
// `ImportRefs` RPC rather than its internals, and a durability quorum that a
// *second* node has to satisfy.
//
// The earlier AC1 test drove the fetch step directly, because `validSourceURL`
// refuses a local path and a local fixture could not travel through the RPC. This
// one closes that gap by serving the source the way a real source is served —
// `git http-backend` behind TLS — so the whole path runs: URL validation, the PDP
// decision, the fetch, the ref scan, the quorum gate, and the ref announcement.
//
// The repository root can be pointed at a real mount with
// GITFROK_TEST_BLOCK_VOLUME, and it must be a **block-backed** one: the server
// refuses a FUSE root at construction (ErrFUSERepositoryRoot, ADR-0033,
// invariant 7). That is worth knowing before reaching for a rootless mount —
// `fuse2fs` over an ext4 image gives a real ext4 filesystem and the server
// rejects it anyway, correctly, because a FUSE-backed repository is exactly what
// the invariant disqualifies. Proving this path on a genuine attached volume
// therefore needs a machine that can attach one, which is the cluster lane's
// (T-0003). Without the variable the test runs on an ordinary temp directory.
//
// The other thing that remains the cluster lane's, stated rather than implied:
// the "second node" here is a goroutine acknowledging through the in-process
// coordinator, not another machine running SPEC-0018's production coordinator.
// What this does prove is that the acknowledgement is withheld until something
// other than the writing node calls the write durable, and that object identity
// survives the whole round trip.

// repositoryRootFor returns the directory this test's repositories live in: a real
// block-backed ext4 mount when one is configured, and a temp directory otherwise.
func repositoryRootFor(t *testing.T, name string) string {
	t.Helper()
	volume := os.Getenv("GITFROK_TEST_BLOCK_VOLUME")
	if volume == "" {
		return t.TempDir()
	}
	root := filepath.Join(volume, name+"-"+time.Now().UTC().Format("20060102150405.000000000"))
	if err := os.MkdirAll(root, 0o750); err != nil {
		t.Fatalf("create repository root on the block volume: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	return root
}

// gitHTTPSource serves a bare repository over HTTPS via git-http-backend, which
// is what an https clone URL points at in the real world.
func gitHTTPSource(t *testing.T, repositoryRoot string) *httptest.Server {
	t.Helper()
	// cgi.Handler execs the path verbatim, so it needs git's absolute location.
	gitBinary, err := exec.LookPath("git")
	if err != nil {
		t.Skipf("git is not on PATH: %v", err)
	}
	handler := &cgi.Handler{
		Path: gitBinary,
		Args: []string{"http-backend"},
		Dir:  repositoryRoot,
		Env: []string{
			"GIT_PROJECT_ROOT=" + repositoryRoot,
			"GIT_HTTP_EXPORT_ALL=1",
		},
	}
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)

	// git runs as a child process and does not inherit Go's TLS trust, so the
	// server's certificate is written out and named through GIT_SSL_CAINFO. The
	// import's own fetch inherits this process's environment.
	certificate := server.Certificate()
	path := filepath.Join(t.TempDir(), "source-ca.pem")
	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatalf("write CA: %v", err)
	}
	t.Setenv("GIT_SSL_CAINFO", path)

	// Sanity: the trust plumbing is part of the fixture, not part of the claim, so
	// fail loudly here rather than as a confusing import failure below.
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(encoded) {
		t.Fatal("the test server's certificate is not usable as a CA")
	}
	return server
}

// ackingReplica is the second node. It watches for the operation this import
// leases and acknowledges it, which is the only way the quorum is ever satisfied:
// the writing node's own acknowledgement is not enough.
type ackingReplica struct {
	coordinator repoapi.Coordinator
	nodeID      string

	mu     sync.Mutex
	acked  []string
	stop   chan struct{}
	closed bool
}

func newAckingReplica(coordinator repoapi.Coordinator, nodeID string) *ackingReplica {
	return &ackingReplica{coordinator: coordinator, nodeID: nodeID, stop: make(chan struct{})}
}

// ackWhenLeased polls for the operation and acknowledges it under the given term.
// A real sync replica learns of the write by replicating it; this stands in for
// that, and deliberately does nothing else — it cannot make the primary's own ack
// sufficient, which is the property under test.
func (r *ackingReplica) ackWhenLeased(ctx context.Context, tenantID, repositoryID, operationID string, term uint64) {
	go func() {
		ticker := time.NewTicker(5 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-r.stop:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				if _, err := r.coordinator.AckDurable(ctx, tenantID, repositoryID, operationID, r.nodeID, term); err == nil {
					r.mu.Lock()
					r.acked = append(r.acked, operationID)
					r.mu.Unlock()
					return
				}
			}
		}
	}()
}

func (r *ackingReplica) close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.closed {
		close(r.stop)
		r.closed = true
	}
}

func (r *ackingReplica) ackCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.acked)
}

// The whole import path: an HTTPS source, the ImportRefs RPC, a two-node quorum,
// and a clone of the result carrying the source's own SHAs.
func TestImportRefsOverHTTPSWithASyncReplica(t *testing.T) {
	const (
		primaryNode = "node-primary"
		syncNode    = "node-sync"
		tenantID    = "tenant-a"
		repoID      = "repo-a"
		requestID   = "request-import-quorum"
	)

	// The source, served over HTTPS the way a real remote is.
	sourceRoot := t.TempDir()
	sourceBare := filepath.Join(sourceRoot, "widgets.git")
	mustRunGit(t, sourceRoot, "init", "--bare", sourceBare)

	work := t.TempDir()
	mustRunGit(t, work, "init", "--initial-branch=main", work)
	mustRunGit(t, work, "config", "user.email", "dev@gitsaas.test")
	mustRunGit(t, work, "config", "user.name", "GitFrok test")
	mustRunGit(t, work, "config", "tag.gpgSign", "false")
	writeFile(t, work, "README.md", "imported over https\n")
	mustRunGit(t, work, "add", "README.md")
	mustRunGit(t, work, "commit", "-m", "initial")
	mustRunGit(t, work, "tag", "-a", "v1.0.0", "-m", "release one")
	writeFile(t, work, "second.txt", "more history\n")
	mustRunGit(t, work, "add", "second.txt")
	mustRunGit(t, work, "commit", "-m", "second")
	mustRunGit(t, work, "push", sourceBare, "refs/heads/main:refs/heads/main", "--tags")
	sourceHead := mustGitOutput(t, work, "rev-parse", "HEAD")

	source := gitHTTPSource(t, sourceRoot)

	// The destination, on a block volume when one is configured (invariant 7), and
	// a shard whose in-sync replica is a different node.
	root := repositoryRootFor(t, "import-quorum")
	destination := filepath.Join(root, tenantID, repoID+".git")
	mustRunGit(t, root, "init", "--bare", destination)

	events := bus.NewInProcess()
	var (
		mu        sync.Mutex
		published []repoapi.RefUpdated
	)
	bus.SubscribeTyped(events, func(_ context.Context, e repoapi.RefUpdated) error {
		mu.Lock()
		published = append(published, e)
		mu.Unlock()
		return nil
	})

	coordinator := repository.NewInMemoryCoordinator(primaryNode, events)
	if err := coordinator.(testCoordinator).SeedShard(repoapi.ShardSeed{
		TenantID: tenantID, RepositoryID: repoID,
		PrimaryNode: primaryNode, SyncReplica: syncNode,
	}); err != nil {
		t.Fatalf("SeedShard: %v", err)
	}

	replica := newAckingReplica(coordinator, syncNode)
	defer replica.close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	replica.ackWhenLeased(ctx, tenantID, repoID, requestID, 1)

	client, closeClient := newClientWithConfig(t, Config{
		RepositoryRoot: root, PDP: allowPDP{}, Events: events,
		Coordinator:   coordinator,
		NodeID:        primaryNode,
		QuorumTimeout: 30 * time.Second,
		command:       testGitCommand,
	})
	defer closeClient()

	response, err := client.ImportRefs(ctx, &gitv1.ImportRefsRequest{
		Context: &gitv1.OperationContext{
			TenantId: tenantID, RepositoryId: repoID,
			ActorId: "operator-1", RequestId: requestID, ActorRoles: []string{"owner"},
		},
		SourceUrl: source.URL + "/widgets.git",
	})
	if err != nil {
		t.Fatalf("ImportRefs over https: %v", err)
	}

	imported := map[string]string{}
	for _, ref := range response.GetRefs() {
		imported[ref.GetRef()] = ref.GetRevision()
	}
	if imported["refs/heads/main"] != sourceHead {
		t.Fatalf("imported main = %q, want the source's %q", imported["refs/heads/main"], sourceHead)
	}
	if imported["refs/tags/v1.0.0"] == "" {
		t.Error("the annotated tag was not imported")
	}
	if response.GetImportedBytes() <= 0 {
		t.Errorf("imported bytes = %d, want the growth this fetch caused", response.GetImportedBytes())
	}

	// The acknowledgement came only after the second node acked (AC3).
	if replica.ackCount() != 1 {
		t.Fatalf("the sync replica acknowledged %d operations, want 1 — the quorum was not what "+
			"released this import", replica.ackCount())
	}

	// And the refs were announced, which happens only past the quorum gate.
	mu.Lock()
	announced := len(published)
	mu.Unlock()
	if announced == 0 {
		t.Fatal("no RefUpdated was published for an acknowledged import")
	}

	// AC1: a clone of the imported repository yields the source's own SHAs.
	clone := filepath.Join(t.TempDir(), "clone.git")
	mustRunGit(t, filepath.Dir(clone), "clone", "--mirror", destination, clone)
	if got := mustGitOutput(t, clone, "rev-parse", "refs/heads/main"); got != sourceHead {
		t.Fatalf("clone main = %q, want the source's %q", got, sourceHead)
	}
	if got, want := refList(t, clone), refList(t, sourceBare); !equalRefs(got, want) {
		t.Fatalf("clone refs = %v, want the source's %v", got, want)
	}
}

// The same import with a sync replica that never acknowledges: nothing is
// announced, and the caller is told the import failed rather than being handed a
// repository whose write no second node ever confirmed (AC3).
func TestImportRefsWithoutAReplicaAckAnnouncesNothing(t *testing.T) {
	const (
		primaryNode = "node-primary"
		tenantID    = "tenant-a"
		repoID      = "repo-a"
	)

	sourceRoot := t.TempDir()
	sourceBare := filepath.Join(sourceRoot, "widgets.git")
	mustRunGit(t, sourceRoot, "init", "--bare", sourceBare)
	work := t.TempDir()
	mustRunGit(t, work, "init", "--initial-branch=main", work)
	mustRunGit(t, work, "config", "user.email", "dev@gitsaas.test")
	mustRunGit(t, work, "config", "user.name", "GitFrok test")
	writeFile(t, work, "README.md", "never acknowledged\n")
	mustRunGit(t, work, "add", "README.md")
	mustRunGit(t, work, "commit", "-m", "initial")
	mustRunGit(t, work, "push", sourceBare, "refs/heads/main:refs/heads/main")

	source := gitHTTPSource(t, sourceRoot)

	root := repositoryRootFor(t, "import-no-ack")
	mustRunGit(t, root, "init", "--bare", filepath.Join(root, tenantID, repoID+".git"))

	events := bus.NewInProcess()
	var (
		mu        sync.Mutex
		published []repoapi.RefUpdated
	)
	bus.SubscribeTyped(events, func(_ context.Context, e repoapi.RefUpdated) error {
		mu.Lock()
		published = append(published, e)
		mu.Unlock()
		return nil
	})

	coordinator := repository.NewInMemoryCoordinator(primaryNode, events)
	if err := coordinator.(testCoordinator).SeedShard(repoapi.ShardSeed{
		TenantID: tenantID, RepositoryID: repoID,
		PrimaryNode: primaryNode, SyncReplica: "node-sync-down",
	}); err != nil {
		t.Fatalf("SeedShard: %v", err)
	}

	client, closeClient := newClientWithConfig(t, Config{
		RepositoryRoot: root, PDP: allowPDP{}, Events: events,
		Coordinator:   coordinator,
		NodeID:        primaryNode,
		QuorumTimeout: 200 * time.Millisecond,
		command:       testGitCommand,
	})
	defer closeClient()

	if _, err := client.ImportRefs(context.Background(), &gitv1.ImportRefsRequest{
		Context: &gitv1.OperationContext{
			TenantId: tenantID, RepositoryId: repoID,
			ActorId: "operator-1", RequestId: "request-no-ack", ActorRoles: []string{"owner"},
		},
		SourceUrl: source.URL + "/widgets.git",
	}); err == nil {
		t.Fatal("an import was acknowledged with no in-sync replica acknowledgement")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(published) != 0 {
		t.Fatalf("published %d RefUpdated events, want none — the quorum was withheld", len(published))
	}
}
