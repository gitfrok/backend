package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gitv1 "github.com/gitfrok/backend/gen/proto/git/v1"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
	"github.com/gitfrok/backend/modules/repository"
	repoapi "github.com/gitfrok/backend/modules/repository/api"
	"github.com/gitfrok/backend/platform/bus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

const (
	// testNodeID is the storage node identity test pushes lease writes under. The in-process
	// coordinator auto-seeds a shard as primary==sync==testNodeID, so a push acknowledges its own quorum.
	testNodeID        = "git-storaged-test"
	testQuorumTimeout = 200 * time.Millisecond
)

func TestNewServerRejectsFUSERepositoryRoot(t *testing.T) {
	root := t.TempDir()
	_, err := newServer(Config{RepositoryRoot: root, PDP: allowPDP{}, Events: bus.NewInProcess()}, fuseMount{})
	if !errors.Is(err, ErrFUSERepositoryRoot) {
		t.Fatalf("newServer() error = %v, want ErrFUSERepositoryRoot", err)
	}
}

func TestLoadRuntimeRequiresExplicitProcessConfiguration(t *testing.T) {
	config, err := loadRuntime(func(name string) string {
		return map[string]string{
			repositoryRootEnv: "/var/lib/gitfrok/repos",
			policyBundleEnv:   "/etc/gitfrok/policies",
			listenAddressEnv:  "127.0.0.1:9443",
		}[name]
	})
	if err != nil {
		t.Fatalf("loadRuntime(): %v", err)
	}
	if config.repositoryRoot != "/var/lib/gitfrok/repos" || config.policyBundle != "/etc/gitfrok/policies" || config.listenAddress != "127.0.0.1:9443" {
		t.Fatalf("runtime config = %+v", config)
	}
	_, err = loadRuntime(func(name string) string {
		if name == repositoryRootEnv {
			return "/var/lib/gitfrok/repos"
		}
		return ""
	})
	if err == nil || !strings.Contains(err.Error(), policyBundleEnv) {
		t.Fatalf("missing policy bundle error = %v", err)
	}
}

func TestUploadPackStreamsFetchThroughRPC(t *testing.T) {
	root, tenantID, repositoryID, head := seededRepository(t)
	var gitStderr bytes.Buffer
	client, closeClient := newClientWithConfig(t, Config{
		RepositoryRoot: root,
		PDP:            allowPDP{},
		Events:         bus.NewInProcess(),
		command: func(ctx context.Context, name string, args ...string) *exec.Cmd {
			command := testGitCommand(ctx, name, args...)
			command.Stderr = &gitStderr
			return command
		},
	})
	defer closeClient()

	stream, err := client.UploadPack(t.Context())
	if err != nil {
		t.Fatalf("UploadPack(): %v", err)
	}
	if err := stream.Send(uploadContext(tenantID, repositoryID)); err != nil {
		t.Fatalf("Send context: %v", err)
	}

	advertisement, err := stream.Recv()
	if err != nil {
		t.Fatalf("Recv advertisement: %v", err)
	}
	if !bytes.Contains(advertisement.GetData(), []byte(head)) {
		t.Fatalf("advertisement does not contain HEAD %s: %q", head, advertisement.GetData())
	}

	request := append(pktLine("want "+head+" multi_ack_detailed side-band-64k ofs-delta\n"), []byte("0000")...)
	request = append(request, pktLine("done\n")...)
	if err := stream.Send(&gitv1.UploadPackRequest{Payload: &gitv1.UploadPackRequest_Data{Data: request}}); err != nil {
		t.Fatalf("Send fetch request: %v", err)
	}
	if err := stream.Send(&gitv1.UploadPackRequest{Payload: &gitv1.UploadPackRequest_Close{Close: true}}); err != nil {
		t.Fatalf("Send close: %v", err)
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatalf("CloseSend: %v", err)
	}

	var response bytes.Buffer
	for {
		part, recvErr := stream.Recv()
		if errors.Is(recvErr, io.EOF) {
			break
		}
		if recvErr != nil {
			t.Fatalf("Recv fetch response: %v\ngit stderr: %s", recvErr, gitStderr.String())
		}
		response.Write(part.GetData())
	}
	if !bytes.Contains(response.Bytes(), []byte("PACK")) {
		t.Fatalf("fetch response has no Git pack: %q", response.Bytes())
	}
}

func TestUploadPackWrongTenantIsUnavailableAndNeverStartsGit(t *testing.T) {
	root, _, repositoryID, _ := seededRepository(t)
	pdp := allowPDP{}
	called := false
	client, closeClient := newClientWithConfig(t, Config{
		RepositoryRoot: root,
		PDP:            pdp,
		Events:         bus.NewInProcess(),
		command: func(context.Context, string, ...string) *exec.Cmd {
			called = true
			return exec.Command("false")
		},
	})
	defer closeClient()

	stream, err := client.UploadPack(t.Context())
	if err != nil {
		t.Fatalf("UploadPack(): %v", err)
	}
	if err := stream.Send(uploadContext("tenant-b", repositoryID)); err != nil {
		t.Fatalf("Send context: %v", err)
	}
	_, err = stream.Recv()
	if status.Code(err) != codes.NotFound {
		t.Fatalf("Recv error code = %s, want %s; error = %v", status.Code(err), codes.NotFound, err)
	}
	if called {
		t.Fatal("Git subprocess started for a wrong-tenant repository handle")
	}
}

// SPEC-0016 AC3 / ADR-0041: front doors authenticate, but git-storaged makes
// the authorization decision. The verified role set must therefore survive
// the internal operation context and become the PDP subject, never an allow
// assertion supplied by a client.
func TestPreparePassesVerifiedActorRolesToPDP(t *testing.T) {
	root, tenantID, repositoryID, _ := seededRepository(t)
	pdp := &recordingPDP{decision: policyapi.Decision{Allowed: true}}
	events := bus.NewInProcess()
	server, err := NewServer(Config{
		RepositoryRoot: root,
		PDP:            pdp,
		Events:         events,
		Coordinator:    repository.NewInMemoryCoordinator(testNodeID, events),
		NodeID:         testNodeID,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = server.prepare(t.Context(), &gitv1.OperationContext{
		TenantId: tenantID, RepositoryId: repositoryID, ActorId: "actor-a", RequestId: "request-1", ActorRoles: []string{"test-a", "test-b"}, Transport: gitv1.GitTransport_GIT_TRANSPORT_SSH,
	}, "repo.read")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := pdp.request.Subject.Roles, []string{"test-a", "test-b"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("PDP subject roles = %v, want %v", got, want)
	}
}

func TestReceivePackPublishesRefUpdated(t *testing.T) {
	root := t.TempDir()
	tenantID, repositoryID := "tenant-a", "repo-a"
	bare := filepath.Join(root, tenantID, repositoryID+".git")
	mustRunGit(t, root, "init", "--bare", bare)

	work := t.TempDir()
	mustRunGit(t, work, "init")
	mustRunGit(t, work, "config", "user.email", "dev@gitsaas.test")
	mustRunGit(t, work, "config", "user.name", "GitFrok test")
	if err := os.WriteFile(filepath.Join(work, "README.md"), []byte("git-rpc\n"), 0o600); err != nil {
		t.Fatalf("write README: %v", err)
	}
	mustRunGit(t, work, "add", "README.md")
	mustRunGit(t, work, "commit", "-m", "initial")
	commit := mustGitOutput(t, work, "rev-parse", "HEAD")
	pack := packForCommit(t, work, commit)

	events := bus.NewInProcess()
	var (
		gotEvents []repoapi.RefUpdated
		mu        sync.Mutex
	)
	bus.SubscribeTyped(events, func(_ context.Context, event repoapi.RefUpdated) error {
		mu.Lock()
		gotEvents = append(gotEvents, event)
		mu.Unlock()
		return nil
	})
	client, closeClient := newClient(t, root, allowPDP{}, events)
	defer closeClient()

	stream, err := client.ReceivePack(t.Context())
	if err != nil {
		t.Fatalf("ReceivePack(): %v", err)
	}
	if err := stream.Send(receiveContext(tenantID, repositoryID)); err != nil {
		t.Fatalf("Send context: %v", err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("Recv receive-pack advertisement: %v", err)
	}
	update := pktLine(strings.Repeat("0", 40) + " " + commit + " refs/heads/main\x00report-status\n")
	payload := append(append(update, []byte("0000")...), pack...)
	if err := stream.Send(&gitv1.ReceivePackRequest{Payload: &gitv1.ReceivePackRequest_Data{Data: payload}}); err != nil {
		t.Fatalf("Send push: %v", err)
	}
	if err := stream.Send(&gitv1.ReceivePackRequest{Payload: &gitv1.ReceivePackRequest_Close{Close: true}}); err != nil {
		t.Fatalf("Send close: %v", err)
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatalf("CloseSend: %v", err)
	}
	for {
		_, recvErr := stream.Recv()
		if errors.Is(recvErr, io.EOF) {
			break
		}
		if recvErr != nil {
			t.Fatalf("Recv push response: %v", recvErr)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if len(gotEvents) != 1 {
		t.Fatalf("RefUpdated events = %d, want 1", len(gotEvents))
	}
	got := gotEvents[0]
	if got.TenantID != tenantID || got.RepoID != repositoryID || got.Ref != "refs/heads/main" || got.OldSha != strings.Repeat("0", 40) || got.NewSha != commit || got.ActorID != "actor-a" {
		t.Fatalf("RefUpdated = %+v", got)
	}
}

type allowPDP struct{}

func (allowPDP) Decide(context.Context, policyapi.Request) (policyapi.Decision, error) {
	return policyapi.Decision{Allowed: true}, nil
}

type recordingPDP struct {
	decision policyapi.Decision
	request  policyapi.Request
}

func (p *recordingPDP) Decide(_ context.Context, request policyapi.Request) (policyapi.Decision, error) {
	p.request = request
	return p.decision, nil
}

type fuseMount struct{}

func (fuseMount) Check(string) error { return ErrFUSERepositoryRoot }

func newClient(t *testing.T, root string, pdp policyapi.DecisionPoint, events bus.Bus) (gitv1.GitStorageClient, func()) {
	t.Helper()
	return newClientWithConfig(t, Config{RepositoryRoot: root, PDP: pdp, Events: events, command: testGitCommand})
}

func newClientWithConfig(t *testing.T, config Config) (gitv1.GitStorageClient, func()) {
	t.Helper()
	// Default the coordinator to a single-node in-process instance so pushes acknowledge their own
	// quorum; tests that need a multi-node topology inject their own (see TestReceivePack*).
	if config.Coordinator == nil {
		config.Coordinator = repository.NewInMemoryCoordinator(testNodeID, config.Events)
		config.NodeID = testNodeID
	}
	if config.QuorumTimeout == 0 {
		config.QuorumTimeout = testQuorumTimeout
	}
	server, err := NewServer(config)
	if err != nil {
		t.Fatalf("NewServer(): %v", err)
	}
	listener := bufconn.Listen(1 << 20)
	grpcServer := grpc.NewServer()
	gitv1.RegisterGitStorageServer(grpcServer, server)
	go func() { _ = grpcServer.Serve(listener) }()

	conn, err := grpc.NewClient("passthrough:///git-storaged", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
		return listener.Dial()
	}), grpc.WithInsecure())
	if err != nil {
		t.Fatalf("grpc.NewClient(): %v", err)
	}
	return gitv1.NewGitStorageClient(conn), func() {
		_ = conn.Close()
		grpcServer.Stop()
		_ = listener.Close()
	}
}

func seededRepository(t *testing.T) (root, tenantID, repositoryID, head string) {
	t.Helper()
	root = t.TempDir()
	tenantID, repositoryID = "tenant-a", "repo-a"
	bare := filepath.Join(root, tenantID, repositoryID+".git")
	mustRunGit(t, root, "init", "--bare", bare)
	work := t.TempDir()
	mustRunGit(t, work, "init")
	mustRunGit(t, work, "config", "user.email", "dev@gitsaas.test")
	mustRunGit(t, work, "config", "user.name", "GitFrok test")
	if err := os.WriteFile(filepath.Join(work, "README.md"), []byte("git-rpc\n"), 0o600); err != nil {
		t.Fatalf("write README: %v", err)
	}
	mustRunGit(t, work, "add", "README.md")
	mustRunGit(t, work, "commit", "-m", "initial")
	mustRunGit(t, work, "remote", "add", "origin", bare)
	mustRunGit(t, work, "push", "origin", "HEAD:refs/heads/main")
	mustRunGit(t, bare, "symbolic-ref", "HEAD", "refs/heads/main")
	head = mustGitOutput(t, work, "rev-parse", "HEAD")
	return root, tenantID, repositoryID, head
}

func packForCommit(t *testing.T, work, commit string) []byte {
	t.Helper()
	command := exec.Command("git", "pack-objects", "--stdout", "--revs")
	command.Dir = work
	command.Stdin = strings.NewReader(commit + "\n")
	pack, err := command.Output()
	if err != nil {
		t.Fatalf("git pack-objects: %v", err)
	}
	return pack
}

func mustRunGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	command := exec.Command("git", args...)
	command.Dir = dir
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, output)
	}
}

func mustGitOutput(t *testing.T, dir string, args ...string) string {
	t.Helper()
	command := exec.Command("git", args...)
	command.Dir = dir
	output, err := command.Output()
	if err != nil {
		t.Fatalf("git %s: %v", strings.Join(args, " "), err)
	}
	return strings.TrimSpace(string(output))
}

func uploadContext(tenantID, repositoryID string) *gitv1.UploadPackRequest {
	return &gitv1.UploadPackRequest{Payload: &gitv1.UploadPackRequest_Context{Context: operationContext(tenantID, repositoryID)}}
}

func receiveContext(tenantID, repositoryID string) *gitv1.ReceivePackRequest {
	return &gitv1.ReceivePackRequest{Payload: &gitv1.ReceivePackRequest_Context{Context: operationContext(tenantID, repositoryID)}}
}

func operationContext(tenantID, repositoryID string) *gitv1.OperationContext {
	return &gitv1.OperationContext{TenantId: tenantID, RepositoryId: repositoryID, ActorId: "actor-a", RequestId: fmt.Sprintf("request-%d", time.Now().UnixNano()), Transport: gitv1.GitTransport_GIT_TRANSPORT_SSH}
}

func TestGitCommandArgsSelectsTransportFraming(t *testing.T) {
	for _, test := range []struct {
		name      string
		binary    string
		transport gitv1.GitTransport
		want      []string
		valid     bool
	}{
		{name: "ssh upload", binary: "git-upload-pack", transport: gitv1.GitTransport_GIT_TRANSPORT_SSH, want: []string{"--strict", "/repos/tenant/repo.git"}, valid: true},
		{name: "http discovery", binary: "git-upload-pack", transport: gitv1.GitTransport_GIT_TRANSPORT_SMART_HTTP_DISCOVERY, want: []string{"--stateless-rpc", "--advertise-refs", "/repos/tenant/repo.git"}, valid: true},
		{name: "http upload rpc", binary: "git-upload-pack", transport: gitv1.GitTransport_GIT_TRANSPORT_SMART_HTTP_RPC, want: []string{"--stateless-rpc", "/repos/tenant/repo.git"}, valid: true},
		{name: "http receive rpc", binary: "git-receive-pack", transport: gitv1.GitTransport_GIT_TRANSPORT_SMART_HTTP_RPC, want: []string{"--stateless-rpc", "/repos/tenant/repo.git"}, valid: true},
		{name: "http receive discovery", binary: "git-receive-pack", transport: gitv1.GitTransport_GIT_TRANSPORT_SMART_HTTP_DISCOVERY, want: []string{"--stateless-rpc", "--advertise-refs", "/repos/tenant/repo.git"}, valid: true},
		{name: "unspecified denied", binary: "git-upload-pack", transport: gitv1.GitTransport_GIT_TRANSPORT_UNSPECIFIED},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := gitCommandArgs(test.binary, test.transport, "/repos/tenant/repo.git")
			if test.valid != (err == nil) {
				t.Fatalf("gitCommandArgs() err = %v, valid = %t", err, test.valid)
			}
			if test.valid && !reflect.DeepEqual(got, test.want) {
				t.Fatalf("gitCommandArgs() = %q, want %q", got, test.want)
			}
		})
	}
}

func pktLine(body string) []byte { return []byte(fmt.Sprintf("%04x%s", len(body)+4, body)) }

// The request fixture below is protocol v0 packet-line syntax. GitHub-hosted runners can export
// GIT_PROTOCOL=version=2, so make the server side explicit rather than coupling this contract test
// to whichever global Git configuration happens to run it.
func testGitCommand(ctx context.Context, name string, args ...string) *exec.Cmd {
	command := exec.CommandContext(ctx, name, args...)
	command.Env = append(os.Environ(), "GIT_PROTOCOL=version=0")
	return command
}

// testCoordinator is the api.Coordinator plus the in-process-only setup hooks the InMemory adapter
// exposes for tests. git-storaged (package main, outside modules/repository) reaches these through
// structural typing rather than importing internal/replica (ADR-0025 internal/ rule).
type testCoordinator interface {
	repoapi.Coordinator
	SeedShard(repoapi.ShardSeed) error
	MarkDegraded(context.Context, string, string) error
}

// T-0012 AC4 at the write path: a shard that has failed to read-only (confirmed primary+sync loss)
// must be denied before a Git subprocess starts, so no write activity races a term change.
func TestReceivePackDeniedOnReadOnlyShardNeverStartsGit(t *testing.T) {
	root, tenantID, repositoryID, _ := seededRepository(t)
	events := bus.NewInProcess()
	coord := repository.NewInMemoryCoordinator(testNodeID, events)
	if err := coord.(testCoordinator).SeedShard(repoapi.ShardSeed{
		TenantID: tenantID, RepositoryID: repositoryID,
		PrimaryNode: testNodeID, SyncReplica: testNodeID,
	}); err != nil {
		t.Fatalf("SeedShard: %v", err)
	}
	if err := coord.(testCoordinator).MarkDegraded(t.Context(), tenantID, repositoryID); err != nil {
		t.Fatalf("MarkDegraded: %v", err)
	}

	// atomic_types (SPEC-0036 CONDITIONAL, test-file-only): the counter is only read and
	// incremented, so the typed atomic carries the same semantics with no address-taking.
	var gitCalls atomic.Int32
	client, closeClient := newClientWithConfig(t, Config{
		RepositoryRoot: root, PDP: allowPDP{}, Events: events,
		Coordinator:   coord,
		NodeID:        testNodeID,
		QuorumTimeout: testQuorumTimeout,
		command: func(context.Context, string, ...string) *exec.Cmd {
			gitCalls.Add(1)
			return exec.Command("false")
		},
	})
	defer closeClient()

	stream, err := client.ReceivePack(t.Context())
	if err != nil {
		t.Fatalf("ReceivePack(): %v", err)
	}
	if err := stream.Send(receiveContext(tenantID, repositoryID)); err != nil {
		t.Fatalf("Send context: %v", err)
	}
	// No advertisement is produced: prepare() denies on the read-only shard before git starts.
	_, err = stream.Recv()
	if status.Code(err) != codes.NotFound {
		t.Fatalf("Recv error code = %s, want %s; error = %v", status.Code(err), codes.NotFound, err)
	}
	if gitCalls.Load() != 0 {
		t.Fatalf("git subprocess started %d times on a read-only shard, want 0", gitCalls.Load())
	}
}

// T-0012 AC1 at the write path: with the in-sync replica unreachable, the primary ack alone must not
// satisfy the quorum, so the push acknowledgment is withheld and no RefUpdated event reaches consumers.
func TestReceivePackQuorumWithholdsAckWhenSyncUnreachable(t *testing.T) {
	root := t.TempDir()
	tenantID, repositoryID := "tenant-a", "repo-a"
	bare := filepath.Join(root, tenantID, repositoryID+".git")
	mustRunGit(t, root, "init", "--bare", bare)
	work := t.TempDir()
	mustRunGit(t, work, "init")
	mustRunGit(t, work, "config", "user.email", "dev@gitsaas.test")
	mustRunGit(t, work, "config", "user.name", "GitFrok test")
	if err := os.WriteFile(filepath.Join(work, "README.md"), []byte("git-rpc\n"), 0o600); err != nil {
		t.Fatalf("write README: %v", err)
	}
	mustRunGit(t, work, "add", "README.md")
	mustRunGit(t, work, "commit", "-m", "initial")
	commit := mustGitOutput(t, work, "rev-parse", "HEAD")
	pack := packForCommit(t, work, commit)

	events := bus.NewInProcess()
	var (
		mu        sync.Mutex
		gotEvents []repoapi.RefUpdated
	)
	bus.SubscribeTyped(events, func(_ context.Context, e repoapi.RefUpdated) error {
		mu.Lock()
		gotEvents = append(gotEvents, e)
		mu.Unlock()
		return nil
	})
	coord := repository.NewInMemoryCoordinator(testNodeID, events)
	// primary == this node, sync == a different node that never acks.
	if err := coord.(testCoordinator).SeedShard(repoapi.ShardSeed{
		TenantID: tenantID, RepositoryID: repositoryID,
		PrimaryNode: testNodeID, SyncReplica: "node-sync-down",
	}); err != nil {
		t.Fatalf("SeedShard: %v", err)
	}
	client, closeClient := newClientWithConfig(t, Config{
		RepositoryRoot: root, PDP: allowPDP{}, Events: events,
		Coordinator:   coord,
		NodeID:        testNodeID,
		QuorumTimeout: 150 * time.Millisecond,
		command:       testGitCommand,
	})
	defer closeClient()

	stream, err := client.ReceivePack(t.Context())
	if err != nil {
		t.Fatalf("ReceivePack(): %v", err)
	}
	if err := stream.Send(receiveContext(tenantID, repositoryID)); err != nil {
		t.Fatalf("Send context: %v", err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("Recv advertisement: %v", err)
	}
	update := pktLine(strings.Repeat("0", 40) + " " + commit + " refs/heads/main\x00report-status\n")
	payload := append(append(update, []byte("0000")...), pack...)
	if err := stream.Send(&gitv1.ReceivePackRequest{Payload: &gitv1.ReceivePackRequest_Data{Data: payload}}); err != nil {
		t.Fatalf("Send push: %v", err)
	}
	if err := stream.Send(&gitv1.ReceivePackRequest{Payload: &gitv1.ReceivePackRequest_Close{Close: true}}); err != nil {
		t.Fatalf("Send close: %v", err)
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatalf("CloseSend: %v", err)
	}
	// Drain until the server ends the stream. The quorum times out and the server returns Unavailable.
	for {
		if _, err := stream.Recv(); err != nil {
			break
		}
	}

	mu.Lock()
	n := len(gotEvents)
	mu.Unlock()
	if n != 0 {
		t.Fatalf("published %d RefUpdated events, want 0 (quorum withheld)", n)
	}
}
