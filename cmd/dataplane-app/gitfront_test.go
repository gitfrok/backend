package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	gitv1 "github.com/gitfrok/backend/gen/proto/git/v1"
	policyv1 "github.com/gitfrok/backend/gen/proto/policy/v1"
	"github.com/gitfrok/backend/modules/identity"
	identityapi "github.com/gitfrok/backend/modules/identity/api"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
	"github.com/gitfrok/backend/platform/tenancy"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type allowDecisionPoint struct{}

func (allowDecisionPoint) Decide(context.Context, policyapi.Request) (policyapi.Decision, error) {
	return policyapi.Decision{Allowed: true}, nil
}

// fakeGitStorage records the operation context the front door sends and
// answers with one protocol chunk, standing in for git-storaged.
type fakeGitStorage struct {
	gitv1.UnimplementedGitStorageServer
	mu       sync.Mutex
	uploads  []*gitv1.OperationContext
	receives []*gitv1.OperationContext
}

func (f *fakeGitStorage) UploadPack(stream grpc.BidiStreamingServer[gitv1.UploadPackRequest, gitv1.UploadPackResponse]) error {
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	f.mu.Lock()
	f.uploads = append(f.uploads, first.GetContext())
	f.mu.Unlock()
	if err := stream.Send(&gitv1.UploadPackResponse{Data: []byte("0000")}); err != nil {
		return err
	}
	for {
		message, err := stream.Recv()
		if errors.Is(err, io.EOF) || message.GetClose() {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func (f *fakeGitStorage) ReceivePack(stream grpc.BidiStreamingServer[gitv1.ReceivePackRequest, gitv1.ReceivePackResponse]) error {
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	f.mu.Lock()
	f.receives = append(f.receives, first.GetContext())
	f.mu.Unlock()
	if err := stream.Send(&gitv1.ReceivePackResponse{Data: []byte("0000")}); err != nil {
		return err
	}
	for {
		message, err := stream.Recv()
		if errors.Is(err, io.EOF) || message.GetClose() {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func (f *fakeGitStorage) uploadCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.uploads)
}

func (f *fakeGitStorage) receiveCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.receives)
}

func startFakeGitStorage(t *testing.T) (string, *fakeGitStorage, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	storage := &fakeGitStorage{}
	server := grpc.NewServer()
	gitv1.RegisterGitStorageServer(server, storage)
	go func() { _ = server.Serve(listener) }()
	return listener.Addr().String(), storage, func() {
		server.Stop()
		_ = listener.Close()
	}
}

func TestLoadFrontDoorConfig(t *testing.T) {
	key := strings.Repeat("A", 44) // 33 bytes in base64
	cases := []struct {
		name    string
		env     map[string]string
		wantErr bool
		enabled bool
	}{
		{name: "nothing configured", env: map[string]string{}, enabled: false},
		{name: "storage without listener", env: map[string]string{gitStorageAddrEnv: "storaged:9090"}, wantErr: true},
		{name: "http without storage", env: map[string]string{gitHTTPAddrEnv: ":9080"}, wantErr: true},
		{name: "http without verifier key", env: map[string]string{gitStorageAddrEnv: "storaged:9090", gitHTTPAddrEnv: ":9080"}, wantErr: true},
		{name: "ssh without verifier key id", env: map[string]string{gitStorageAddrEnv: "storaged:9090", gitSSHAddrEnv: ":9022", patVerifierKeyEnv: key}, wantErr: true},
		{name: "full transport", env: map[string]string{gitStorageAddrEnv: "storaged:9090", gitHTTPAddrEnv: ":9080", gitSSHAddrEnv: ":9022", patVerifierKeyEnv: key, sshVerifierKeyIDEnv: "active-1"}, enabled: true},
		{name: "policy door alone", env: map[string]string{policyGRPCAddrEnv: ":9091"}, enabled: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := loadFrontDoorConfig(func(name string) string { return tc.env[name] })
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected configuration error")
				}
				return
			}
			if err != nil {
				t.Fatalf("loadFrontDoorConfig(): %v", err)
			}
			if cfg.enabled() != tc.enabled {
				t.Fatalf("enabled() = %t, want %t", cfg.enabled(), tc.enabled)
			}
		})
	}
}

func issueTestPAT(t *testing.T, auth identityapi.Authenticator) string {
	t.Helper()
	ctx := tenancy.WithTenant(context.Background(), tenancy.ID("tenant-a"))
	ctx = identityapi.WithPrincipal(ctx, identityapi.Principal{TenantID: "tenant-a", ActorID: "actor-a", Roles: []string{"owner"}})
	_, token, err := auth.IssuePAT(ctx, "tenant-a", "actor-a", "wiring", []string{"repo.read", "repo.write"}, nil)
	if err != nil {
		t.Fatalf("IssuePAT(): %v", err)
	}
	return token
}

// ADR-0041 decision 1: the Smart-HTTP front door runs inside the data-plane
// binary. An authenticated PAT reaches GitStorage as a verified operation
// context; an anonymous request never reaches storage at all.
func TestDataPlaneServesSmartHTTPFrontDoor(t *testing.T) {
	storageAddr, storage, stopStorage := startFakeGitStorage(t)
	defer stopStorage()

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	authenticator := identity.NewInMemory(key, allowDecisionPoint{})
	token := issueTestPAT(t, authenticator)

	cfg := frontDoorConfig{storageAddr: storageAddr, httpAddr: "127.0.0.1:0", patKey: key}
	ctx := t.Context()
	doors, err := startGitFrontDoors(ctx, cfg, authenticator, allowDecisionPoint{})
	if err != nil {
		t.Fatalf("startGitFrontDoors(): %v", err)
	}
	defer doors.Close()
	base := "http://" + doors.HTTPAddr()

	anonymous, err := http.Get(base + "/git/tenant-a/repo-a.git/info/refs?service=git-upload-pack")
	if err != nil {
		t.Fatal(err)
	}
	anonymous.Body.Close()
	if anonymous.StatusCode != http.StatusUnauthorized || storage.uploadCount() != 0 {
		t.Fatalf("anonymous status=%d uploads=%d", anonymous.StatusCode, storage.uploadCount())
	}

	discovery, err := http.NewRequest(http.MethodGet, base+"/git/tenant-a/repo-a.git/info/refs?service=git-upload-pack", nil)
	if err != nil {
		t.Fatal(err)
	}
	discovery.SetBasicAuth("git", token)
	response, err := http.DefaultClient.Do(discovery)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("authenticated discovery status = %d", response.StatusCode)
	}
	waitFor(t, func() bool { return storage.uploadCount() == 1 })
	storage.mu.Lock()
	operation := storage.uploads[0]
	storage.mu.Unlock()
	if operation.GetTenantId() != "tenant-a" || operation.GetRepositoryId() != "repo-a" || operation.GetActorId() != "actor-a" {
		t.Fatalf("operation context = %+v", operation)
	}
	if operation.GetTransport() != gitv1.GitTransport_GIT_TRANSPORT_SMART_HTTP_DISCOVERY {
		t.Fatalf("transport = %s", operation.GetTransport())
	}

	push, err := http.NewRequest(http.MethodPost, base+"/git/tenant-a/repo-a.git/git-receive-pack", strings.NewReader("pack-bytes"))
	if err != nil {
		t.Fatal(err)
	}
	push.SetBasicAuth("git", token)
	pushResponse, err := http.DefaultClient.Do(push)
	if err != nil {
		t.Fatal(err)
	}
	pushResponse.Body.Close()
	if pushResponse.StatusCode != http.StatusOK {
		t.Fatalf("receive-pack status = %d", pushResponse.StatusCode)
	}
	waitFor(t, func() bool { return storage.receiveCount() == 1 })
	storage.mu.Lock()
	receive := storage.receives[0]
	storage.mu.Unlock()
	if receive.GetTransport() != gitv1.GitTransport_GIT_TRANSPORT_SMART_HTTP_RPC {
		t.Fatalf("receive transport = %s", receive.GetTransport())
	}
}

// ADR-0041 decision 1: the SSH front door runs inside the data-plane binary.
// A key Identity does not know is refused at authentication, before storage.
func TestDataPlaneSSHDeniesUnknownKey(t *testing.T) {
	storageAddr, storage, stopStorage := startFakeGitStorage(t)
	defer stopStorage()

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	authenticator := identity.NewInMemory(key, allowDecisionPoint{})

	cfg := frontDoorConfig{storageAddr: storageAddr, sshAddr: "127.0.0.1:0", patKey: key, verifierKeyID: "active-1"}
	ctx := t.Context()
	doors, err := startGitFrontDoors(ctx, cfg, authenticator, allowDecisionPoint{})
	if err != nil {
		t.Fatalf("startGitFrontDoors(): %v", err)
	}
	defer doors.Close()

	_, clientPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(clientPrivate)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ssh.Dial("tcp", doors.SSHAddr(), &ssh.ClientConfig{
		User:            "git",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err == nil {
		t.Fatal("ssh dial succeeded with an unknown key")
	}
	if storage.uploadCount() != 0 || storage.receiveCount() != 0 {
		t.Fatalf("storage observed calls after SSH denial")
	}
}

// The PDP's gRPC door for out-of-process PEPs is served by the data plane
// when configured, answering over the contract rather than in-process calls.
func TestDataPlaneServesPolicyGRPCDoor(t *testing.T) {
	cfg := frontDoorConfig{policyAddr: "127.0.0.1:0"}
	ctx := t.Context()
	doors, err := startGitFrontDoors(ctx, cfg, nil, allowDecisionPoint{})
	if err != nil {
		t.Fatalf("startGitFrontDoors(): %v", err)
	}
	defer doors.Close()

	conn, err := grpc.NewClient(doors.PolicyAddr(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := policyv1.NewPolicyDecisionPointClient(conn)
	decideCtx, decideCancel := context.WithTimeout(ctx, 5*time.Second)
	defer decideCancel()
	response, err := client.Decide(decideCtx, &policyv1.DecideRequest{
		TenantId: "tenant-a",
		Subject:  &policyv1.Subject{Id: "actor-a", TenantId: "tenant-a", Roles: []string{"member"}},
		Action:   "repo.read",
		Resource: &policyv1.Resource{Type: "repository", Id: "repo-a"},
	})
	if err != nil {
		t.Fatalf("Decide(): %v", err)
	}
	if !response.GetAllowed() {
		t.Fatalf("Decide allowed = %v", response.GetAllowed())
	}
}

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met within 5s")
}
