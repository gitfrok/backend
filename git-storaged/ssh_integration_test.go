package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	gitv1 "github.com/gitfrok/backend/gen/proto/git/v1"
	"github.com/gitfrok/backend/internal/gitfrontdoor"
	identityapi "github.com/gitfrok/backend/modules/identity/api"
	"github.com/gitfrok/backend/platform/bus"
	"golang.org/x/crypto/ssh"
)

// T-0011 AC1/AC2: a real Git client clones and pushes through the restricted
// SSH command boundary. GitStorage receives only the principal resolved from
// the verified key, then continues to make the PDP decision itself.
func TestSSHGitCloneAndPushStreamThroughGitStorage(t *testing.T) {
	root, tenantID, repositoryID, _ := seededRepository(t)
	client, closeClient := newClient(t, root, allowPDP{}, bus.NewInProcess())
	defer closeClient()

	_, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPrivate)
	if err != nil {
		t.Fatal(err)
	}
	clientPublic, clientPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := writeOpenSSHPrivateKey(t, clientPrivate)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	serveCtx := t.Context()
	server := gitfrontdoor.SSH{
		Router:  gitfrontdoor.Router{Authenticator: sshTransportAuthenticator{key: canonicalAuthorizedKey(t, clientPublic)}},
		Storage: gitfrontdoor.GRPCStorage{Client: client}, HostSigner: hostSigner, VerifierKeyID: "test-key",
	}
	go func() { _ = server.Serve(serveCtx, listener) }()

	destination := filepath.Join(t.TempDir(), "clone")
	remote := "ssh://git@" + listener.Addr().String() + "/" + tenantID + "/" + repositoryID + ".git"
	gitEnv := append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_SSH_COMMAND=ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i "+keyPath)
	command := exec.Command("git", "clone", remote, destination)
	command.Env = gitEnv
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git clone: %v\n%s", err, output)
	}
	if _, err := os.Stat(filepath.Join(destination, "README.md")); err != nil {
		t.Fatalf("cloned README: %v", err)
	}
	mustRunGit(t, destination, "config", "user.email", "dev@gitsaas.test")
	mustRunGit(t, destination, "config", "user.name", "GitFrok test")
	if err := os.WriteFile(filepath.Join(destination, "pushed.txt"), []byte("pushed through ssh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	mustRunGit(t, destination, "add", "pushed.txt")
	mustRunGit(t, destination, "commit", "-m", "push through ssh")
	command = exec.Command("git", "push", "origin", "HEAD:refs/heads/main")
	command.Dir = destination
	command.Env = gitEnv
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git push: %v\n%s", err, output)
	}
}

// T-0011 AC2/AC3: a key not known to Identity must be rejected at SSH
// authentication. The Git storage port must not observe the request.
func TestSSHUnknownKeyIsDeniedBeforeStorage(t *testing.T) {
	_, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPrivate)
	if err != nil {
		t.Fatal(err)
	}
	_, clientPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	storage := &deniedStorage{}
	serveCtx := t.Context()
	server := gitfrontdoor.SSH{
		Router:        gitfrontdoor.Router{Authenticator: sshTransportAuthenticator{key: "known-key"}},
		Storage:       storage,
		HostSigner:    hostSigner,
		VerifierKeyID: "test-key",
	}
	go func() { _ = server.Serve(serveCtx, listener) }()

	remote := "ssh://git@" + listener.Addr().String() + "/tenant-a/private-repo.git"
	keyPath := writeOpenSSHPrivateKey(t, clientPrivate)
	command := exec.Command("git", "ls-remote", remote)
	command.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_SSH_COMMAND=ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i "+keyPath)
	if output, err := command.CombinedOutput(); err == nil {
		t.Fatalf("git ls-remote succeeded for an unknown key: %s", output)
	}
	if calls := storage.calls.Load(); calls != 0 {
		t.Fatalf("storage calls = %d, want 0", calls)
	}
}

type deniedStorage struct {
	calls atomic.Int64
}

func (s *deniedStorage) UploadPack(context.Context, *gitv1.OperationContext, io.Reader, io.Writer) error {
	s.calls.Add(1)
	return errors.New("storage must not be called")
}

func (s *deniedStorage) ReceivePack(context.Context, *gitv1.OperationContext, io.Reader, io.Writer) error {
	s.calls.Add(1)
	return errors.New("storage must not be called")
}

type sshTransportAuthenticator struct {
	key string
}

func (a sshTransportAuthenticator) AuthenticatePAT(context.Context, string) (identityapi.Principal, bool) {
	return identityapi.Principal{}, false
}

func (a sshTransportAuthenticator) AuthenticateSSHKey(_ context.Context, key, _ string) (identityapi.Principal, bool) {
	if key != a.key {
		return identityapi.Principal{}, false
	}
	return identityapi.Principal{TenantID: "tenant-a", ActorID: "actor-a", Roles: []string{"member"}}, true
}

func (a sshTransportAuthenticator) IssuePAT(context.Context, string, string, string, []string, *time.Time) (identityapi.PAT, string, error) {
	panic("not used")
}

func (a sshTransportAuthenticator) RevokePAT(context.Context, string, string, string) (identityapi.PAT, error) {
	panic("not used")
}

func (a sshTransportAuthenticator) ListPATs(context.Context, string, string) ([]identityapi.PAT, error) {
	panic("not used")
}

func writeOpenSSHPrivateKey(t *testing.T, key ed25519.PrivateKey) string {
	t.Helper()
	encoded, err := ssh.MarshalPrivateKey(key, "")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(path, pem.EncodeToMemory(encoded), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func canonicalAuthorizedKey(t *testing.T, key ed25519.PublicKey) string {
	t.Helper()
	public, err := ssh.NewPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(public)))
}
