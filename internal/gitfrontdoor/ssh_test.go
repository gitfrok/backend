package gitfrontdoor

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"testing"

	gitv1 "github.com/gitfrok/backend/gen/proto/git/v1"
	identityapi "github.com/gitfrok/backend/modules/identity/api"
	"golang.org/x/crypto/ssh"
)

func TestParseSSHCommandAcceptsOnlyGitServiceAndOpaqueHandle(t *testing.T) {
	for _, test := range []struct {
		command string
		service string
		handle  string
	}{
		{command: "git-upload-pack 'tenant-a/repo-a.git'", service: "git-upload-pack", handle: "tenant-a/repo-a.git"},
		{command: "git-receive-pack 'tenant-a/repo-a.git'", service: "git-receive-pack", handle: "tenant-a/repo-a.git"},
		{command: "git-upload-pack '/tenant-a/repo-a.git'", service: "git-upload-pack", handle: "tenant-a/repo-a.git"},
	} {
		service, handle, err := ParseSSHCommand(test.command)
		if err != nil || service != test.service || handle != test.handle {
			t.Fatalf("ParseSSHCommand(%q) = %q, %q, %v", test.command, service, handle, err)
		}
	}
}

func TestParseSSHCommandRejectsShellPathsAndExtraArguments(t *testing.T) {
	for _, command := range []string{"", "sh", "git-upload-pack tenant-a/repo-a.git", "git-upload-pack 'tenant-a/../repo-a.git'", "git-upload-pack 'tenant-a/repo-a.git' --upload-pack=sh", "git-upload-pack 'tenant-a/repo-a.git'; id"} {
		if _, _, err := ParseSSHCommand(command); err == nil {
			t.Errorf("ParseSSHCommand(%q) succeeded", command)
		}
	}
}

func TestSSHServesOnlyVerifiedForcedGitCommand(t *testing.T) {
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
	clientSigner, err := ssh.NewSignerFromKey(clientPrivate)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx := t.Context()
	storage := &recordingStorage{}
	server := SSH{Router: Router{Authenticator: &fakeAuthenticator{sshPrincipal: identityapi.Principal{TenantID: "tenant-a", ActorID: "actor-a"}, sshOK: true}}, Storage: storage, HostSigner: hostSigner, VerifierKeyID: "default"}
	go func() { _ = server.Serve(ctx, listener) }()
	client, err := ssh.Dial("tcp", listener.Addr().String(), &ssh.ClientConfig{User: "git", Auth: []ssh.AuthMethod{ssh.PublicKeys(clientSigner)}, HostKeyCallback: ssh.InsecureIgnoreHostKey()})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	var output bytes.Buffer
	session.Stdout = &output
	if err := session.Run("git-upload-pack 'tenant-a/repo-a.git'"); err != nil {
		t.Fatal(err)
	}
	if storage.called != "upload" || output.String() != "advertisement" {
		t.Fatalf("storage=%q output=%q", storage.called, output.String())
	}
	if storage.context.GetTransport() != gitv1.GitTransport_GIT_TRANSPORT_SSH {
		t.Fatalf("transport = %s", storage.context.GetTransport())
	}
}
