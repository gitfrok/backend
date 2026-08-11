package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"net/http/httptest"

	"github.com/gitfrok/backend/internal/gitfrontdoor"
	identityapi "github.com/gitfrok/backend/modules/identity/api"
	"github.com/gitfrok/backend/platform/bus"
	"github.com/gitfrok/backend/platform/ids"
)

type transportAuthenticator struct{}

func (transportAuthenticator) AuthenticatePAT(context.Context, string) (identityapi.Principal, bool) {
	return identityapi.Principal{TenantID: "tenant-a", ActorID: "actor-a", Roles: []string{"member"}}, true
}
func (transportAuthenticator) AuthenticateSSHKey(context.Context, string, string) (identityapi.Principal, bool) {
	return identityapi.Principal{}, false
}
func (transportAuthenticator) IssuePAT(context.Context, string, string, string, []string, []string, *time.Time) (identityapi.PAT, string, error) {
	panic("not used")
}
func (transportAuthenticator) RevokePAT(context.Context, string, string, string) (identityapi.PAT, error) {
	panic("not used")
}
func (transportAuthenticator) ListPATs(context.Context, string, string) ([]identityapi.PAT, error) {
	panic("not used")
}

// T-0011 AC1/AC2: a real Git client reaches the storage process only through
// the Smart-HTTP PAT boundary. The client sees protocol bytes; GitStorage sees
// only a verified opaque operation context and still performs its PDP decision.
func TestSmartHTTPGitCloneStreamsThroughGitStorage(t *testing.T) {
	root, tenantID, repositoryID, _ := seededRepository(t)
	client, closeClient := newClient(t, root, allowPDP{}, bus.NewInProcess())
	defer closeClient()

	handler := gitfrontdoor.SmartHTTP{
		Router:    gitfrontdoor.Router{Authenticator: transportAuthenticator{}},
		Storage:   gitfrontdoor.GRPCStorage{Client: client},
		RequestID: ids.NewULID,
	}
	server := httptest.NewServer(handler)
	defer server.Close()

	destination := filepath.Join(t.TempDir(), "clone")
	url := strings.Replace(server.URL, "http://", "http://git:pat@", 1) + "/git/" + tenantID + "/" + repositoryID + ".git"
	command := exec.Command("git", "clone", url, destination)
	command.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git clone: %v\n%s", err, output)
	}
	if _, err := os.Stat(filepath.Join(destination, "README.md")); err != nil {
		t.Fatalf("cloned README: %v", err)
	}
}

// T-0011 AC1: the write path over Smart-HTTP. A real Git client pushes new
// objects through the same PAT boundary the clone used; GitStorage still
// makes its own PDP decision before git-receive-pack runs.
func TestSmartHTTPGitPushStreamsThroughGitStorage(t *testing.T) {
	root, tenantID, repositoryID, head := seededRepository(t)
	client, closeClient := newClient(t, root, allowPDP{}, bus.NewInProcess())
	defer closeClient()

	handler := gitfrontdoor.SmartHTTP{
		Router:    gitfrontdoor.Router{Authenticator: transportAuthenticator{}},
		Storage:   gitfrontdoor.GRPCStorage{Client: client},
		RequestID: ids.NewULID,
	}
	server := httptest.NewServer(handler)
	defer server.Close()

	destination := filepath.Join(t.TempDir(), "clone")
	url := strings.Replace(server.URL, "http://", "http://git:pat@", 1) + "/git/" + tenantID + "/" + repositoryID + ".git"
	gitEnv := append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	clone := exec.Command("git", "clone", url, destination)
	clone.Env = gitEnv
	if output, err := clone.CombinedOutput(); err != nil {
		t.Fatalf("git clone: %v\n%s", err, output)
	}
	mustRunGit(t, destination, "config", "user.email", "dev@gitsaas.test")
	mustRunGit(t, destination, "config", "user.name", "GitFrok test")
	if err := os.WriteFile(filepath.Join(destination, "pushed.txt"), []byte("pushed through smart-http\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	mustRunGit(t, destination, "add", "pushed.txt")
	mustRunGit(t, destination, "commit", "-m", "push through smart-http")
	push := exec.Command("git", "push", "origin", "HEAD:refs/heads/main")
	push.Dir = destination
	push.Env = gitEnv
	if output, err := push.CombinedOutput(); err != nil {
		t.Fatalf("git push: %v\n%s", err, output)
	}

	pushed := mustGitOutput(t, filepath.Join(root, tenantID, repositoryID+".git"), "rev-parse", "refs/heads/main")
	if pushed == head {
		t.Fatalf("refs/heads/main still at %s after push", head)
	}
}

// T-0011 AC3: a PDP denial at the storage tier surfaces through the
// Smart-HTTP front door as a failed transfer. The front door does not decide
// repository authorization (ADR-0041 decision 4), so the same boundary that
// admitted the credential still refuses the operation once storage denies it.
func TestSmartHTTPPDPDenialFailsTheGitClient(t *testing.T) {
	root, tenantID, repositoryID, _ := seededRepository(t)
	client, closeClient := newClient(t, root, denyPDP{}, bus.NewInProcess())
	defer closeClient()

	handler := gitfrontdoor.SmartHTTP{
		Router:    gitfrontdoor.Router{Authenticator: transportAuthenticator{}},
		Storage:   gitfrontdoor.GRPCStorage{Client: client},
		RequestID: ids.NewULID,
	}
	server := httptest.NewServer(handler)
	defer server.Close()

	destination := filepath.Join(t.TempDir(), "clone")
	url := strings.Replace(server.URL, "http://", "http://git:pat@", 1) + "/git/" + tenantID + "/" + repositoryID + ".git"
	command := exec.Command("git", "clone", url, destination)
	command.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	if output, err := command.CombinedOutput(); err == nil {
		t.Fatalf("git clone succeeded despite PDP denial: %s", output)
	}
	if _, err := os.Stat(filepath.Join(destination, "README.md")); !os.IsNotExist(err) {
		t.Fatalf("denied clone left content behind: %v", err)
	}
}
