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
func (transportAuthenticator) IssuePAT(context.Context, string, string, string, []string, *time.Time) (identityapi.PAT, string, error) {
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
