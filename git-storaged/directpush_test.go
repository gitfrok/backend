package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gitv1 "github.com/gitfrok/backend/gen/proto/git/v1"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
	repoapi "github.com/gitfrok/backend/modules/repository/api"
	"github.com/gitfrok/backend/platform/bus"
)

// staticProtection stands in for the BranchProtectionChanged projection.
type staticProtection map[string][]string

func (p staticProtection) ProtectedRefs(tenantID, repositoryID string) []string {
	return p[tenantID+"/"+repositoryID]
}

// protectionPDP answers the way the Rego policy does: a direct push to a
// protected ref is refused, and everything else this test needs is allowed.
type protectionPDP struct{ asked []policyapi.Request }

func (p *protectionPDP) Decide(_ context.Context, req policyapi.Request) (policyapi.Decision, error) {
	p.asked = append(p.asked, req)
	if req.Context["operation"] == "direct_push" && req.Context["protected"] == "true" {
		return policyapi.Decision{Allowed: false, DecisionID: "decision-protected"}, nil
	}
	return policyapi.Decision{Allowed: true, DecisionID: "decision-allow"}, nil
}

// pushOne runs a full receive-pack exchange and reports git's own outcome.
func pushOne(t *testing.T, client gitv1.GitStorageClient, tenantID, repositoryID, ref, commit string, pack []byte) string {
	t.Helper()
	stream, err := client.ReceivePack(context.Background())
	if err != nil {
		t.Fatalf("ReceivePack(): %v", err)
	}
	if err := stream.Send(receiveContext(tenantID, repositoryID)); err != nil {
		t.Fatalf("Send context: %v", err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("Recv advertisement: %v", err)
	}
	update := pktLine(strings.Repeat("0", 40) + " " + commit + " " + ref + "\x00report-status\n")
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
	var report strings.Builder
	for {
		response, recvErr := stream.Recv()
		if errors.Is(recvErr, io.EOF) {
			break
		}
		if recvErr != nil {
			// A refused push may end the stream with an error rather than a report.
			break
		}
		report.Write(response.GetData())
	}
	return report.String()
}

// pushFixture prepares a bare repository and a pack holding one commit.
func pushFixture(t *testing.T, protection Protection, pdp policyapi.DecisionPoint) (gitv1.GitStorageClient, string, string, []byte, *[]repoapi.RefUpdated) {
	t.Helper()
	root := t.TempDir()
	bare := filepath.Join(root, "tenant-a", "repo-a.git")
	mustRunGit(t, root, "init", "--bare", bare)

	work := t.TempDir()
	mustRunGit(t, work, "init")
	mustRunGit(t, work, "config", "user.email", "dev@gitsaas.test")
	mustRunGit(t, work, "config", "user.name", "GitFrok test")
	if err := os.WriteFile(filepath.Join(work, "README.md"), []byte("direct push\n"), 0o600); err != nil {
		t.Fatalf("write README: %v", err)
	}
	mustRunGit(t, work, "add", "README.md")
	mustRunGit(t, work, "commit", "-m", "initial")
	commit := mustGitOutput(t, work, "rev-parse", "HEAD")
	pack := packForCommit(t, work, commit)

	events := bus.NewInProcess()
	observed := &[]repoapi.RefUpdated{}
	bus.SubscribeTyped(events, func(_ context.Context, event repoapi.RefUpdated) error {
		*observed = append(*observed, event)
		return nil
	})
	client, closeClient := newClientWithConfig(t, Config{
		RepositoryRoot: root, PDP: pdp, Events: events,
		Protection: protection, command: testGitCommand,
	})
	t.Cleanup(closeClient)
	return client, bare, commit, pack, observed
}

// AC3: a direct receive-pack update to an explicitly protected ref is denied
// through the PDP, and the ref does not move.
func TestDirectPushToAProtectedRefIsRefused(t *testing.T) {
	pdp := &protectionPDP{}
	protection := staticProtection{"tenant-a/repo-a": {"refs/heads/main"}}
	client, bare, commit, pack, observed := pushFixture(t, protection, pdp)

	pushOne(t, client, "tenant-a", "repo-a", "refs/heads/main", commit, pack)

	if _, err := os.Stat(filepath.Join(bare, "refs", "heads", "main")); err == nil {
		t.Fatal("the protected ref was created by a direct push")
	}
	if len(*observed) != 0 {
		t.Fatalf("a refused push announced %d ref updates", len(*observed))
	}

	// The refusal came from the PDP, with context storage derived itself.
	var asked bool
	for _, request := range pdp.asked {
		if request.Context["operation"] == "direct_push" && request.Context["target_ref"] == "refs/heads/main" && request.Context["protected"] == "true" {
			asked = true
		}
	}
	if !asked {
		t.Fatalf("the push was refused without a direct-push decision: %+v", pdp.asked)
	}
}

// The rule is per ref: an unprotected branch in the same repository still accepts
// a direct push, so protection is not a repository-wide freeze.
func TestDirectPushToAnUnprotectedRefStillLands(t *testing.T) {
	pdp := &protectionPDP{}
	protection := staticProtection{"tenant-a/repo-a": {"refs/heads/main"}}
	client, bare, commit, pack, observed := pushFixture(t, protection, pdp)

	pushOne(t, client, "tenant-a", "repo-a", "refs/heads/feature", commit, pack)

	if _, err := os.Stat(filepath.Join(bare, "refs", "heads", "feature")); err != nil {
		t.Fatalf("an unprotected ref was refused: %v", err)
	}
	if len(*observed) != 1 {
		t.Fatalf("RefUpdated published %d times, want 1", len(*observed))
	}
}

// A repository with no protection rule behaves exactly as before.
func TestDirectPushIsUnaffectedWithoutAProtectionRule(t *testing.T) {
	client, bare, commit, pack, _ := pushFixture(t, staticProtection{}, &protectionPDP{})

	pushOne(t, client, "tenant-a", "repo-a", "refs/heads/main", commit, pack)

	if _, err := os.Stat(filepath.Join(bare, "refs", "heads", "main")); err != nil {
		t.Fatalf("a push to an unprotected repository was refused: %v", err)
	}
}

// A protection rule in another tenant is not a rule here.
func TestProtectionInAnotherTenantDoesNotRefuseThisPush(t *testing.T) {
	protection := staticProtection{"tenant-b/repo-a": {"refs/heads/main"}}
	client, bare, commit, pack, _ := pushFixture(t, protection, &protectionPDP{})

	pushOne(t, client, "tenant-a", "repo-a", "refs/heads/main", commit, pack)

	if _, err := os.Stat(filepath.Join(bare, "refs", "heads", "main")); err != nil {
		t.Fatalf("another tenant's protection rule refused this push: %v", err)
	}
}

// The hook is rewritten on every push, so a repository whose hook was removed —
// restored from a backup, created by an import, edited by hand — cannot end up
// silently accepting a direct push to a protected ref.
func TestTheHookIsRestoredBeforeEveryPush(t *testing.T) {
	protection := staticProtection{"tenant-a/repo-a": {"refs/heads/main"}}
	client, bare, commit, pack, _ := pushFixture(t, protection, &protectionPDP{})

	hook := filepath.Join(bare, "hooks", "pre-receive")
	if err := os.RemoveAll(filepath.Join(bare, "hooks")); err != nil {
		t.Fatalf("removing the hooks directory: %v", err)
	}

	pushOne(t, client, "tenant-a", "repo-a", "refs/heads/main", commit, pack)

	if _, err := os.Stat(hook); err != nil {
		t.Fatalf("the hook was not restored: %v", err)
	}
	if _, err := os.Stat(filepath.Join(bare, "refs", "heads", "main")); err == nil {
		t.Fatal("a push landed on the protected ref after its hook was removed")
	}
}

// Deny by default: a PDP that cannot answer closes the protected branch rather
// than opening it.
func TestAnUnreachablePDPClosesTheProtectedRef(t *testing.T) {
	protection := staticProtection{"tenant-a/repo-a": {"refs/heads/main"}}
	client, bare, commit, pack, _ := pushFixture(t, protection, &partialPDP{})

	pushOne(t, client, "tenant-a", "repo-a", "refs/heads/main", commit, pack)

	if _, err := os.Stat(filepath.Join(bare, "refs", "heads", "main")); err == nil {
		t.Fatal("a protected ref was written while the PDP could not answer")
	}
}

// partialPDP allows the operation to start and then fails the per-ref question,
// which is the shape of a PDP that becomes unreachable mid-request.
type partialPDP struct{}

func (partialPDP) Decide(_ context.Context, req policyapi.Request) (policyapi.Decision, error) {
	if req.Context["operation"] == "direct_push" {
		return policyapi.Decision{}, errors.New("policy decision point unavailable")
	}
	return policyapi.Decision{Allowed: true}, nil
}
