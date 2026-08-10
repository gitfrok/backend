package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	gitv1 "github.com/gitfrok/backend/gen/proto/git/v1"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
	repoapi "github.com/gitfrok/backend/modules/repository/api"
	"github.com/gitfrok/backend/platform/bus"
)

// mergeFixture builds a bare repository with two commits on refs/heads/main and
// one further commit that a merge would move the ref to.
type mergeFixture struct {
	root            string
	bare            string
	base, head      string
	events          bus.Bus
	observed        *[]repoapi.RefUpdated
	client          gitv1.GitStorageClient
	closeClient     func()
	tenant, repoIDs string
}

func newMergeFixture(t *testing.T, pdp policyapi.DecisionPoint) *mergeFixture {
	t.Helper()
	root := t.TempDir()
	tenantID, repositoryID := "tenant-a", "repo-a"
	bare := filepath.Join(root, tenantID, repositoryID+".git")
	mustRunGit(t, root, "init", "--bare", bare)

	work := t.TempDir()
	mustRunGit(t, work, "init")
	mustRunGit(t, work, "config", "user.email", "dev@gitsaas.test")
	mustRunGit(t, work, "config", "user.name", "GitFrok test")
	if err := os.WriteFile(filepath.Join(work, "README.md"), []byte("base\n"), 0o600); err != nil {
		t.Fatalf("write README: %v", err)
	}
	mustRunGit(t, work, "add", "README.md")
	mustRunGit(t, work, "commit", "-m", "base")
	base := mustGitOutput(t, work, "rev-parse", "HEAD")

	if err := os.WriteFile(filepath.Join(work, "README.md"), []byte("head\n"), 0o600); err != nil {
		t.Fatalf("write README: %v", err)
	}
	mustRunGit(t, work, "add", "README.md")
	mustRunGit(t, work, "commit", "-m", "head")
	head := mustGitOutput(t, work, "rev-parse", "HEAD")

	// Both commits are pushed, so the merge names an object that is already here.
	mustRunGit(t, work, "push", bare, "HEAD:refs/heads/feature")
	mustRunGit(t, work, "push", bare, base+":refs/heads/main")

	events := bus.NewInProcess()
	observed := &[]repoapi.RefUpdated{}
	var mu sync.Mutex
	bus.SubscribeTyped(events, func(_ context.Context, event repoapi.RefUpdated) error {
		mu.Lock()
		*observed = append(*observed, event)
		mu.Unlock()
		return nil
	})
	client, closeClient := newClient(t, root, pdp, events)
	t.Cleanup(closeClient)

	return &mergeFixture{
		root: root, bare: bare, base: base, head: head,
		events: events, observed: observed, client: client, closeClient: closeClient,
		tenant: tenantID, repoIDs: repositoryID,
	}
}

func (f *mergeFixture) request(targetRef, revision, expected string) *gitv1.MergeRefRequest {
	return &gitv1.MergeRefRequest{
		Context: &gitv1.RefUpdateContext{
			TenantId: f.tenant, RepositoryId: f.repoIDs,
			ActorId: "actor-a", RequestId: "request-a", ActorRoles: []string{"member"},
		},
		TargetRef: targetRef, Revision: revision, ExpectedCurrentRevision: expected,
	}
}

func (f *mergeFixture) ref(t *testing.T, name string) string {
	t.Helper()
	return mustGitOutput(t, f.bare, "show-ref", "--verify", "--hash", name)
}

// The authorized merge is the only route that moves a protected ref, and it must
// actually move it (SPEC-0019 AC3).
func TestMergeRefMovesTheTargetRefAndAnnouncesIt(t *testing.T) {
	fixture := newMergeFixture(t, allowPDP{})

	response, err := fixture.client.MergeRef(t.Context(), fixture.request("refs/heads/main", fixture.head, fixture.base))
	if err != nil {
		t.Fatalf("MergeRef: %v", err)
	}
	if response.GetRevision() != fixture.head {
		t.Fatalf("response revision = %q, want %q", response.GetRevision(), fixture.head)
	}
	if got := fixture.ref(t, "refs/heads/main"); got != fixture.head {
		t.Fatalf("refs/heads/main = %q, want %q", got, fixture.head)
	}
	if len(*fixture.observed) != 1 {
		t.Fatalf("RefUpdated published %d times, want 1", len(*fixture.observed))
	}
	event := (*fixture.observed)[0]
	if event.Ref != "refs/heads/main" || event.OldSha != fixture.base || event.NewSha != fixture.head {
		t.Fatalf("RefUpdated = %+v", event)
	}
}

// Storage asks its own PDP with its own context. `operation` is set here, which is
// what makes the protected-branch rule safe: a caller cannot present a merge as a
// direct push or the reverse.
func TestMergeRefAsksThePDPWithAServerDerivedOperation(t *testing.T) {
	pdp := &recordingPDP{decision: policyapi.Decision{Allowed: true}}
	fixture := newMergeFixture(t, pdp)

	if _, err := fixture.client.MergeRef(t.Context(), fixture.request("refs/heads/main", fixture.head, fixture.base)); err != nil {
		t.Fatalf("MergeRef: %v", err)
	}
	if pdp.request.Action != "repo.write" {
		t.Fatalf("action = %q, want repo.write", pdp.request.Action)
	}
	if pdp.request.Context["operation"] != "merge" {
		t.Fatalf("operation = %q, want merge", pdp.request.Context["operation"])
	}
	if pdp.request.Context["target_ref"] != "refs/heads/main" {
		t.Fatalf("target_ref = %q", pdp.request.Context["target_ref"])
	}
	if _, present := pdp.request.Context["allowed"]; present {
		t.Fatal("the decision context carried an allow flag")
	}
}

func TestMergeRefDeniedByThePDPMovesNothing(t *testing.T) {
	pdp := &recordingPDP{decision: policyapi.Decision{Allowed: false}}
	fixture := newMergeFixture(t, pdp)

	if _, err := fixture.client.MergeRef(t.Context(), fixture.request("refs/heads/main", fixture.head, fixture.base)); err == nil {
		t.Fatal("a PDP denial still moved the ref")
	}
	if got := fixture.ref(t, "refs/heads/main"); got != fixture.base {
		t.Fatalf("refs/heads/main = %q, want it left at %q", got, fixture.base)
	}
	if len(*fixture.observed) != 0 {
		t.Fatalf("a denied merge announced %d ref updates", len(*fixture.observed))
	}
}

// The compare-and-swap is the point: a merge decided against one state cannot
// land on a different one.
func TestMergeRefRefusesAStaleExpectedRevision(t *testing.T) {
	fixture := newMergeFixture(t, allowPDP{})

	if _, err := fixture.client.MergeRef(t.Context(), fixture.request("refs/heads/main", fixture.head, fixture.head)); err == nil {
		t.Fatal("a merge against a revision the ref was never at was applied")
	}
	if got := fixture.ref(t, "refs/heads/main"); got != fixture.base {
		t.Fatalf("refs/heads/main = %q, want it unchanged", got)
	}
}

// An empty expected revision means the ref is expected not to exist, so it must
// not silently overwrite one that does.
func TestMergeRefRefusesAnExistingRefWhenNoneWasExpected(t *testing.T) {
	fixture := newMergeFixture(t, allowPDP{})

	if _, err := fixture.client.MergeRef(t.Context(), fixture.request("refs/heads/main", fixture.head, "")); err == nil {
		t.Fatal("a merge expecting no ref overwrote an existing one")
	}
	if got := fixture.ref(t, "refs/heads/main"); got != fixture.base {
		t.Fatalf("refs/heads/main = %q, want it unchanged", got)
	}
}

// A revision that is not in this repository would leave the ref pointing at
// nothing resolvable.
func TestMergeRefRefusesAnUnknownRevision(t *testing.T) {
	fixture := newMergeFixture(t, allowPDP{})
	absent := strings.Repeat("a", 40)

	if _, err := fixture.client.MergeRef(t.Context(), fixture.request("refs/heads/main", absent, fixture.base)); err == nil {
		t.Fatal("a merge to a revision this repository does not have was applied")
	}
	if got := fixture.ref(t, "refs/heads/main"); got != fixture.base {
		t.Fatalf("refs/heads/main = %q, want it unchanged", got)
	}
}

// MergeRef is narrower than a ref write: it moves one exact branch, and nothing
// that could be read as a pattern, a path escape, an option, or a non-branch ref.
func TestMergeRefRefusesAnythingButAnExactBranchRef(t *testing.T) {
	fixture := newMergeFixture(t, allowPDP{})

	for _, ref := range []string{
		"refs/heads/*", "refs/heads/", "refs/heads/../../etc", "refs/heads/a//b",
		"refs/tags/v1", "refs/heads/-delete", "HEAD", "main", "refs/heads/main.lock",
	} {
		if _, err := fixture.client.MergeRef(t.Context(), fixture.request(ref, fixture.head, fixture.base)); err == nil {
			t.Errorf("MergeRef accepted %q", ref)
		}
	}
	if got := fixture.ref(t, "refs/heads/main"); got != fixture.base {
		t.Fatalf("refs/heads/main = %q, want it unchanged", got)
	}
}

// A revision expression could name something other than the object the caller
// decided about, so only a full object ID is accepted.
func TestMergeRefRefusesARevisionExpression(t *testing.T) {
	fixture := newMergeFixture(t, allowPDP{})

	for _, revision := range []string{"HEAD", "refs/heads/feature", fixture.head[:8], fixture.head + "^", ""} {
		if _, err := fixture.client.MergeRef(t.Context(), fixture.request("refs/heads/main", revision, fixture.base)); err == nil {
			t.Errorf("MergeRef accepted the revision expression %q", revision)
		}
	}
}

// The tenant-scoped handle is resolved by storage. Another tenant's request finds
// nothing, in the same coarse shape as every other storage refusal.
func TestMergeRefIsTenantScoped(t *testing.T) {
	fixture := newMergeFixture(t, allowPDP{})
	request := fixture.request("refs/heads/main", fixture.head, fixture.base)
	request.Context.TenantId = "tenant-b"

	if _, err := fixture.client.MergeRef(t.Context(), request); err == nil {
		t.Fatal("a merge from another tenant was applied")
	}
	if got := fixture.ref(t, "refs/heads/main"); got != fixture.base {
		t.Fatalf("refs/heads/main = %q, want it unchanged", got)
	}
}
