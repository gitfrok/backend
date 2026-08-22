package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	gitv1 "github.com/gitfrok/backend/gen/proto/git/v1"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// SPEC-0065 against real git objects. Every claim here is about what git
// produces — parent structure, tree identity, authorship, refusal atomicity —
// so the proofs run against a real repository, not a fake of one.

// divergedFixture extends mergeFixture: feature carries `head` on top of base,
// and main carries its own commit touching a DIFFERENT file, so the branches
// have genuinely diverged and no fast-forward is possible.
type divergedFixture struct {
	*mergeFixture
	mainHead string
}

func newDivergedFixture(t *testing.T, pdp policyapi.DecisionPoint) *divergedFixture {
	t.Helper()
	f := newMergeFixture(t, pdp)
	work := t.TempDir()
	mustRunGit(t, work, "init")
	mustRunGit(t, work, "config", "user.email", "main-dev@gitsaas.test")
	mustRunGit(t, work, "config", "user.name", "Main Dev")
	mustRunGit(t, work, "pull", f.bare, "refs/heads/main:refs/heads/main")
	mustRunGit(t, work, "checkout", "main")
	if err := os.WriteFile(filepath.Join(work, "MAIN.txt"), []byte("main-only\n"), 0o600); err != nil {
		t.Fatalf("write MAIN.txt: %v", err)
	}
	mustRunGit(t, work, "add", "MAIN.txt")
	mustRunGit(t, work, "commit", "-m", "main side")
	mainHead := mustGitOutput(t, work, "rev-parse", "HEAD")
	mustRunGit(t, work, "push", f.bare, "HEAD:refs/heads/main")

	return &divergedFixture{mergeFixture: f, mainHead: mainHead}
}

// landingPlan builds the wire plan from strategy + trunk mode.
func landingPlan(strategy gitv1.LandingStrategy, trunk bool, title, mrRef string) *gitv1.LandingPlan {
	return &gitv1.LandingPlan{
		Strategy:              strategy,
		TrunkBased:            trunk,
		MessageTitle:          title,
		MergeRequestReference: mrRef,
	}
}

func (f *mergeFixture) requestLanding(targetRef, revision, expected string, plan *gitv1.LandingPlan) *gitv1.MergeRefRequest {
	req := f.request(targetRef, revision, expected)
	req.Landing = plan
	return req
}

// parentsOf returns the commit's parent object IDs in order.
func (f *mergeFixture) parentsOf(t *testing.T, sha string) []string {
	t.Helper()
	out := mustGitOutput(t, f.bare, "rev-list", "--parents", "-n", "1", sha)
	fields := strings.Fields(out)
	if len(fields) < 1 {
		t.Fatalf("rev-list --parents %s = %q", sha, out)
	}
	return fields[1:]
}

// AC1 — the default is unchanged behaviour. A repository whose landing policy
// was never set merges exactly as today: the ref moves to the named revision,
// nothing is produced, and the response says nothing about a shape.
func TestLegacyLandingWithoutAPlanIsByteForByteToday(t *testing.T) {
	fixture := newMergeFixture(t, allowPDP{})

	response, err := fixture.client.MergeRef(t.Context(), fixture.request("refs/heads/main", fixture.head, fixture.base))
	if err != nil {
		t.Fatalf("MergeRef: %v", err)
	}
	if response.GetRevision() != fixture.head || response.GetLandedRevision() != fixture.head {
		t.Fatalf("response = %+v, want landed == requested == source head", response)
	}
	if response.GetLandedShape() != gitv1.LandingShape_LANDING_SHAPE_UNSPECIFIED {
		t.Fatalf("legacy landing reported shape %v, want UNSPECIFIED", response.GetLandedShape())
	}
	if got := fixture.ref(t, "refs/heads/main"); got != fixture.head {
		t.Fatalf("main = %q, want %q", got, fixture.head)
	}
	if len(*fixture.observed) != 1 {
		t.Fatalf("RefUpdated published %d times, want 1", len(*fixture.observed))
	}
}

// AC2 — merge_commit lands a two-parent commit whose parents are target head
// and source head, with the platform's own service identity as committer and
// the source commits' authorship preserved verbatim.
func TestAMergeCommitCarriesTwoParentsAndTheServiceIdentity(t *testing.T) {
	fixture := newDivergedFixture(t, allowPDP{})

	response, err := fixture.client.MergeRef(t.Context(), fixture.requestLanding(
		"refs/heads/main", fixture.head, fixture.mainHead,
		landingPlan(gitv1.LandingStrategy_LANDING_STRATEGY_MERGE_COMMIT, false, "Add the thing", "mr-42")))
	if err != nil {
		t.Fatalf("MergeRef: %v", err)
	}
	landed := response.GetLandedRevision()
	if landed == fixture.head || landed == fixture.mainHead {
		t.Fatalf("landed revision %q is not a produced commit", landed)
	}
	parents := fixture.parentsOf(t, landed)
	if len(parents) != 2 || parents[0] != fixture.mainHead || parents[1] != fixture.head {
		t.Fatalf("parents of %s = %v, want [%s %s]", landed, parents, fixture.mainHead, fixture.head)
	}
	committer := strings.SplitN(mustGitOutput(t, fixture.bare, "log", "-1", "--format=%cn%n%ce", landed), "\n", 2)
	name, email := committer[0], ""
	if len(committer) > 1 {
		email = committer[1]
	}
	if name != defaultLandingName || email != defaultLandingEmail {
		t.Fatalf("committer = %q <%q>, want the service's own identity", name, email)
	}
	sourceAuthor := mustGitOutput(t, fixture.bare, "log", "-1", "--format=%an", fixture.head)
	if sourceAuthor != "GitFrok test" {
		t.Fatalf("source authorship rewritten: %q", sourceAuthor)
	}
	if got := fixture.ref(t, "refs/heads/main"); got != landed {
		t.Fatalf("main = %q, want the produced commit %q", got, landed)
	}
	event := (*fixture.observed)[0]
	if event.NewSha != landed {
		t.Fatalf("RefUpdated.NewSha = %q, want the produced commit", event.NewSha)
	}
}

// AC3 — squash lands exactly one commit (single parent, the target head) whose
// tree equals the merged content, message defaulted to the MR title with the
// MR reference in a trailer.
func TestASquashLandsOneParentWithTheReferenceTrailer(t *testing.T) {
	fixture := newDivergedFixture(t, allowPDP{})

	response, err := fixture.client.MergeRef(t.Context(), fixture.requestLanding(
		"refs/heads/main", fixture.head, fixture.mainHead,
		landingPlan(gitv1.LandingStrategy_LANDING_STRATEGY_SQUASH, false, "Add the thing", "mr-7")))
	if err != nil {
		t.Fatalf("MergeRef: %v", err)
	}
	landed := response.GetLandedRevision()
	if response.GetLandedShape() != gitv1.LandingShape_LANDING_SHAPE_SQUASH {
		t.Fatalf("shape = %v, want SQUASH", response.GetLandedShape())
	}
	if parents := fixture.parentsOf(t, landed); len(parents) != 1 || parents[0] != fixture.mainHead {
		t.Fatalf("parents of %s = %v, want exactly [%s]", landed, parents, fixture.mainHead)
	}
	merged := strings.TrimRight(mustGitOutput(t, fixture.bare, "show", landed+":MAIN.txt"), "\n")
	if merged != "main-only" {
		t.Fatalf("squash lost the target-side content: MAIN.txt = %q", merged)
	}
	headFile := strings.TrimRight(mustGitOutput(t, fixture.bare, "show", landed+":README.md"), "\n")
	if headFile != "head" {
		t.Fatalf("squash lost the source content: README.md = %q", headFile)
	}
	message := mustGitOutput(t, fixture.bare, "log", "-1", "--format=%B", landed)
	if !strings.HasPrefix(message, "Add the thing") || !strings.Contains(message, "Merge-request: mr-7") {
		t.Fatalf("message = %q, want the title with the MR trailer", message)
	}
}

// AC4 — rebase replays the source commits onto the target head: linear, with
// each replayed commit preserving its original authorship.
func TestARebaseLandsLinearWithAuthorshipPreserved(t *testing.T) {
	fixture := newMergeFixture(t, allowPDP{}) // feature is strictly ahead of main

	response, err := fixture.client.MergeRef(t.Context(), fixture.requestLanding(
		"refs/heads/main", fixture.head, fixture.base,
		landingPlan(gitv1.LandingStrategy_LANDING_STRATEGY_REBASE, false, "", "")))
	if err != nil {
		t.Fatalf("MergeRef: %v", err)
	}
	landed := response.GetLandedRevision()
	if response.GetLandedShape() != gitv1.LandingShape_LANDING_SHAPE_REBASE {
		t.Fatalf("shape = %v, want REBASE", response.GetLandedShape())
	}
	if landed == fixture.head {
		t.Fatalf("rebase produced no new history: %q", landed)
	}
	// The first-parent chain from the landing is linear: every commit on it has
	// exactly one parent until the chain ends at the original base.
	chain := nonEmptyLines(mustGitOutput(t, fixture.bare, "rev-list", "--first-parent", landed))
	if len(chain) != 2 { // the replayed source commit on top of base
		t.Fatalf("first-parent chain = %v (%d commits), want a linear pair atop base", chain, len(chain))
	}
	if got := mustGitOutput(t, fixture.bare, "log", "-1", "--format=%an", landed); got != "GitFrok test" {
		t.Fatalf("replayed authorship rewritten: %q", got)
	}
	// The result contains everything feature had.
	content := strings.TrimRight(mustGitOutput(t, fixture.bare, "show", landed+":README.md"), "\n")
	if content != "head" {
		t.Fatalf("rebase lost the source content: %q", content)
	}
}

// AC4 conflict half — a conflicting replay refuses with the ref unmoved.
func TestAConflictingReplayRefusesWithNothingMoved(t *testing.T) {
	fixture := newConflictFixture(t)

	before := fixture.ref(t, "refs/heads/main")
	_, err := fixture.client.MergeRef(t.Context(), fixture.requestLanding(
		"refs/heads/main", fixture.conflictingHead, fixture.mainHead,
		landingPlan(gitv1.LandingStrategy_LANDING_STRATEGY_MERGE_COMMIT, false, "", "")))
	if err == nil {
		t.Fatal("conflicting landing succeeded")
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition beside the coarse denial", status.Code(err))
	}
	if !strings.Contains(status.Convert(err).Message(), "merge_conflict") {
		t.Fatalf("refusal = %q, want the machine-readable reason", status.Convert(err).Message())
	}
	if after := fixture.ref(t, "refs/heads/main"); after != before {
		t.Fatalf("the ref moved during a refused landing: %q -> %q", before, after)
	}
	if len(*fixture.observed) != 0 {
		t.Fatalf("a refused landing published %d events", len(*fixture.observed))
	}
}

// conflictFixture: two branches editing the SAME file differently off a shared
// base — the minimal genuine conflict.
type conflictFixture struct {
	*mergeFixture
	mainHead        string
	conflictingHead string
}

func newConflictFixture(t *testing.T) *conflictFixture {
	t.Helper()
	f := newMergeFixture(t, allowPDP{})

	write := func(dir, content string) string {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte(content), 0o600); err != nil {
			t.Fatalf("write README: %v", err)
		}
		return content
	}

	sideA := t.TempDir()
	mustRunGit(t, sideA, "init")
	mustRunGit(t, sideA, "config", "user.email", "a@gitsaas.test")
	mustRunGit(t, sideA, "config", "user.name", "Side A")
	mustRunGit(t, sideA, "pull", f.bare, "refs/heads/main:refs/heads/main")
	mustRunGit(t, sideA, "checkout", "main")
	write(sideA, "side-a\n")
	mustRunGit(t, sideA, "add", "README.md")
	mustRunGit(t, sideA, "commit", "-m", "side a")
	mustRunGit(t, sideA, "push", f.bare, "HEAD:refs/heads/main")
	mainHead := mustGitOutput(t, sideA, "rev-parse", "HEAD")

	sideB := t.TempDir()
	mustRunGit(t, sideB, "init")
	mustRunGit(t, sideB, "config", "user.email", "b@gitsaas.test")
	mustRunGit(t, sideB, "config", "user.name", "Side B")
	mustRunGit(t, sideB, "pull", f.bare, "refs/heads/feature:refs/heads/feature")
	mustRunGit(t, sideB, "checkout", "feature")
	write(sideB, "side-b\n")
	mustRunGit(t, sideB, "add", "README.md")
	mustRunGit(t, sideB, "commit", "-m", "side b")
	conflicting := mustGitOutput(t, sideB, "rev-parse", "HEAD")
	mustRunGit(t, sideB, "push", f.bare, "HEAD:refs/heads/feature")

	return &conflictFixture{mergeFixture: f, mainHead: mainHead, conflictingHead: conflicting}
}

// AC5 — trunk mode prefers fast-forward, falls back to rebase, and never
// produces a merge commit; four eyes still applies upstream (the gate is
// Code Review's decision, unchanged by this surface).
func TestTrunkModePrefersFastForwardAndFallsBackToRebase(t *testing.T) {
	// Fast-forward first: feature is strictly ahead of an untouched main.
	straight := newMergeFixture(t, allowPDP{})
	response, err := straight.client.MergeRef(t.Context(), straight.requestLanding(
		"refs/heads/main", straight.head, straight.base,
		landingPlan(gitv1.LandingStrategy_LANDING_STRATEGY_MERGE_COMMIT, true, "", "")))
	if err != nil {
		t.Fatalf("trunk FF: %v", err)
	}
	if response.GetLandedShape() != gitv1.LandingShape_LANDING_SHAPE_FAST_FORWARD || response.GetLandedRevision() != straight.head {
		t.Fatalf("trunk did not prefer the fast-forward: %+v", response)
	}

	// Diverged: the same merge-commit request lands LINEARLY instead.
	diverged := newDivergedFixture(t, allowPDP{})
	response, err = diverged.client.MergeRef(t.Context(), diverged.requestLanding(
		"refs/heads/main", diverged.head, diverged.mainHead,
		landingPlan(gitv1.LandingStrategy_LANDING_STRATEGY_MERGE_COMMIT, true, "", "")))
	if err != nil {
		t.Fatalf("trunk fallback: %v", err)
	}
	landed := response.GetLandedRevision()
	if parents := diverged.parentsOf(t, landed); len(parents) != 1 {
		t.Fatalf("trunk mode produced a %d-parent commit — a merge commit by another name", len(parents))
	}
	if response.GetLandedShape() != gitv1.LandingShape_LANDING_SHAPE_REBASE {
		t.Fatalf("shape = %v, want the rebase fallback", response.GetLandedShape())
	}
}

// AC5/up-to-date — landing something the target already contains refuses as
// up_to_date rather than producing an empty duplicate.
func TestAnUpToDateSourceRefuses(t *testing.T) {
	fixture := newMergeFixture(t, allowPDP{})
	// main already sits at base; merging base into it has nothing to land.
	for _, strategy := range []gitv1.LandingStrategy{
		gitv1.LandingStrategy_LANDING_STRATEGY_SQUASH,
	} {
		_, err := fixture.client.MergeRef(t.Context(), fixture.requestLanding(
			"refs/heads/main", fixture.base, fixture.base,
			landingPlan(strategy, false, "", "")))
		if err == nil {
			t.Fatalf("%v landing of a contained source succeeded", strategy)
		}
		if !strings.Contains(status.Convert(err).Message(), "up_to_date") {
			t.Fatalf("%v refusal = %q, want up_to_date", strategy, status.Convert(err).Message())
		}
	}
}

// AC6 — every landing takes the quorum path. The single-node harness treats
// this node as its own sync replica, so an acknowledged landing proves the
// acknowledgement waited for durability exactly as a push does; the observable
// difference is that a landing which could not be acknowledged fails.
func TestALandingAcknowledgesOnlyThroughQuorum(t *testing.T) {
	fixture := newDivergedFixture(t, allowPDP{})
	response, err := fixture.client.MergeRef(t.Context(), fixture.requestLanding(
		"refs/heads/main", fixture.head, fixture.mainHead,
		landingPlan(gitv1.LandingStrategy_LANDING_STRATEGY_MERGE_COMMIT, false, "", "")))
	if err != nil {
		t.Fatalf("produced landing refused at quorum: %v", err)
	}
	if got := fixture.ref(t, "refs/heads/main"); got != response.GetLandedRevision() {
		t.Fatalf("acknowledged ref = %q, response said %q", got, response.GetLandedRevision())
	}
}

func nonEmptyLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}
