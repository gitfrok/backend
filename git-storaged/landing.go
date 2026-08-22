package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	gitv1 "github.com/gitfrok/backend/gen/proto/git/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// The landing engine (SPEC-0065, ADR-0088): when a merge arrives with a
// landing plan, storage resolves the effective shape from the object graph —
// its own fact, never the caller's claim — and produces whatever commits the
// shape needs before moving the ref through the same compare-and-swap and
// quorum path every landing takes.
//
// Two properties are load-bearing:
//
//   - A conflicting landing refuses BEFORE anything moves. merge-tree computes
//     the content merge into tree objects no ref points at; a conflict leaves
//     the graph untouched and returns one machine-readable reason beside the
//     coarse denial.
//   - The committer of a produced commit is this service's own identity,
//     never the caller's name: history answers "which review landed this"
//     through the Merge-request trailer, not by impersonating a person.
//
// Under trunk mode the resolution is ADR-0088's sentence read literally:
// fast-forward preferred, rebase as the fallback, merge commits never —
// whatever strategy asked for. Without a plan at all, MergeRef behaves
// byte-for-byte as it always did (SPEC-0065 AC1).

// Landing identity defaults. Per-environment overrides ride the Config so a
// deployment can name itself (invariant 13); these say only what an unset
// deployment calls itself.
const (
	defaultLandingName  = "gitfrok-landing"
	defaultLandingEmail = "landing@gitsaas.test"
)

// Machine-readable refusal reasons. They travel as the gRPC error message on
// FailedPrecondition — beside the coarse denial, never instead of it: Code
// Review maps every refusal to its own coarse surface but records WHY nothing
// moved, and the audit trail keeps that reason with the compensation.
const (
	reasonConflict     = "landing refused: merge_conflict"
	reasonUpToDate     = "landing refused: up_to_date"
	reasonRebaseUnsafe = "landing refused: rebase_path_unproven"
)

func refuseLanding(reason string) error {
	return status.Error(codes.FailedPrecondition, reason)
}

// resolveLanding decides what lands and produces any commits needed. It
// returns the revision to move the ref to and the shape that was executed.
func (s *Server) resolveLanding(ctx context.Context, path string, current, sourceRevision, refLabel string, plan *gitv1.LandingPlan) (string, gitv1.LandingShape, error) {
	if current == "" {
		// Producing a commit onto an unborn target has no base to land on, and
		// no strategy here defines an unborn target's landing.
		return "", 0, unavailable()
	}
	ffPossible := s.isAncestor(ctx, path, current, sourceRevision)
	strategy := plan.GetStrategy()
	trunk := plan.GetTrunkBased()

	// Trunk mode first: it constrains everything (AC5).
	if trunk && ffPossible {
		return sourceRevision, gitv1.LandingShape_LANDING_SHAPE_FAST_FORWARD, nil
	}
	if trunk {
		switch strategy {
		case gitv1.LandingStrategy_LANDING_STRATEGY_SQUASH:
			return s.landSquash(ctx, path, current, sourceRevision, plan)
		default:
			// REBASE asked for, or MERGE_COMMIT/UNSPECIFIED converted: the
			// fallback is rebase, and merge commits are refused outright.
			return s.landRebase(ctx, path, current, sourceRevision, refLabel)
		}
	}

	// No trunk mode: the strategy executes as chosen.
	switch strategy {
	case gitv1.LandingStrategy_LANDING_STRATEGY_MERGE_COMMIT:
		tree, conflict, err := s.mergeTreeWrite(ctx, path, current, sourceRevision)
		if err != nil {
			return "", 0, unavailable()
		}
		if conflict {
			return "", 0, refuseLanding(reasonConflict)
		}
		message := fmt.Sprintf("Merge merge request %q\n\nMerge-request: %s\n",
			plan.GetMessageTitle(), plan.GetMergeRequestReference())
		sha, err := s.commitTree(ctx, path, tree, []string{current, sourceRevision}, message)
		if err != nil {
			return "", 0, unavailable()
		}
		return sha, gitv1.LandingShape_LANDING_SHAPE_MERGE_COMMIT, nil

	case gitv1.LandingStrategy_LANDING_STRATEGY_SQUASH:
		return s.landSquash(ctx, path, current, sourceRevision, plan)

	case gitv1.LandingStrategy_LANDING_STRATEGY_REBASE:
		return s.landRebase(ctx, path, current, sourceRevision, refLabel)

	default:
		// A present-but-empty plan is the legacy landing; callers that mean
		// legacy send no landing field at all, and MergeRef guards this.
		return "", 0, unavailable()
	}
}

// landSquash lands exactly one commit whose tree is the merged content of
// source into target, whose single parent is the target head, and whose
// message defaults to the MR title with the MR reference in a trailer (AC3).
func (s *Server) landSquash(ctx context.Context, path string, current, sourceRevision string, plan *gitv1.LandingPlan) (string, gitv1.LandingShape, error) {
	commits, err := s.revListCount(ctx, path, current, sourceRevision)
	if err != nil {
		return "", 0, unavailable()
	}
	if commits == 0 {
		return "", 0, refuseLanding(reasonUpToDate)
	}
	tree, conflict, err := s.mergeTreeWrite(ctx, path, current, sourceRevision)
	if err != nil {
		return "", 0, unavailable()
	}
	if conflict {
		return "", 0, refuseLanding(reasonConflict)
	}
	title := plan.GetMessageTitle()
	if title == "" {
		title = "Squashed landing"
	}
	sha, err := s.commitTree(ctx, path, tree, []string{current},
		fmt.Sprintf("%s\n\nMerge-request: %s\n", title, plan.GetMergeRequestReference()))
	if err != nil {
		return "", 0, unavailable()
	}
	return sha, gitv1.LandingShape_LANDING_SHAPE_SQUASH, nil
}

// landRebase replays the source-only commits onto the target head through
// `git replay`, the worktree-free replayer (git ≥ 2.44). The result is linear
// by construction; a conflicting replay exits non-zero with the ref unmoved
// (AC4). Where the node's git cannot prove the path, the landing refuses —
// ADR-0088's named risk ships unsafe nowhere.
func (s *Server) landRebase(ctx context.Context, path string, current, sourceRevision, refLabel string) (string, gitv1.LandingShape, error) {
	if !s.replayProven() {
		return "", 0, refuseLanding(reasonRebaseUnsafe)
	}
	commits, err := s.revListCount(ctx, path, current, sourceRevision)
	if err != nil {
		return "", 0, unavailable()
	}
	if commits == 0 {
		return "", 0, refuseLanding(reasonUpToDate)
	}
	// --ref-action=print is the whole safety story: replay names what it
	// WOULD update and touches nothing itself; the only ref move is this
	// function's caller, through the same compare-and-swap every landing takes.
	// `git replay` writes commits, so it needs a committer identity like every
	// other producing path here. Without one it exits 128 with "unable to
	// auto-detect email address" — which this function used to report as
	// merge_conflict. The service's own identity is the committer; the AUTHOR is
	// deliberately NOT set, because replay carries each replayed commit's
	// original author forward and AC4 requires that authorship survive.
	name, email := s.landingIdentity()
	replay := s.command(ctx, "git", "-C", path, "replay",
		"--onto="+current, "--ref="+refLabel, "--ref-action=print",
		current+".."+sourceRevision)
	replay.Env = append(os.Environ(),
		"GIT_COMMITTER_NAME="+name, "GIT_COMMITTER_EMAIL="+email,
	)
	output, err := replay.Output()
	if err != nil {
		// A replay that cannot complete cleanly refuses before anything moves;
		// `git replay` writes nothing to the object database until it succeeds.
		return "", 0, refuseLanding(reasonConflict)
	}
	head, ok := lastReplayedHead(output)
	if !ok || head == "" {
		return "", 0, unavailable()
	}
	return head, gitv1.LandingShape_LANDING_SHAPE_REBASE, nil
}

// lastReplayedHead reads `git replay`'s stdout: one `update <ref> <new> <old>`
// line per replayed commit; the last line's new value is the landing head.
func lastReplayedHead(output []byte) (string, bool) {
	var head string
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[0] == "update" {
			head = fields[2]
		}
	}
	return head, head != ""
}

// isAncestor reports whether ancestor is contained in descendant — the test
// that makes a fast-forward possible at all.
func (s *Server) isAncestor(ctx context.Context, path, ancestor, descendant string) bool {
	return s.command(ctx, "git", "-C", path,
		"merge-base", "--is-ancestor", ancestor, descendant).Run() == nil
}

// revListCount counts the source commits the target does not already contain.
func (s *Server) revListCount(ctx context.Context, path, current, sourceRevision string) (int, error) {
	output, err := s.command(ctx, "git", "-C", path,
		"rev-list", "--count", current+".."+sourceRevision).Output()
	if err != nil {
		return 0, err
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(output)))
	if err != nil {
		return 0, err
	}
	return n, nil
}

// mergeTreeWrite computes the content merge of two commits into tree objects
// WITHOUT touching any ref (`git merge-tree --write-tree`). Exit zero names
// the merged tree on stdout; exit one IS the conflict signal — the graph
// changed only in objects no ref points at, which nothing accepts unless a
// later ref move does.
func (s *Server) mergeTreeWrite(ctx context.Context, path, ours, theirs string) (tree string, conflict bool, err error) {
	output, runErr := s.command(ctx, "git", "-C", path,
		"merge-tree", "--write-tree", ours, theirs).Output()
	if runErr == nil {
		first := strings.SplitN(string(output), "\n", 2)[0]
		if strings.TrimSpace(first) == "" {
			return "", false, fmt.Errorf("merge-tree wrote no tree")
		}
		return strings.TrimSpace(first), false, nil
	}
	if exitCode(runErr) == 1 {
		return "", true, nil
	}
	return "", false, runErr
}

// commitTree produces one commit from a tree, parents and message, authored
// AND committed as this service's own identity — never the caller's name
// (SPEC-0065 AC2).
func (s *Server) commitTree(ctx context.Context, path, tree string, parents []string, message string) (string, error) {
	args := []string{"-C", path, "commit-tree", tree}
	for _, parent := range parents {
		args = append(args, "-p", parent)
	}
	args = append(args, "-m", message)
	name, email := s.landingIdentity()
	cmd := s.command(ctx, "git", args...)
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME="+name, "GIT_AUTHOR_EMAIL="+email,
		"GIT_COMMITTER_NAME="+name, "GIT_COMMITTER_EMAIL="+email,
	)
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

func (s *Server) landingIdentity() (name, email string) {
	if s.landingName != "" {
		name = s.landingName
	} else {
		name = defaultLandingName
	}
	if s.landingEmail != "" {
		email = s.landingEmail
	} else {
		email = defaultLandingEmail
	}
	return name, email
}

// exitCode extracts a command's exit status without importing os/exec twice
// per call site; non-exit failures report -1 and are never a conflict signal.
func exitCode(err error) int {
	type exitCoder interface{ ExitCode() int }
	if coder, ok := err.(exitCoder); ok {
		return coder.ExitCode()
	}
	return -1
}

// replayProven reports whether this node's git can produce a rebase landing
// through the worktree-free path (`git replay`, git >= 2.44). Probed once;
// git does not change under a running process.
func (s *Server) replayProven() bool {
	s.replayMu.Lock()
	defer s.replayMu.Unlock()
	if !s.replayProvenCache {
		out, _ := s.command(context.Background(), "git", "version").Output()
		s.replayProvenCache = gitVersionAtLeast(string(out), 2, 44)
	}
	return s.replayProvenCache
}

// gitVersionAtLeast parses `git version X.Y.Z` far enough to gate the one
// capability the rebase landing depends on. A parse failure is an honest no.
func gitVersionAtLeast(versionOutput string, wantMajor, wantMinor int) bool {
	fields := strings.Fields(strings.TrimSpace(versionOutput))
	if len(fields) < 3 || fields[0] != "git" || fields[1] != "version" {
		return false
	}
	parts := strings.SplitN(fields[2], ".", 3)
	if len(parts) < 2 {
		return false
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return false
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return false
	}
	return major > wantMajor || (major == wantMajor && minor >= wantMinor)
}
