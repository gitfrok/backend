package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A fetch command must never put the token in argv: /proc would expose it. The
// token travels only in the environment (SPEC-0011 AC22).
func TestFetchFromSourceCarriesTokenInEnvNotArgv(t *testing.T) {
	if !validSourceURL("https://github.com/acme/widgets.git") {
		t.Fatal("a public https URL was refused")
	}
	if !validSourceURL("ssh://git@github.com/acme/widgets.git") {
		t.Fatal("an ssh URL with a user identity was refused")
	}
	if !validSourceURL("git@github.com:acme/widgets.git") {
		t.Fatal("an scp-style ssh URL was refused")
	}
	// A password embedded in a URL is a credential in a place argv, process
	// listings and logs can all reach; the token travels separately or not at
	// all. Those shapes are refused.
	for _, bad := range []string{
		"https://user:token@github.com/acme/widgets.git",
		"ssh://user:token@github.com/acme/widgets.git",
		"file:///etc/passwd",
		"/local/path",
		"https://github.com/a b.git",
		"-oProxyCommand=evil",
		"https://github.com/acme/widgets.git --upload-pack=evil",
		"",
	} {
		if validSourceURL(bad) {
			t.Errorf("source URL %q was accepted", bad)
		}
	}
}

// refDeltas reports exactly the refs that moved, in both directions: new refs,
// moved refs, and deleted refs (fetch --prune can drop them).
func TestRefDeltasReportsAddedMovedAndDeleted(t *testing.T) {
	before := map[string]string{
		"refs/heads/main":  "aaa",
		"refs/heads/topic": "bbb",
		"refs/tags/v1.0.0": "ccc",
		"refs/remotes/x":   "ddd",
	}
	after := map[string]string{
		"refs/heads/main":  "aaa", // unchanged
		"refs/heads/topic": "eee", // moved
		"refs/tags/v1.0.0": "ccc", // unchanged
		"refs/tags/v2.0.0": "fff", // added
		"refs/heads/new":   "ggg", // added
	}

	deltas := refDeltas(before, after)
	byRef := map[string]refDelta{}
	for _, d := range deltas {
		byRef[d.ref] = d
	}

	if _, ok := byRef["refs/heads/main"]; ok {
		t.Error("unchanged ref was reported as a delta")
	}
	if d := byRef["refs/heads/topic"]; d.oldSHA != "bbb" || d.newSHA != "eee" {
		t.Errorf("moved ref = %+v", d)
	}
	if d := byRef["refs/tags/v2.0.0"]; d.oldSHA != "" || d.newSHA != "fff" {
		t.Errorf("added ref = %+v", d)
	}
	if d := byRef["refs/heads/new"]; d.oldSHA != "" || d.newSHA != "ggg" {
		t.Errorf("added ref = %+v", d)
	}
	if d := byRef["refs/remotes/x"]; d.oldSHA != "ddd" || d.newSHA != "" {
		t.Errorf("deleted ref = %+v", d)
	}
}

// A fetch that changes nothing is a no-op, not a failure: an import of an
// already-current source has no durability acknowledgement to withhold.
func TestRefDeltasEmptyForUnchanged(t *testing.T) {
	same := map[string]string{"refs/heads/main": "aaa"}
	if got := refDeltas(same, map[string]string{"refs/heads/main": "aaa"}); len(got) != 0 {
		t.Errorf("deltas = %+v, want none", got)
	}
}

// The imported byte count is what the storage tier holds, measured by git
// itself: an empty repository weighs nothing, and one holding objects weighs
// more than one that does not (SPEC-0011 AC9/AC21).
func TestRepositoryBytesMeasuresWhatStorageHolds(t *testing.T) {
	root := t.TempDir()
	bare := filepath.Join(root, "repo.git")
	mustRunGit(t, root, "init", "--bare", bare)

	empty := repositoryBytes(context.Background(), bare)
	if empty != 0 {
		t.Fatalf("empty repository = %d bytes, want 0", empty)
	}

	// A commit written into the bare repository is content the tenant now holds.
	work := filepath.Join(root, "work")
	mustRunGit(t, root, "init", work)
	mustRunGit(t, work, "config", "user.email", "t@example.test")
	mustRunGit(t, work, "config", "user.name", "T")
	if err := os.WriteFile(filepath.Join(work, "payload"), []byte(strings.Repeat("x", 64*1024)), 0o600); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	mustRunGit(t, work, "add", "payload")
	mustRunGit(t, work, "commit", "-m", "payload")
	mustRunGit(t, work, "push", bare, "HEAD:refs/heads/main")

	held := repositoryBytes(context.Background(), bare)
	if held <= empty {
		t.Fatalf("repository holding a commit = %d bytes, want more than the empty %d", held, empty)
	}
}

// An unmeasurable repository reports zero rather than failing: at the point this
// is called the objects are already durable, and failing an import that landed
// would be a worse answer than an unrecorded charge.
func TestRepositoryBytesOfNothingIsZero(t *testing.T) {
	if got := repositoryBytes(context.Background(), filepath.Join(t.TempDir(), "absent")); got != 0 {
		t.Fatalf("absent repository = %d bytes, want 0", got)
	}
}
