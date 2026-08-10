package main

import (
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
