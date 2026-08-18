package main

import (
	"encoding/base64"
	"slices"
	"strings"
	"testing"
)

// b64 mirrors the cursor encoder's alphabet so a test can forge one by hand.
var b64 = base64.RawURLEncoding

// SPEC-0053 AC4: a path can never become a flag.
//
// This is the oldest bug in shelling out, and it is asserted against the
// ARGUMENT LIST rather than by running git — running git would prove that this
// git, today, tolerated the input, which is a different claim.

func TestHistoryArgsPlaceEveryPathAfterTheSeparator(t *testing.T) {
	args := historyArgs("/srv/repo.git", "main", "internal/db/query.go", 0, 50)

	sep := slices.Index(args, "--")
	if sep < 0 {
		t.Fatal("no -- separator: a path beginning with a dash would be parsed as a flag")
	}
	path := slices.Index(args, "internal/db/query.go")
	if path < sep {
		t.Fatalf("the path sits before the separator: %v", args)
	}
	// The revision must be BEFORE the separator, or git reads it as a path.
	rev := slices.Index(args, "main")
	if rev > sep {
		t.Fatalf("the revision sits after the separator: %v", args)
	}
}

func TestHistoryArgsCarryTheSeparatorEvenWithNoPath(t *testing.T) {
	// A separator that is only sometimes present is one refactor away from
	// sometimes missing.
	if !slices.Contains(historyArgs("/srv/repo.git", "main", "", 0, 50), "--") {
		t.Fatal("the separator is absent when no path is given")
	}
}

func TestBlameArgsPlaceThePathAfterTheSeparator(t *testing.T) {
	args := blameArgs("/srv/repo.git", "main", "internal/db/query.go")
	sep := slices.Index(args, "--")
	if sep < 0 {
		t.Fatal("no -- separator")
	}
	if slices.Index(args, "internal/db/query.go") < sep {
		t.Fatalf("the path sits before the separator: %v", args)
	}
}

// Rename and copy detection are deliberately off: a heuristic rendered without
// its uncertainty is an overclaim (SPEC-0053 open question 1).
func TestBlameAsksForNoRenameDetection(t *testing.T) {
	for _, arg := range blameArgs("/srv/repo.git", "main", "a.go") {
		if arg == "-C" && slices.Index(blameArgs("/srv/repo.git", "main", "a.go"), arg) != 0 {
			t.Fatalf("blame asks for copy detection: %v", blameArgs("/srv/repo.git", "main", "a.go"))
		}
		if arg == "-M" || arg == "--follow" {
			t.Fatalf("blame asks for rename detection: %v", arg)
		}
	}
}

// AC4's other half: the paths that must never reach an argument list at all.
//
// A leading dash is deliberately NOT in this list. A filename beginning with
// one is legal in a repository, and refusing it here would make those files
// unbrowsable through GetTree, GetFile and GetDiff — a regression to three
// shipped surfaces in the name of a defence the `--` separator already
// provides. What this validator stops is escaping the repository at all
// (SPEC-0053 amendment 2026-08-19).
func TestTheRejectedPathsAreRejectedBeforeAnyCommandIsBuilt(t *testing.T) {
	for _, path := range []string{
		"../../etc/passwd",
		"a/../../../etc/passwd",
		"with\x00nul",
		"/absolute",
		"",
		"a//b",
		"./relative",
		"a/./b",
	} {
		if validRepositoryPath(path) {
			t.Fatalf("validRepositoryPath admitted %q, which would escape the repository", path)
		}
	}
}

// And the dash case, asserted where the defence actually is: whatever the path
// looks like, it lands after the separator, so git reads it as a path.
func TestADashLeadingPathStillLandsAfterTheSeparator(t *testing.T) {
	for _, path := range []string{"-rf", "--upload-pack=/bin/sh"} {
		for _, args := range [][]string{
			historyArgs("/srv/repo.git", "main", path, 0, 50),
			blameArgs("/srv/repo.git", "main", path),
		} {
			sep := slices.Index(args, "--")
			if sep < 0 {
				t.Fatalf("no separator for %q: %v", path, args)
			}
			if idx := slices.Index(args, path); idx < sep {
				t.Fatalf("%q sits before the separator and would be read as a flag: %v", path, args)
			}
		}
	}
}

func TestOrdinaryPathsAreStillAccepted(t *testing.T) {
	for _, path := range []string{"README.md", "internal/db/query.go", "a-b_c/d.txt"} {
		if !validRepositoryPath(path) {
			t.Fatalf("validRepositoryPath refused an ordinary path %q", path)
		}
	}
}

// SPEC-0053 AC1: the cursor is bound to everything that shapes the walk, so a
// cursor from another repository, revision or path cannot resume here.
func TestTheHistoryCursorIsBoundToEveryInputThatShapesTheWalk(t *testing.T) {
	s := &Server{}
	base := historyCursor{TenantID: "t-1", RepositoryID: "r-1", Revision: "main", Path: "a.go", Skip: 50}
	token := s.historyCursor(base)

	got, ok := s.parseHistoryCursor(token)
	if !ok || got != base {
		t.Fatalf("round trip lost the cursor: %+v ok=%v", got, ok)
	}

	// Every field must be carried, or a mismatch could not be detected upstream.
	for name, other := range map[string]historyCursor{
		"tenant":     {TenantID: "t-2", RepositoryID: "r-1", Revision: "main", Path: "a.go", Skip: 50},
		"repository": {TenantID: "t-1", RepositoryID: "r-2", Revision: "main", Path: "a.go", Skip: 50},
		"revision":   {TenantID: "t-1", RepositoryID: "r-1", Revision: "next", Path: "a.go", Skip: 50},
		"path":       {TenantID: "t-1", RepositoryID: "r-1", Revision: "main", Path: "b.go", Skip: 50},
	} {
		if s.historyCursor(other) == token {
			t.Fatalf("the cursor does not distinguish a different %s", name)
		}
	}
}

func TestAMalformedCursorIsRefusedRatherThanTreatedAsTheBeginning(t *testing.T) {
	s := &Server{}
	for _, token := range []string{"not-base64!!", "", "dg==", "djE"} {
		if _, ok := s.parseHistoryCursor(token); ok {
			t.Fatalf("accepted a malformed cursor %q", token)
		}
	}
}

func TestANegativeSkipIsRefused(t *testing.T) {
	s := &Server{}
	forged := s.historyCursor(historyCursor{TenantID: "t", RepositoryID: "r", Revision: "main", Skip: 0})
	// Rebuild with a negative skip by hand — the encoder would never emit one.
	raw := strings.Replace(decode(t, forged), "\x000", "\x00-5", 1)
	if _, ok := s.parseHistoryCursor(encode(raw)); ok {
		t.Fatal("accepted a negative skip")
	}
}

// SPEC-0053 AC8, at the type level: the shape carries git's word and nothing
// that would read as a platform principal.
func TestTheParsedCommitCarriesOnlyGitIdentity(t *testing.T) {
	record := strings.Join([]string{
		"abc123", "Ada", "ada@example.test", "Grace", "grace@example.test",
		"2026-08-19T00:00:00Z", "2026-08-19T01:00:00Z", "Add the thing",
	}, historyFieldSeparator)

	commit, err := parseCommit(record)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if commit.GetIdentity().GetGitAuthorName() != "Ada" || commit.GetIdentity().GetGitCommitterEmail() != "grace@example.test" {
		t.Fatalf("parsed %+v", commit.GetIdentity())
	}
	if commit.GetSubject() != "Add the thing" {
		t.Fatalf("subject %q", commit.GetSubject())
	}
}

func TestAMalformedHistoryRecordIsAnError(t *testing.T) {
	if _, err := parseCommit("only" + historyFieldSeparator + "two"); err == nil {
		t.Fatal("a short record must not parse into a commit with empty identity")
	}
}

func decode(t *testing.T, token string) string {
	t.Helper()
	raw, err := b64.DecodeString(token)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	return string(raw)
}

func encode(raw string) string { return b64.EncodeToString([]byte(raw)) }
