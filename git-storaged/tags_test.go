package main

import (
	"slices"
	"testing"

	repositoryv1 "github.com/gitfrok/backend/gen/proto/repository/v1"
)

// SPEC-0056 AC1. The property worth a test here is the annotated-tag
// dereference: without it a release would record a tag object's SHA as though
// it were a commit, and every later comparison against it would be false.

func TestAnAnnotatedTagReportsTheCommitItPointsAt(t *testing.T) {
	// for-each-ref gives objectname = the tag object, *objectname = the commit.
	tag := parseTag("v1.0.0\x1ftagobject111\x1fcommit222")
	if tag == nil {
		t.Fatal("did not parse")
	}
	if tag.GetCommitId() != "commit222" {
		t.Fatalf("recorded %q — an annotated tag's own SHA is not a commit", tag.GetCommitId())
	}
}

func TestALightweightTagReportsItsObjectname(t *testing.T) {
	// A lightweight tag has no tag object, so *objectname is empty.
	tag := parseTag("v0.9.0\x1fcommit333\x1f")
	if tag == nil || tag.GetCommitId() != "commit333" {
		t.Fatalf("parsed %+v", tag)
	}
}

func TestAMalformedRecordIsSkippedRatherThanGuessed(t *testing.T) {
	for _, record := range []string{"", "only-one-field", "name\x1f\x1f", "\x1fa\x1fb"} {
		if tag := parseTag(record); tag != nil {
			t.Fatalf("record %q became %+v", record, tag)
		}
	}
}

func TestTagArgsAskForTheDereferencedTargetAndNewestFirst(t *testing.T) {
	args := tagArgs("/srv/repo.git")
	joined := ""
	for _, a := range args {
		joined += a + " "
	}
	if !slices.Contains(args, "refs/tags") {
		t.Fatalf("does not scope to refs/tags: %v", args)
	}
	if !slices.Contains(args, "--sort=-creatordate") {
		t.Fatalf("does not sort newest first: %v", args)
	}
	// The dereference is the whole point.
	found := false
	for _, a := range args {
		if len(a) > 9 && a[:9] == "--format=" && slices.Contains([]string{a}, a) {
			if containsAll(a, "%(refname:short)", "%(objectname)", "%(*objectname)") {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("the format does not ask for the dereferenced target: %v", args)
	}
}

func TestTheTagCursorIsBoundToTenantAndRepository(t *testing.T) {
	s := &Server{}
	base := tagCursor{TenantID: "t-1", RepositoryID: "r-1", Offset: 100}
	got, ok := s.parseTagCursor(s.tagCursor(base))
	if !ok || got != base {
		t.Fatalf("round trip lost the cursor: %+v ok=%v", got, ok)
	}
	if s.tagCursor(tagCursor{TenantID: "t-2", RepositoryID: "r-1", Offset: 100}) == s.tagCursor(base) {
		t.Fatal("the cursor does not distinguish a different tenant")
	}
	for _, bad := range []string{"nope!!", "", "djE"} {
		if _, ok := s.parseTagCursor(bad); ok {
			t.Fatalf("accepted a malformed cursor %q", bad)
		}
	}
}

func containsAll(haystack string, needles ...string) bool {
	for _, n := range needles {
		found := false
		for i := 0; i+len(n) <= len(haystack); i++ {
			if haystack[i:i+len(n)] == n {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

var _ = repositoryv1.Tag{}
