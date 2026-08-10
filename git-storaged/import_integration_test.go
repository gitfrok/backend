package main

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// SPEC-0011 AC1 end to end, against a real source repository on this filesystem:
// every ref and tag is imported, and a clone of the imported repository yields
// commit SHAs byte-identical to the source's.
//
// The source is a local git remote, and the test drives the import's fetch step
// directly rather than through the ImportRefs RPC. That is not a shortcut around
// the surface: validSourceURL deliberately refuses a local path and file:// (a
// source must come over the network, SPEC-0011 AC22), so a local fixture cannot
// travel through the RPC by design. What AC1 claims is about git object identity,
// and the fetch plus the ref scan below are the steps that could break it — the
// same functions the RPC calls, on the same live bare repository.
//
// Two things this deliberately does not prove: the durability acknowledgement
// (AC3, covered by the receive-pack quorum tests the RPC shares) and that it all
// holds on a block volume with a real replica, which is the cluster lane's. That
// the SHAs survive an import at all is provable here, and until now was proved
// nowhere.
func TestImportRefsPreservesSourceObjectIdentity(t *testing.T) {
	root := t.TempDir()
	tenantID, repositoryID := "tenant-a", "repo-a"
	bare := filepath.Join(root, tenantID, repositoryID+".git")
	mustRunGit(t, root, "init", "--bare", bare)

	// The source: two branches, an annotated tag and a lightweight tag, so the
	// import is asserted over more than one ref kind.
	source := filepath.Join(t.TempDir(), "source")
	mustRunGit(t, filepath.Dir(source), "init", source)
	mustRunGit(t, source, "config", "user.email", "dev@gitsaas.test")
	mustRunGit(t, source, "config", "user.name", "GitFrok test")
	mustRunGit(t, source, "config", "tag.gpgSign", "false")

	writeFile(t, source, "README.md", "history\n")
	mustRunGit(t, source, "add", "README.md")
	mustRunGit(t, source, "commit", "-m", "initial")
	mustRunGit(t, source, "branch", "-M", "main")
	first := mustGitOutput(t, source, "rev-parse", "HEAD")

	mustRunGit(t, source, "tag", "v1.0.0")
	writeFile(t, source, "feature.txt", "a feature\n")
	mustRunGit(t, source, "add", "feature.txt")
	mustRunGit(t, source, "commit", "-m", "second")
	second := mustGitOutput(t, source, "rev-parse", "HEAD")
	mustRunGit(t, source, "tag", "-a", "v2.0.0", "-m", "release two")

	mustRunGit(t, source, "checkout", "-b", "topic")
	writeFile(t, source, "topic.txt", "on a branch\n")
	mustRunGit(t, source, "add", "topic.txt")
	mustRunGit(t, source, "commit", "-m", "topic work")
	topic := mustGitOutput(t, source, "rev-parse", "HEAD")
	mustRunGit(t, source, "checkout", "main")

	// The import's git phase, as ImportRefs runs it: measure, fetch, rescan refs.
	ctx := t.Context()
	before, err := refs(ctx, bare)
	if err != nil {
		t.Fatalf("refs before: %v", err)
	}
	bytesBefore := repositoryBytes(ctx, bare)
	if err := fetchFromSource(ctx, bare, source, ""); err != nil {
		t.Fatalf("fetchFromSource: %v", err)
	}
	after, err := refs(ctx, bare)
	if err != nil {
		t.Fatalf("refs after: %v", err)
	}

	// Every ref and tag arrived, and each one names the source's own object.
	imported := map[string]string{}
	for _, delta := range refDeltas(before, after) {
		imported[delta.ref] = delta.newSHA
	}
	for ref, want := range map[string]string{
		"refs/heads/main":  second,
		"refs/heads/topic": topic,
		"refs/tags/v1.0.0": first,
	} {
		if got := imported[ref]; got != want {
			t.Errorf("imported %s = %q, want the source's %q", ref, got, want)
		}
	}
	// The annotated tag's ref names its tag object, not the commit — so assert it
	// exists and that it dereferences to the source's commit below.
	if imported["refs/tags/v2.0.0"] == "" {
		t.Error("the annotated tag was not imported")
	}

	// The bytes the storage tier wrote (AC9) — for a source carrying objects, more
	// than nothing.
	if grown := repositoryBytes(ctx, bare) - bytesBefore; grown <= 0 {
		t.Errorf("imported bytes = %d, want the growth this fetch caused", grown)
	}

	// AC1's actual claim: clone what was imported and compare object identity. A
	// mirror clone, because a plain clone creates a local branch only for HEAD and
	// leaves the rest as remote-tracking refs — that would test git's clone
	// defaults rather than what the import stored.
	clone := filepath.Join(t.TempDir(), "clone.git")
	mustRunGit(t, filepath.Dir(clone), "clone", "--mirror", bare, clone)

	for _, check := range []struct {
		revision, want, what string
	}{
		{"refs/heads/main", second, "main"},
		{"refs/heads/topic", topic, "topic"},
		{"refs/tags/v1.0.0", first, "the lightweight tag"},
		{"refs/tags/v2.0.0^{commit}", second, "the annotated tag's commit"},
	} {
		// The clone is fetched from the imported repository, so this is the SHA a
		// migrating customer's own clone would see.
		if got := mustGitOutput(t, clone, "rev-parse", check.revision); got != check.want {
			t.Errorf("clone %s = %q, want the source's %q", check.what, got, check.want)
		}
	}

	// And the trees, not only the tips: a commit whose content differed would
	// have a different SHA, but comparing the full ref list catches a ref that
	// was silently dropped or renamed on the way in.
	if got, want := refList(t, clone), refList(t, source); !equalRefs(got, want) {
		t.Errorf("clone refs = %v, want the source's %v", got, want)
	}
}

// writeFile writes one file into a working tree.
func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

// refList returns the repository's heads and tags with the object each names,
// excluding remote-tracking refs (a clone has them, a source does not, and they
// are not part of what an import must preserve).
func refList(t *testing.T, dir string) []string {
	t.Helper()
	out := mustGitOutput(t, dir, "for-each-ref", "--format=%(refname) %(objectname)",
		"refs/heads", "refs/tags")
	var refs []string
	for line := range strings.SplitSeq(strings.TrimSpace(out), "\n") {
		if line != "" {
			refs = append(refs, line)
		}
	}
	sort.Strings(refs)
	return refs
}

func equalRefs(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// An import never overwrites a branch this platform already holds. A source whose
// branch has diverged from ours fails the fetch — and the import fails with it —
// rather than rewriting first-party history from a foreign source (SPEC-0011
// AC1/AC7, the reason the refspec is not forced).
func TestImportRefusesToOverwriteADivergedBranch(t *testing.T) {
	root := t.TempDir()
	bare := filepath.Join(root, "tenant-a", "repo-a.git")
	mustRunGit(t, root, "init", "--bare", bare)

	// What this platform already holds on refs/heads/main.
	ours := filepath.Join(t.TempDir(), "ours")
	mustRunGit(t, filepath.Dir(ours), "init", ours)
	mustRunGit(t, ours, "config", "user.email", "dev@gitsaas.test")
	mustRunGit(t, ours, "config", "user.name", "GitFrok test")
	writeFile(t, ours, "ours.txt", "written here\n")
	mustRunGit(t, ours, "add", "ours.txt")
	mustRunGit(t, ours, "commit", "-m", "ours")
	mustRunGit(t, ours, "branch", "-M", "main")
	mustRunGit(t, ours, "push", bare, "refs/heads/main:refs/heads/main")
	held := mustGitOutput(t, ours, "rev-parse", "HEAD")

	// A source with an unrelated history on the same branch name.
	source := filepath.Join(t.TempDir(), "source")
	mustRunGit(t, filepath.Dir(source), "init", source)
	mustRunGit(t, source, "config", "user.email", "dev@gitsaas.test")
	mustRunGit(t, source, "config", "user.name", "GitFrok test")
	writeFile(t, source, "theirs.txt", "written elsewhere\n")
	mustRunGit(t, source, "add", "theirs.txt")
	mustRunGit(t, source, "commit", "-m", "theirs")
	mustRunGit(t, source, "branch", "-M", "main")

	if err := fetchFromSource(t.Context(), bare, source, ""); err == nil {
		t.Fatal("the fetch overwrote a branch this platform already held")
	}
	if got := mustGitOutput(t, bare, "rev-parse", "refs/heads/main"); got != held {
		t.Fatalf("refs/heads/main = %q, want the %q we already held", got, held)
	}
}
