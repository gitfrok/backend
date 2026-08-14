package objectstore_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gitfrok/backend/platform/objectstore"
)

func mountFor(t *testing.T) (*objectstore.Mount, string) {
	t.Helper()
	root := t.TempDir()
	mount, err := objectstore.NewMount(objectstore.MountConfig{Root: root})
	if err != nil {
		t.Fatalf("NewMount: %v", err)
	}
	return mount, root
}

func keyFor(tenant string, content []byte) (string, string) {
	sum := sha256.Sum256(content)
	digest := hex.EncodeToString(sum[:])
	return "lfs/" + tenant + "/" + digest[:2] + "/" + digest, digest
}

// The ordinary path: an object written to the mount reads back byte-identical.
func TestMountRoundTrip(t *testing.T) {
	mount, _ := mountFor(t)
	payload := []byte("an object on the mount")
	key, digest := keyFor("tenant-a", payload)

	written, err := mount.Put(t.Context(), key, int64(len(payload)), digest, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if written != int64(len(payload)) {
		t.Fatalf("wrote %d, want %d", written, len(payload))
	}

	size, err := mount.Stat(t.Context(), key)
	if err != nil || size != int64(len(payload)) {
		t.Fatalf("Stat = %d, %v", size, err)
	}

	body, size, err := mount.Get(t.Context(), key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer func() { _ = body.Close() }()
	got, _ := io.ReadAll(body)
	if !bytes.Equal(got, payload) || size != int64(len(payload)) {
		t.Fatalf("got %q (%d bytes), want %q", got, size, payload)
	}
}

// SPEC-0023 AC11: a write is staged and committed by rename, so a failed write
// leaves no object — never a short one under a name that claims to describe it.
func TestMountFailedWriteLeavesNoObject(t *testing.T) {
	mount, root := mountFor(t)
	payload := []byte("this write will not finish")
	key, digest := keyFor("tenant-a", payload)

	// A reader that fails halfway is the crash this simulates.
	failing := io.MultiReader(bytes.NewReader(payload[:5]), errorReader{})
	if _, err := mount.Put(t.Context(), key, int64(len(payload)), digest, failing); err == nil {
		t.Fatal("a truncated write reported success")
	}
	if _, err := mount.Stat(t.Context(), key); !errors.Is(err, objectstore.ErrNotFound) {
		t.Fatalf("Stat after a failed write = %v, want ErrNotFound", err)
	}
	// And no staging debris is left behind.
	if leftovers := stagingFiles(t, root); len(leftovers) != 0 {
		t.Fatalf("staging files left behind: %v", leftovers)
	}
}

// Content that does not hash to its promised digest never becomes an object
// (SPEC-0023 AC5 on the mount).
func TestMountRejectsContentThatDoesNotMatchItsDigest(t *testing.T) {
	mount, root := mountFor(t)
	_, digest := keyFor("tenant-a", []byte("what was promised"))
	key := "lfs/tenant-a/" + digest[:2] + "/" + digest

	_, err := mount.Put(t.Context(), key, 4, digest, strings.NewReader("what was actually sent"))
	if !errors.Is(err, objectstore.ErrDigestMismatch) {
		t.Fatalf("Put = %v, want ErrDigestMismatch", err)
	}
	if _, err := mount.Stat(t.Context(), key); !errors.Is(err, objectstore.ErrNotFound) {
		t.Fatal("a digest mismatch still produced an object")
	}
	if leftovers := stagingFiles(t, root); len(leftovers) != 0 {
		t.Fatalf("staging files left behind: %v", leftovers)
	}
}

// SPEC-0023 AC14, the criterion ADR-0050 rests on: an object whose content no
// longer matches the digest in its name is not served. This is what turns a torn
// rename — which this backend can produce, because rename is not atomic — into a
// detected absence instead of corruption handed to a client.
func TestMountRefusesToServeAnObjectThatFailsVerification(t *testing.T) {
	mount, root := mountFor(t)
	payload := []byte("the object as written")
	key, digest := keyFor("tenant-a", payload)
	if _, err := mount.Put(t.Context(), key, int64(len(payload)), digest, bytes.NewReader(payload)); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Truncate it the way a torn rename would leave it: the name resolves, the
	// content behind it does not match.
	if err := os.WriteFile(filepath.Join(root, key), payload[:5], 0o600); err != nil {
		t.Fatalf("simulate a torn object: %v", err)
	}

	if _, _, err := mount.Get(t.Context(), key); !errors.Is(err, objectstore.ErrNotFound) {
		t.Fatalf("Get on a torn object = %v, want it treated as absent", err)
	}
	// And it is not repaired in place or deleted behind the caller's back: the
	// bytes are still there for an operator to look at.
	if _, err := os.Stat(filepath.Join(root, key)); err != nil {
		t.Fatalf("the failed object was removed from under the operator: %v", err)
	}
}

// SPEC-0023 AC12: an object is acknowledged only once it reads back at full
// length.
func TestMountAcknowledgesOnlyWhatReadsBack(t *testing.T) {
	mount, root := mountFor(t)
	payload := []byte("acknowledged only when present")
	key, digest := keyFor("tenant-a", payload)
	if _, err := mount.Put(t.Context(), key, int64(len(payload)), digest, bytes.NewReader(payload)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	info, err := os.Stat(filepath.Join(root, key))
	if err != nil {
		t.Fatalf("the acknowledged object is not on the mount: %v", err)
	}
	if info.Size() != int64(len(payload)) {
		t.Fatalf("stored %d bytes, acknowledged %d", info.Size(), len(payload))
	}
}

// SPEC-0023 AC13: the same OID under two tenants is two files, and nothing in a
// key can escape the mount.
func TestMountKeysAreTenantScopedAndCannotEscape(t *testing.T) {
	mount, root := mountFor(t)
	payload := []byte("shared content")
	keyA, digest := keyFor("tenant-a", payload)
	keyB, _ := keyFor("tenant-b", payload)

	if _, err := mount.Put(t.Context(), keyA, int64(len(payload)), digest, bytes.NewReader(payload)); err != nil {
		t.Fatalf("Put A: %v", err)
	}
	if _, err := mount.Stat(t.Context(), keyB); !errors.Is(err, objectstore.ErrNotFound) {
		t.Fatal("tenant B saw an object only tenant A stored")
	}
	if _, err := mount.Put(t.Context(), keyB, int64(len(payload)), digest, bytes.NewReader(payload)); err != nil {
		t.Fatalf("Put B: %v", err)
	}
	for _, key := range []string{keyA, keyB} {
		if _, err := os.Stat(filepath.Join(root, key)); err != nil {
			t.Fatalf("%s is not its own file: %v", key, err)
		}
	}

	outside := filepath.Join(filepath.Dir(root), "escaped")
	for _, key := range []string{
		"../escaped", "lfs/../../escaped", "/etc/passwd", "", "lfs//double", "lfs/./here",
	} {
		if _, err := mount.Put(t.Context(), key, 1, digest, strings.NewReader("x")); err == nil {
			t.Errorf("Put accepted the key %q", key)
		}
		if _, err := mount.Stat(t.Context(), key); err == nil {
			t.Errorf("Stat accepted the key %q", key)
		}
	}
	if _, err := os.Stat(outside); err == nil {
		t.Fatal("a key wrote outside the mount")
	}
}

// A key that does not end in a content digest cannot be verified, so it cannot be
// read: verification is not optional on this tier.
func TestMountRefusesAKeyWithNoDigest(t *testing.T) {
	mount, root := mountFor(t)
	if err := os.MkdirAll(filepath.Join(root, "lfs/tenant-a"), 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "lfs/tenant-a/not-a-digest"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, _, err := mount.Get(t.Context(), "lfs/tenant-a/not-a-digest"); err == nil {
		t.Fatal("an unverifiable object was served")
	}
}

// A mount has no signed URLs, and says so rather than returning something a
// client would discover was unusable at transfer time (ADR-0050 §4).
func TestMountHasNoPresignedURLs(t *testing.T) {
	mount, _ := mountFor(t)
	if _, err := mount.Presign("GET", "lfs/tenant-a/aa/"+strings.Repeat("a", 64), time.Minute); !errors.Is(err, objectstore.ErrPresignUnsupported) {
		t.Fatalf("Presign = %v, want ErrPresignUnsupported", err)
	}
}

// A mount root that does not exist is a configuration failure, not something to
// create: a mount point this process had to create is a mount point that was not
// mounted, and objects written under it are invisible to every other node.
func TestMountRootMustExist(t *testing.T) {
	if _, err := objectstore.NewMount(objectstore.MountConfig{Root: filepath.Join(t.TempDir(), "absent")}); err == nil {
		t.Fatal("a missing mount root was accepted")
	}
	if _, err := objectstore.NewMount(objectstore.MountConfig{}); err == nil {
		t.Fatal("an empty mount root was accepted")
	}
	file := filepath.Join(t.TempDir(), "a-file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := objectstore.NewMount(objectstore.MountConfig{Root: file}); err == nil {
		t.Fatal("a file was accepted as a mount root")
	}
}

// The mount satisfies the same port the S3 tier does, so a caller cannot tell
// them apart at the type level — which is what makes ADR-0050's "the port does
// not change shape" true rather than aspirational.
func TestMountSatisfiesTheSamePort(t *testing.T) {
	type objectTier interface {
		Put(ctx context.Context, key string, size int64, sha256Hex string, body io.Reader) (int64, error)
		Stat(ctx context.Context, key string) (int64, error)
		Get(ctx context.Context, key string) (io.ReadCloser, int64, error)
	}
	mount, _ := mountFor(t)
	var _ objectTier = mount
	var _ objectTier = (*objectstore.Store)(nil)
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("the writer went away") }

// stagingFiles lists any staging debris left under the mount.
func stagingFiles(t *testing.T, root string) []string {
	t.Helper()
	var found []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasPrefix(filepath.Base(path), ".staging-") {
			found = append(found, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	return found
}

// putObject stores content under a digest-terminated key and returns the key.
func putObject(t *testing.T, mount *objectstore.Mount, key string, payload []byte) string {
	t.Helper()
	sum := sha256.Sum256(payload)
	digest := hex.EncodeToString(sum[:])
	full := key + "/" + digest
	if _, err := mount.Put(t.Context(), full, int64(len(payload)), digest, bytes.NewReader(payload)); err != nil {
		t.Fatalf("Put %s: %v", full, err)
	}
	return full
}

// List names what a prefix holds, sorted — and never a staging file, because a
// listing that surfaced an uncommitted write would make the retention sweep
// delete something no reader can see committed (SPEC-0037 AC1, AC9).
func TestMountListIsPrefixedSortedAndSkipsStaging(t *testing.T) {
	mount, root := mountFor(t)
	keyA := putObject(t, mount, "ci-scan-reports/tenant-a/job/attempt/class-a", []byte("report one"))
	keyB := putObject(t, mount, "ci-scan-reports/tenant-a/job/attempt/class-b", []byte("report two"))
	keyC := putObject(t, mount, "ci-scan-reports/tenant-b/job/attempt/class-a", []byte("elsewhere"))

	// Staging debris from a crashed writer must not be listed.
	if err := os.WriteFile(filepath.Join(root, "ci-scan-reports/tenant-a/job/attempt/class-a/.staging-junk"), []byte("x"), 0o600); err != nil {
		t.Fatalf("seed staging file: %v", err)
	}

	got, err := mount.List(t.Context(), "ci-scan-reports/tenant-a/")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	want := []string{keyA, keyB}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("List = %v, want %v", got, want)
	}

	// A broader prefix sees both tenants but still no staging files.
	got, err = mount.List(t.Context(), "ci-scan-reports/")
	if err != nil {
		t.Fatalf("List broad: %v", err)
	}
	all := []string{keyA, keyB, keyC}
	slices.Sort(all)
	if !slices.Equal(got, all) {
		t.Fatalf("List broad = %v, want %v", got, all)
	}

	// A prefix naming nothing yields an empty listing, not an error.
	got, err = mount.List(t.Context(), "ci-scan-reports/tenant-c/")
	if err != nil || len(got) != 0 {
		t.Fatalf("List of an empty prefix = %v, %v", got, err)
	}
}

// The mount will not list the whole tier, nor anything that could leave it.
func TestMountListRefusesBroadOrEscapingPrefixes(t *testing.T) {
	mount, _ := mountFor(t)
	for _, prefix := range []string{"", "../", "reports/../", "/etc/"} {
		if _, err := mount.List(t.Context(), prefix); err == nil {
			t.Errorf("List accepted the prefix %q", prefix)
		}
	}
}

// Delete removes one object and is idempotent: the retention sweep must not
// fail because a concurrent sweep already took a report (SPEC-0037 AC9).
func TestMountDeleteRemovesAndIsIdempotent(t *testing.T) {
	mount, _ := mountFor(t)
	key := putObject(t, mount, "ci-scan-reports/tenant-a/job/attempt/class-a", []byte("doomed"))

	if err := mount.Delete(t.Context(), key); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := mount.Stat(t.Context(), key); !errors.Is(err, objectstore.ErrNotFound) {
		t.Fatalf("Stat after Delete = %v, want ErrNotFound", err)
	}
	if err := mount.Delete(t.Context(), key); err != nil {
		t.Fatalf("deleting an absent object must succeed: %v", err)
	}
	for _, key := range []string{"", "../escaped", "/etc/passwd", "reports//gap"} {
		if err := mount.Delete(t.Context(), key); err == nil {
			t.Errorf("Delete accepted the key %q", key)
		}
	}
}
