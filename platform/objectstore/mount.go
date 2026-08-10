package objectstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Mount is the large-object tier backed by a SeaweedFS FUSE mount (ADR-0050).
//
// It is the same port as the S3-backed Store and deliberately not a superset: a
// mount has no signed URLs, so transfers proxy through the plane rather than
// going client-to-tier. What that costs is ADR-0050's to argue; what this file
// owes is the two properties the decision rests on.
//
// **Writes stage and commit.** An object is written to a temporary name beside
// its destination, fsynced, and renamed onto its content-addressed name. A crash
// mid-write leaves a temporary file and no object — never a short object under a
// name claiming to describe it (SPEC-0023 AC11).
//
// **Reads verify.** Rename is not atomic on this backend — that is the measured
// finding ADR-0033 rests on, and ADR-0050 accepts it for objects only because
// this verification exists. Every read hashes what it read and compares it with
// the digest in the object's name before the caller sees a byte. A mismatch is
// reported as absence, because a torn object is not an object (SPEC-0023 AC14).
type Mount struct {
	root string
	// now is injectable so a temporary name is deterministic in a test.
	now func() time.Time
	// pid distinguishes concurrent writers of the same object on one node.
	pid int
}

// MountConfig is the per-environment mount configuration.
type MountConfig struct {
	// Root is where the SeaweedFS FUSE mount is presented, e.g. /mnt/seaweedfs.
	Root string
	Now  func() time.Time
}

// NewMount validates the mount and returns the tier.
//
// The directory must already exist and be writable. It is deliberately not
// created: a mount point that this process had to create is a mount point that
// was not mounted, and writing objects into the empty directory underneath a
// missing mount is the failure mode most likely to be discovered months later,
// on the node where nobody looked.
func NewMount(config MountConfig) (*Mount, error) {
	if config.Root == "" {
		return nil, errors.New("objectstore: the mount needs a root")
	}
	info, err := os.Stat(config.Root)
	if err != nil {
		return nil, fmt.Errorf("objectstore: mount root is unusable: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("objectstore: mount root %s is not a directory", config.Root)
	}
	probe, err := os.CreateTemp(config.Root, ".gitfrok-mount-probe-")
	if err != nil {
		return nil, fmt.Errorf("objectstore: mount root is not writable: %w", err)
	}
	name := probe.Name()
	_ = probe.Close()
	_ = os.Remove(name)

	now := config.Now
	if now == nil {
		now = time.Now
	}
	return &Mount{root: config.Root, now: now, pid: os.Getpid()}, nil
}

// Put stores one object, verifying its content against sha256Hex on the way in.
func (m *Mount) Put(ctx context.Context, key string, size int64, sha256Hex string, body io.Reader) (int64, error) {
	if key == "" || sha256Hex == "" || size < 0 {
		return 0, errors.New("objectstore: put needs a key, a size and a digest")
	}
	path, err := m.pathFor(key)
	if err != nil {
		return 0, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return 0, fmt.Errorf("objectstore: cannot create the object's directory: %w", err)
	}

	// The staging file lives in the destination directory so the commit is a
	// rename within one filesystem. A rename across filesystems degrades to
	// copy+unlink, which manufactures exactly the visibility window this staging
	// exists to avoid.
	staged, err := os.CreateTemp(filepath.Dir(path), ".staging-")
	if err != nil {
		return 0, fmt.Errorf("objectstore: cannot stage the object: %w", err)
	}
	stagedName := staged.Name()
	// Any early return leaves no debris.
	defer func() {
		_ = staged.Close()
		_ = os.Remove(stagedName)
	}()

	hasher := sha256.New()
	written, err := io.Copy(io.MultiWriter(staged, hasher), body)
	if err != nil {
		return written, fmt.Errorf("objectstore: writing %s: %w", key, err)
	}
	if got := hex.EncodeToString(hasher.Sum(nil)); got != sha256Hex {
		return written, fmt.Errorf("%w: staged %s, promised %s", ErrDigestMismatch, got, sha256Hex)
	}
	// fsync before the rename: the commit must not become visible ahead of the
	// bytes it names (ADR-0016's rule, applied to the object tier).
	if err := staged.Sync(); err != nil {
		return written, fmt.Errorf("objectstore: cannot flush %s: %w", key, err)
	}
	if err := staged.Close(); err != nil {
		return written, fmt.Errorf("objectstore: cannot close %s: %w", key, err)
	}
	if err := os.Rename(stagedName, path); err != nil {
		return written, fmt.Errorf("objectstore: cannot commit %s: %w", key, err)
	}

	// Acknowledge only what reads back, at full length (SPEC-0023 AC12). The S3
	// path learned this the hard way — a tier can accept a write it does not
	// keep — and a mount over a network filesystem is no more trustworthy about
	// it than a gateway.
	info, err := os.Stat(path)
	if err != nil {
		return written, fmt.Errorf("objectstore: %s was written but is not readable back: %w", key, err)
	}
	if info.Size() != written {
		return written, fmt.Errorf("objectstore: %s holds %d bytes, wrote %d", key, info.Size(), written)
	}
	return written, nil
}

// Stat reports an object's size, or ErrNotFound.
//
// It does not verify content: a size check is what an import needs to decide
// whether it still owes a fetch, and hashing every object on every existence
// check would make that decision cost as much as doing the work. Verification
// happens on read, which is where a torn object could actually reach a client.
func (m *Mount) Stat(_ context.Context, key string) (int64, error) {
	path, err := m.pathFor(key)
	if err != nil {
		return 0, err
	}
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, err
	}
	if info.IsDir() {
		return 0, ErrNotFound
	}
	return info.Size(), nil
}

// Get streams one object, verified.
//
// The whole object is hashed before any byte is returned, which means it is read
// twice — once to verify, once to serve. That is the price ADR-0050 §3 sets, and
// it is not negotiable at this layer: rename is not atomic on this backend, so a
// concurrent reader can observe a torn result, and an unverified read would hand
// that to a client as though it were the object.
func (m *Mount) Get(ctx context.Context, key string) (io.ReadCloser, int64, error) {
	path, err := m.pathFor(key)
	if err != nil {
		return nil, 0, err
	}
	digest, err := digestFromKey(key)
	if err != nil {
		return nil, 0, err
	}

	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, 0, ErrNotFound
	}
	if err != nil {
		return nil, 0, err
	}

	hasher := sha256.New()
	size, err := io.Copy(hasher, file)
	if err != nil {
		_ = file.Close()
		return nil, 0, fmt.Errorf("objectstore: verifying %s: %w", key, err)
	}
	if got := hex.EncodeToString(hasher.Sum(nil)); got != digest {
		_ = file.Close()
		// Absent, not corrupt-but-served. A caller that retries may find the
		// rename settled; a caller that does not gets a miss, which is a state the
		// protocol already has words for.
		return nil, 0, fmt.Errorf("%w: %s did not match its digest on read", ErrNotFound, key)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		_ = file.Close()
		return nil, 0, err
	}
	return file, size, nil
}

// Presign has no meaning on a mount. It returns an error rather than a URL,
// because a caller that silently received something unusable would fail at
// transfer time with no indication that the tier never had signed URLs to give
// (ADR-0050 §4 — transfers proxy).
func (m *Mount) Presign(string, string, time.Duration) (string, error) {
	return "", ErrPresignUnsupported
}

// ErrPresignUnsupported is returned by a tier that cannot hand out capabilities.
var ErrPresignUnsupported = errors.New("objectstore: this tier has no signed URLs; transfers proxy")

// pathFor maps a key onto the mount, refusing anything that could leave it.
//
// A key carries a tenant prefix and an OID, both from callers. Cleaning the path
// is not enough on its own — the check is that the cleaned result is still inside
// the root, which is the property that actually matters (SPEC-0023 AC13).
func (m *Mount) pathFor(key string) (string, error) {
	if key == "" || strings.HasPrefix(key, "/") {
		return "", fmt.Errorf("objectstore: %q is not an object key", key)
	}
	for segment := range strings.SplitSeq(key, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return "", fmt.Errorf("objectstore: %q is not an object key", key)
		}
	}
	path := filepath.Join(m.root, filepath.Clean(key))
	if path != m.root && !strings.HasPrefix(path, m.root+string(os.PathSeparator)) {
		return "", fmt.Errorf("objectstore: %q escapes the mount", key)
	}
	return path, nil
}

// digestFromKey reads the content digest out of the object's name. The key layout
// ends in the digest, which is what makes verification possible without a
// side-channel of expected hashes.
func digestFromKey(key string) (string, error) {
	digest := key[strings.LastIndex(key, "/")+1:]
	if len(digest) != 64 {
		return "", fmt.Errorf("objectstore: %q does not end in a content digest", key)
	}
	for _, r := range digest {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
		default:
			return "", fmt.Errorf("objectstore: %q does not end in a content digest", key)
		}
	}
	return digest, nil
}
