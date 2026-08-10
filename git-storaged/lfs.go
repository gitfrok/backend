package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
)

// Git LFS support (SPEC-0023). This file holds the parts that belong to storage:
// what an object is called on the tier, how a pointer file is read, and which
// objects a set of imported refs references.
//
// The transport surface (the batch API) lives on the Git front door, which is
// where every other Git protocol endpoint is terminated and authorized.

// ObjectStore is the large-object tier as storage needs it (ADR-0004,
// SPEC-0023). It is a port so a deployment without an S3 tier configured is a
// deployment that refuses LFS rather than one that pretends to store objects.
type ObjectStore interface {
	Put(ctx context.Context, key string, size int64, sha256Hex string, body io.Reader) (int64, error)
	Stat(ctx context.Context, key string) (int64, error)
}

// lfsObjectKey is where one object lives on the tier.
//
// The tenant comes first and the OID is scoped underneath it, so the same OID in
// two tenants is two objects (SPEC-0023 AC4). This is not merely a namespacing
// convenience: content addressing would otherwise make an object globally
// readable to anyone who can guess or observe its hash, and "the hash is secret"
// is not an isolation boundary.
//
// The repository is deliberately *not* in the key. An object is content, and a
// repository fork or rename must not orphan it; tenant scope is the isolation
// boundary the invariants name, and the repository is recorded in the pointer
// metadata instead.
func lfsObjectKey(tenantID, oid string) string {
	return fmt.Sprintf("lfs/%s/%s/%s", tenantID, oid[:2], oid)
}

// validOID accepts only a lowercase hex SHA-256, which is the only OID shape Git
// LFS defines. Anything else is refused rather than normalized: an OID is used to
// build a storage key, and a value that could contain a separator or a traversal
// segment must never reach one.
func validOID(oid string) bool {
	if len(oid) != 64 {
		return false
	}
	for _, r := range oid {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
		default:
			return false
		}
	}
	return true
}

// lfsPointer is a parsed LFS pointer file.
type lfsPointer struct {
	oid  string
	size int64
}

// maxPointerSize bounds what will be read as a pointer. A pointer file is a few
// hundred bytes by specification; anything larger is the file itself, and reading
// it into memory to find out is how a large-file host runs out of memory.
const maxPointerSize = 1024

// parseLFSPointer reads a pointer file. It returns ok=false for content that is
// simply not a pointer, which is the common case — most files in a repository are
// not LFS pointers, and that is not an error.
//
// The check is strict about the version line because a permissive parser here
// would misread an ordinary text file that happens to mention an oid as a
// pointer, and then report a missing object for a file that was never in LFS.
func parseLFSPointer(content []byte) (lfsPointer, bool) {
	if len(content) == 0 || len(content) > maxPointerSize {
		return lfsPointer{}, false
	}
	scanner := bufio.NewScanner(strings.NewReader(string(content)))
	var pointer lfsPointer
	first := true
	for scanner.Scan() {
		key, value, found := strings.Cut(scanner.Text(), " ")
		if !found {
			return lfsPointer{}, false
		}
		if first {
			// The specification fixes the first line.
			if key != "version" || !strings.HasPrefix(value, "https://git-lfs.github.com/spec/") {
				return lfsPointer{}, false
			}
			first = false
			continue
		}
		switch key {
		case "oid":
			hash, hex, ok := strings.Cut(value, ":")
			if !ok || hash != "sha256" || !validOID(hex) {
				return lfsPointer{}, false
			}
			pointer.oid = hex
		case "size":
			size, err := strconv.ParseInt(value, 10, 64)
			if err != nil || size < 0 {
				return lfsPointer{}, false
			}
			pointer.size = size
		}
	}
	if pointer.oid == "" {
		return lfsPointer{}, false
	}
	return pointer, true
}

// lfsPointersInRefs returns the distinct LFS pointers reachable from the given
// refs (SPEC-0023 open assumption 1: reachable-only, not every object the source
// ever held).
//
// It walks the objects git itself reports, so a pointer added on a branch that was
// not imported is not fetched — and, more importantly, a pointer *is* found
// wherever it lives in history rather than only at the tips. An object referenced
// by an old commit is still an object the repository needs to be complete.
func lfsPointersInRefs(ctx context.Context, repositoryPath string, refs []string) ([]lfsPointer, error) {
	if len(refs) == 0 {
		return nil, nil
	}
	args := append([]string{"-C", repositoryPath, "rev-list", "--objects", "--no-object-names"}, refs...)
	listed, err := exec.CommandContext(ctx, "git", args...).Output()
	if err != nil {
		return nil, fmt.Errorf("lfs: list objects: %w", err)
	}

	seen := map[string]bool{}
	var pointers []lfsPointer
	for _, line := range strings.Split(strings.TrimSpace(string(listed)), "\n") {
		object := strings.TrimSpace(line)
		if object == "" {
			continue
		}
		// Only blobs can be pointers, and only small ones. Asking git for the type
		// and size first avoids reading every blob in the repository.
		kind, size, err := objectTypeAndSize(ctx, repositoryPath, object)
		if err != nil || kind != "blob" || size > maxPointerSize {
			continue
		}
		content, err := exec.CommandContext(ctx, "git", "-C", repositoryPath, "cat-file", "blob", object).Output()
		if err != nil {
			continue
		}
		pointer, ok := parseLFSPointer(content)
		if !ok || seen[pointer.oid] {
			continue
		}
		seen[pointer.oid] = true
		pointers = append(pointers, pointer)
	}
	return pointers, nil
}

func objectTypeAndSize(ctx context.Context, repositoryPath, object string) (string, int64, error) {
	out, err := exec.CommandContext(ctx, "git", "-C", repositoryPath, "cat-file", "-s", "--allow-unknown-type", object).Output()
	if err != nil {
		return "", 0, err
	}
	size, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
	if err != nil {
		return "", 0, err
	}
	kind, err := exec.CommandContext(ctx, "git", "-C", repositoryPath, "cat-file", "-t", object).Output()
	if err != nil {
		return "", 0, err
	}
	return strings.TrimSpace(string(kind)), size, nil
}

// ErrLFSUnavailable is returned when LFS work is required and no object tier is
// configured. It is an error and never a skip: an import that quietly omitted
// LFS objects would leave a repository whose large files are missing while
// reporting success (SPEC-0023 AC7).
var ErrLFSUnavailable = errors.New("lfs: no object tier is configured")

// errSourceRateLimited reports that the source is throttling us. It travels
// separately from every other failure because the import state machine treats it
// differently: a rate limit stalls an import, which is resumable, rather than
// failing it (SPEC-0011 AC8).
var errSourceRateLimited = errors.New("lfs: the source is rate limiting this import")
