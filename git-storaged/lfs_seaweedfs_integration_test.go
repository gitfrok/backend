package main

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gitfrok/backend/platform/objectstore"
)

// SPEC-0011 AC2 / SPEC-0023 AC6 against a **live SeaweedFS S3 gateway**: an
// import's pointers resolve, and the objects they name are fetchable afterwards
// from the tier that actually stores them.
//
// The in-memory object tier the other LFS tests use proves the import's control
// flow. It cannot prove the claim AC2 makes, which is about a real store: that
// what the import wrote is readable back through a signature SeaweedFS accepts.
// Wiring this up is what surfaced the durability bug the object tier now guards
// against — SeaweedFS answers 200 to a PUT into a bucket that does not exist, and
// the object is not there afterwards.
//
//	podman run -d --name seaweed -p 18333:8333 \
//	  -v "$PWD/s3.json:/etc/seaweedfs/s3.json:ro" chrislusf/seaweedfs:3.97 \
//	  server -s3 -s3.config=/etc/seaweedfs/s3.json -dir=/data
//	podman exec seaweed sh -c 'echo "s3.bucket.create -name gitfrok" | weed shell'
//	GITFROK_TEST_SEAWEEDFS_ENDPOINT=http://127.0.0.1:18333 \
//	GITFROK_TEST_SEAWEEDFS_BUCKET=gitfrok \
//	GITFROK_TEST_SEAWEEDFS_ACCESS_KEY=... GITFROK_TEST_SEAWEEDFS_SECRET_KEY=... \
//	  go test ./git-storaged/
//
// Skipped without that endpoint, like the Postgres audit suite: a test that
// quietly passes without its infrastructure is evidence of nothing.
func liveObjectTier(t *testing.T) *objectstore.Store {
	t.Helper()
	endpoint := os.Getenv("GITFROK_TEST_SEAWEEDFS_ENDPOINT")
	if endpoint == "" {
		t.Skip("GITFROK_TEST_SEAWEEDFS_ENDPOINT is not set; skipping the live SeaweedFS import suite")
	}
	bucket := os.Getenv("GITFROK_TEST_SEAWEEDFS_BUCKET")
	if bucket == "" {
		bucket = "gitfrok"
	}
	store, err := objectstore.New(objectstore.Config{
		Endpoint:  endpoint,
		Region:    "us-east-1",
		Bucket:    bucket,
		AccessKey: os.Getenv("GITFROK_TEST_SEAWEEDFS_ACCESS_KEY"),
		SecretKey: os.Getenv("GITFROK_TEST_SEAWEEDFS_SECRET_KEY"),
	})
	if err != nil {
		t.Fatalf("objectstore.New: %v", err)
	}
	return store
}

// An import fetches the objects its pointers name and stores them on SeaweedFS,
// from where they are fetchable — which is the whole of AC2.
func TestLiveImportStoresLFSObjectsOnSeaweedFS(t *testing.T) {
	store := liveObjectTier(t)
	// A payload unique to this run, so a re-run is not passing on last run's bytes.
	payload := "a large object imported at " + time.Now().UTC().Format(time.RFC3339Nano)

	work := t.TempDir()
	mustRunGit(t, work, "init", "--initial-branch=main", work)
	mustRunGit(t, work, "config", "user.email", "dev@gitsaas.test")
	mustRunGit(t, work, "config", "user.name", "GitFrok test")
	writeFile(t, work, "big.bin", pointerFor(payload))
	mustRunGit(t, work, "add", "big.bin")
	mustRunGit(t, work, "commit", "-m", "add pointer")

	source := newSourceLFSServer(t, map[string]string{oidOf(payload): payload})
	server := &Server{objects: store, sourceLFS: source.client()}

	tenantID := "tenant-live-" + time.Now().UTC().Format("20060102150405")
	stored, err := server.importLFSObjects(t.Context(),
		repositoryOperation{path: work, tenantID: tenantID, repositoryID: "repo-a"},
		[]string{"refs/heads/main"},
		source.server.URL+"/acme/widgets.git", "source-token")
	if err != nil {
		t.Fatalf("importLFSObjects against SeaweedFS: %v", err)
	}
	if stored != int64(len(payload)) {
		t.Fatalf("stored %d bytes, want %d", stored, len(payload))
	}

	// Fetchable afterwards — the actual acceptance criterion, read back through the
	// gateway rather than from the importer's own bookkeeping.
	key := lfsObjectKey(tenantID, oidOf(payload))
	body, size, err := store.Get(t.Context(), key)
	if err != nil {
		t.Fatalf("the imported object is not fetchable: %v", err)
	}
	defer func() { _ = body.Close() }()
	content, _ := io.ReadAll(body)
	if string(content) != payload {
		t.Fatalf("object content = %q, want the source's payload", content)
	}
	if size != int64(len(payload)) {
		t.Fatalf("object size = %d, want %d", size, len(payload))
	}
}

// A client with nothing but a presigned URL — which is all a git-lfs client has
// after a batch response — can fetch an imported object from SeaweedFS
// (SPEC-0023 decision 1, end to end).
func TestLiveImportedObjectIsFetchableWithAPresignedURL(t *testing.T) {
	store := liveObjectTier(t)
	payload := "an imported object fetched by URL alone at " + time.Now().UTC().Format(time.RFC3339Nano)

	work := t.TempDir()
	mustRunGit(t, work, "init", "--initial-branch=main", work)
	mustRunGit(t, work, "config", "user.email", "dev@gitsaas.test")
	mustRunGit(t, work, "config", "user.name", "GitFrok test")
	writeFile(t, work, filepath.Base("big.bin"), pointerFor(payload))
	mustRunGit(t, work, "add", "big.bin")
	mustRunGit(t, work, "commit", "-m", "add pointer")

	source := newSourceLFSServer(t, map[string]string{oidOf(payload): payload})
	server := &Server{objects: store, sourceLFS: source.client()}
	tenantID := "tenant-presign-" + time.Now().UTC().Format("20060102150405")

	if _, err := server.importLFSObjects(t.Context(),
		repositoryOperation{path: work, tenantID: tenantID, repositoryID: "repo-a"},
		[]string{"refs/heads/main"},
		source.server.URL+"/acme/widgets.git", ""); err != nil {
		t.Fatalf("importLFSObjects: %v", err)
	}

	href, err := store.Presign(http.MethodGet, lfsObjectKey(tenantID, oidOf(payload)), 5*time.Minute)
	if err != nil {
		t.Fatalf("Presign: %v", err)
	}
	response, err := (&http.Client{Timeout: 30 * time.Second}).Get(href)
	if err != nil {
		t.Fatalf("presigned fetch: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("SeaweedFS rejected the presigned fetch: status %d", response.StatusCode)
	}
	content, _ := io.ReadAll(response.Body)
	if string(content) != payload {
		t.Fatalf("presigned fetch returned %q, want the imported payload", content)
	}
}

// Two tenants importing the same object hold two objects, verified on the tier
// itself rather than on a key-building function (SPEC-0023 AC4).
func TestLiveSameOIDInTwoTenantsIsTwoObjects(t *testing.T) {
	store := liveObjectTier(t)
	payload := "shared content imported by two tenants at " + time.Now().UTC().Format(time.RFC3339Nano)
	stamp := time.Now().UTC().Format("20060102150405")

	work := t.TempDir()
	mustRunGit(t, work, "init", "--initial-branch=main", work)
	mustRunGit(t, work, "config", "user.email", "dev@gitsaas.test")
	mustRunGit(t, work, "config", "user.name", "GitFrok test")
	writeFile(t, work, "big.bin", pointerFor(payload))
	mustRunGit(t, work, "add", "big.bin")
	mustRunGit(t, work, "commit", "-m", "add pointer")

	source := newSourceLFSServer(t, map[string]string{oidOf(payload): payload})
	server := &Server{objects: store, sourceLFS: source.client()}

	first := "tenant-a-" + stamp
	if _, err := server.importLFSObjects(t.Context(),
		repositoryOperation{path: work, tenantID: first, repositoryID: "repo-a"},
		[]string{"refs/heads/main"}, source.server.URL+"/acme/widgets.git", ""); err != nil {
		t.Fatalf("first tenant: %v", err)
	}

	// The second tenant's object is absent until it imports for itself: one tenant
	// storing an OID must not make it readable in another.
	second := "tenant-b-" + stamp
	if _, err := store.Stat(t.Context(), lfsObjectKey(second, oidOf(payload))); err == nil {
		t.Fatal("tenant B could read an object only tenant A imported")
	}

	if _, err := server.importLFSObjects(t.Context(),
		repositoryOperation{path: work, tenantID: second, repositoryID: "repo-b"},
		[]string{"refs/heads/main"}, source.server.URL+"/acme/widgets.git", ""); err != nil {
		t.Fatalf("second tenant: %v", err)
	}
	for _, tenant := range []string{first, second} {
		if _, err := store.Stat(t.Context(), lfsObjectKey(tenant, oidOf(payload))); err != nil {
			t.Fatalf("%s does not hold its own copy: %v", tenant, err)
		}
	}
}

// A resumed import against the live tier does not re-fetch what is already
// stored: the check is a real HEAD against SeaweedFS, not a map lookup.
func TestLiveResumedImportSkipsWhatSeaweedFSAlreadyHolds(t *testing.T) {
	store := liveObjectTier(t)
	payload := "resumable object at " + time.Now().UTC().Format(time.RFC3339Nano)

	work := t.TempDir()
	mustRunGit(t, work, "init", "--initial-branch=main", work)
	mustRunGit(t, work, "config", "user.email", "dev@gitsaas.test")
	mustRunGit(t, work, "config", "user.name", "GitFrok test")
	writeFile(t, work, "big.bin", pointerFor(payload))
	mustRunGit(t, work, "add", "big.bin")
	mustRunGit(t, work, "commit", "-m", "add pointer")

	source := newSourceLFSServer(t, map[string]string{oidOf(payload): payload})
	server := &Server{objects: store, sourceLFS: source.client()}
	tenantID := "tenant-resume-" + time.Now().UTC().Format("20060102150405")
	operation := repositoryOperation{path: work, tenantID: tenantID, repositoryID: "repo-a"}

	if _, err := server.importLFSObjects(t.Context(), operation,
		[]string{"refs/heads/main"}, source.server.URL+"/acme/widgets.git", ""); err != nil {
		t.Fatalf("first import: %v", err)
	}
	callsAfterFirst := source.batchCalls

	stored, err := server.importLFSObjects(t.Context(), operation,
		[]string{"refs/heads/main"}, source.server.URL+"/acme/widgets.git", "")
	if err != nil {
		t.Fatalf("resumed import: %v", err)
	}
	if stored != 0 {
		t.Fatalf("resumed import stored %d bytes, want none re-fetched", stored)
	}
	if source.batchCalls != callsAfterFirst {
		t.Fatalf("the source was asked again (%d calls, was %d) for an object SeaweedFS already holds",
			source.batchCalls, callsAfterFirst)
	}
}
