package objectstore_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gitfrok/backend/platform/objectstore"
)

// SPEC-0023 against a real SeaweedFS S3 gateway, not a fake.
//
// The unit tests in this package prove the signing and the refusals against an
// httptest server that accepts whatever it is sent. That is worth having and it
// is not the same claim: a signature this platform believes is correct is only
// correct if SeaweedFS accepts it, and every field of SigV4 — canonical path
// escaping, the signed-header list, the payload hash, the credential scope — is a
// place where a plausible implementation is silently wrong until a real server
// rejects it.
//
//	podman run -d --name seaweed -p 18333:8333 \
//	  -v "$PWD/s3.json:/etc/seaweedfs/s3.json:ro" chrislusf/seaweedfs:3.97 \
//	  server -s3 -s3.config=/etc/seaweedfs/s3.json -dir=/data
//	GITFROK_TEST_SEAWEEDFS_ENDPOINT=http://127.0.0.1:18333 \
//	GITFROK_TEST_SEAWEEDFS_BUCKET=gitfrok-test \
//	GITFROK_TEST_SEAWEEDFS_ACCESS_KEY=... GITFROK_TEST_SEAWEEDFS_SECRET_KEY=... \
//	  go test ./platform/objectstore/
//
// Skipped when the endpoint is not configured — like the Postgres audit suite,
// this needs infrastructure CI does not have yet, and a test that quietly passed
// without it would be evidence of nothing.
func liveStore(t *testing.T) (*objectstore.Store, string) {
	t.Helper()
	endpoint := os.Getenv("GITFROK_TEST_SEAWEEDFS_ENDPOINT")
	if endpoint == "" {
		t.Skip("GITFROK_TEST_SEAWEEDFS_ENDPOINT is not set; skipping the live SeaweedFS suite")
	}
	bucket := os.Getenv("GITFROK_TEST_SEAWEEDFS_BUCKET")
	if bucket == "" {
		bucket = "gitfrok-test"
	}
	store, err := objectstore.New(objectstore.Config{
		Endpoint:  endpoint,
		Region:    "us-east-1",
		Bucket:    bucket,
		AccessKey: os.Getenv("GITFROK_TEST_SEAWEEDFS_ACCESS_KEY"),
		SecretKey: os.Getenv("GITFROK_TEST_SEAWEEDFS_SECRET_KEY"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return store, bucket
}

func digestOf(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

// A real round trip: SeaweedFS accepts our signature, stores the object, and
// returns the same bytes.
func TestLiveSeaweedFSRoundTrip(t *testing.T) {
	store, _ := liveStore(t)
	ctx := context.Background()

	payload := []byte("a large object that really travelled over the wire")
	digest := digestOf(payload)
	key := "lfs/tenant-a/" + digest[:2] + "/" + digest

	written, err := store.Put(ctx, key, int64(len(payload)), digest, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("Put against SeaweedFS: %v", err)
	}
	if written != int64(len(payload)) {
		t.Fatalf("wrote %d bytes, want %d", written, len(payload))
	}

	size, err := store.Stat(ctx, key)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if size != int64(len(payload)) {
		t.Fatalf("stat size = %d, want %d", size, len(payload))
	}

	body, _, err := store.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer func() { _ = body.Close() }()
	got, err := io.ReadAll(body)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("got %q, want %q", got, payload)
	}
	if digestOf(got) != digest {
		t.Fatal("the object came back with a different digest than it went in with")
	}
}

// An object SeaweedFS does not hold is ErrNotFound, which is what an import
// depends on to decide whether it still owes a fetch.
func TestLiveSeaweedFSAbsentObject(t *testing.T) {
	store, _ := liveStore(t)
	_, err := store.Stat(context.Background(), "lfs/tenant-a/zz/"+digestOf([]byte("never stored")))
	if err == nil {
		t.Fatal("an object that was never stored reported present")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Fatalf("Stat = %v, want a not-found error", err)
	}
}

// The load-bearing one for SPEC-0023 decision 1: a presigned URL this platform
// generates is honoured by SeaweedFS itself, with no credential in the client's
// hands beyond the URL.
//
// A signature the platform believes in and the gateway rejects would mean every
// LFS transfer failing in production while every unit test stayed green.
func TestLiveSeaweedFSHonoursOurPresignedURL(t *testing.T) {
	store, _ := liveStore(t)
	ctx := context.Background()

	payload := []byte("bytes fetched with nothing but a presigned URL")
	digest := digestOf(payload)
	key := "lfs/tenant-a/" + digest[:2] + "/" + digest
	if _, err := store.Put(ctx, key, int64(len(payload)), digest, bytes.NewReader(payload)); err != nil {
		t.Fatalf("Put: %v", err)
	}

	href, err := store.Presign(http.MethodGet, key, 5*time.Minute)
	if err != nil {
		t.Fatalf("Presign: %v", err)
	}

	// A bare client: no Authorization header, no credentials. This is exactly what
	// a git-lfs client has after a batch response.
	response, err := (&http.Client{Timeout: 30 * time.Second}).Get(href)
	if err != nil {
		t.Fatalf("fetch presigned URL: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 2048))
		t.Fatalf("SeaweedFS rejected our presigned URL: status %d, body %s", response.StatusCode, body)
	}
	got, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read presigned body: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("presigned fetch returned %q, want %q", got, payload)
	}
}

// An unsigned request for the same object is refused by the gateway. Without this
// the presigned test above proves nothing: a bucket that serves anonymous reads
// would pass it whether or not the signature was ever checked.
func TestLiveSeaweedFSRefusesAnUnsignedRequest(t *testing.T) {
	store, bucket := liveStore(t)
	ctx := context.Background()

	payload := []byte("this object is not public")
	digest := digestOf(payload)
	key := "lfs/tenant-a/" + digest[:2] + "/" + digest
	if _, err := store.Put(ctx, key, int64(len(payload)), digest, bytes.NewReader(payload)); err != nil {
		t.Fatalf("Put: %v", err)
	}

	endpoint := strings.TrimSuffix(os.Getenv("GITFROK_TEST_SEAWEEDFS_ENDPOINT"), "/")
	response, err := (&http.Client{Timeout: 30 * time.Second}).Get(endpoint + "/" + bucket + "/" + key)
	if err != nil {
		t.Fatalf("unsigned fetch: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode == http.StatusOK {
		t.Fatal("SeaweedFS served the object to an unsigned request — the bucket is public, and every " +
			"other assertion about scoped credentials in this suite is vacuous")
	}
}

// A tampered presigned URL is refused: changing the key it names invalidates the
// signature, which is what makes the credential scoped to one object rather than
// to the bucket (SPEC-0023 AC4).
func TestLiveSeaweedFSRefusesATamperedPresignedURL(t *testing.T) {
	store, _ := liveStore(t)
	ctx := context.Background()

	first := []byte("the object the credential names")
	second := []byte("the object it does not")
	for _, payload := range [][]byte{first, second} {
		digest := digestOf(payload)
		key := "lfs/tenant-a/" + digest[:2] + "/" + digest
		if _, err := store.Put(ctx, key, int64(len(payload)), digest, bytes.NewReader(payload)); err != nil {
			t.Fatalf("Put: %v", err)
		}
	}

	firstDigest, secondDigest := digestOf(first), digestOf(second)
	href, err := store.Presign(http.MethodGet, "lfs/tenant-a/"+firstDigest[:2]+"/"+firstDigest, 5*time.Minute)
	if err != nil {
		t.Fatalf("Presign: %v", err)
	}
	// Point the same signature at the other object.
	tampered := strings.Replace(href, firstDigest, secondDigest, -1)

	response, err := (&http.Client{Timeout: 30 * time.Second}).Get(tampered)
	if err != nil {
		t.Fatalf("tampered fetch: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode == http.StatusOK {
		t.Fatal("a credential for one object fetched another — the signature does not cover the key")
	}
}
