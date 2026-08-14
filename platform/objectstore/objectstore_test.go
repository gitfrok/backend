package objectstore

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

func fixedClock() func() time.Time {
	return func() time.Time { return time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC) }
}

// fakeTier is a minimal S3: it stores what is PUT and serves what is GET, and
// records the requests so a test can assert the signing.
type fakeTier struct {
	objects  map[string][]byte
	requests []*http.Request
	server   *httptest.Server
	// pageLimit caps how many keys one ListObjectsV2 page returns, so a test can
	// force continuation and prove the client follows it.
	pageLimit int
}

func newFakeTier(t *testing.T) *fakeTier {
	t.Helper()
	tier := &fakeTier{objects: map[string][]byte{}}
	tier.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tier.requests = append(tier.requests, r.Clone(r.Context()))
		key := r.URL.Path
		switch r.Method {
		case http.MethodPut:
			body, _ := io.ReadAll(r.Body)
			tier.objects[key] = body
			w.WriteHeader(http.StatusOK)
		case http.MethodHead:
			body, ok := tier.objects[key]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Length", itoa(len(body)))
			w.WriteHeader(http.StatusOK)
		case http.MethodGet:
			if r.URL.Query().Get("list-type") == "2" {
				tier.serveList(w, r)
				return
			}
			body, ok := tier.objects[key]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = w.Write(body)
		case http.MethodDelete:
			// S3 answers 204 whether or not the object existed.
			delete(tier.objects, key)
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	t.Cleanup(tier.server.Close)
	return tier
}

// serveList answers a ListObjectsV2 request with sorted, prefix-filtered keys,
// paginated at pageLimit when one is set. The continuation token is the offset
// of the next page; a real gateway's is opaque, and the client must treat it so.
func (tier *fakeTier) serveList(w http.ResponseWriter, r *http.Request) {
	bucket := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/", 2)[0]
	prefix := r.URL.Query().Get("prefix")
	var keys []string
	for path := range tier.objects {
		key := strings.TrimPrefix(path, "/"+bucket+"/")
		if strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
	}
	slices.Sort(keys)

	limit := 1000
	if tier.pageLimit > 0 {
		limit = tier.pageLimit
	}
	start := 0
	if token := r.URL.Query().Get("continuation-token"); token != "" {
		start, _ = strconv.Atoi(token)
	}
	end := min(start+limit, len(keys))

	var body strings.Builder
	body.WriteString(`<?xml version="1.0" encoding="UTF-8"?><ListBucketResult>`)
	if end < len(keys) {
		fmt.Fprintf(&body, "<IsTruncated>true</IsTruncated><NextContinuationToken>%d</NextContinuationToken>", end)
	}
	for _, key := range keys[start:end] {
		fmt.Fprintf(&body, "<Contents><Key>%s</Key></Contents>", key)
	}
	body.WriteString("</ListBucketResult>")
	w.Header().Set("Content-Type", "application/xml")
	_, _ = w.Write([]byte(body.String()))
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := ""
	for n > 0 {
		digits = string(rune('0'+n%10)) + digits
		n /= 10
	}
	return digits
}

func testStore(t *testing.T, tier *fakeTier) *Store {
	t.Helper()
	store, err := New(Config{
		Endpoint: tier.server.URL, Region: "us-east-1", Bucket: "gitfrok",
		AccessKey: "AKIAEXAMPLE", SecretKey: "secret",
		HTTPClient: tier.server.Client(), Now: fixedClock(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return store
}

// A round trip: what was put is what comes back, and every request is signed.
func TestPutStatGetRoundTrip(t *testing.T) {
	tier := newFakeTier(t)
	store := testStore(t, tier)
	payload := "a large object"
	digest := sha256Hex(payload)

	written, err := store.Put(t.Context(), "lfs/tenant-a/ab/"+digest, int64(len(payload)), digest, strings.NewReader(payload))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if written != int64(len(payload)) {
		t.Fatalf("wrote %d bytes, want %d", written, len(payload))
	}

	size, err := store.Stat(t.Context(), "lfs/tenant-a/ab/"+digest)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if size != int64(len(payload)) {
		t.Fatalf("stat size = %d", size)
	}

	body, _, err := store.Get(t.Context(), "lfs/tenant-a/ab/"+digest)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer func() { _ = body.Close() }()
	content, _ := io.ReadAll(body)
	if string(content) != payload {
		t.Fatalf("got %q, want %q", content, payload)
	}

	for _, request := range tier.requests {
		if !strings.HasPrefix(request.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE/") {
			t.Fatalf("%s was not signed: %q", request.Method, request.Header.Get("Authorization"))
		}
		if request.Header.Get("X-Amz-Content-Sha256") == "" || request.Header.Get("X-Amz-Date") == "" {
			t.Fatalf("%s is missing the signed headers", request.Method)
		}
		if strings.Contains(request.Header.Get("Authorization"), "secret") {
			t.Fatal("the secret key appeared in a request header")
		}
	}
}

// Content that does not hash to the digest it was announced under is reported as a
// failed write, not a success (SPEC-0023 AC5).
func TestPutRejectsContentThatDoesNotMatchItsDigest(t *testing.T) {
	tier := newFakeTier(t)
	store := testStore(t, tier)
	payload := "the actual bytes"
	promised := sha256Hex("something else")

	_, err := store.Put(t.Context(), "lfs/tenant-a/aa/"+promised, int64(len(payload)), promised, strings.NewReader(payload))
	if !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("Put = %v, want ErrDigestMismatch", err)
	}
}

// An absent object is ErrNotFound, distinct from a transport failure — an import
// that conflated the two would report a repository complete when it is not.
func TestStatAndGetOfAbsentObject(t *testing.T) {
	tier := newFakeTier(t)
	store := testStore(t, tier)
	if _, err := store.Stat(t.Context(), "lfs/tenant-a/zz/missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Stat = %v, want ErrNotFound", err)
	}
	if _, _, err := store.Get(t.Context(), "lfs/tenant-a/zz/missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get = %v, want ErrNotFound", err)
	}
}

// A presigned URL names one object, one method, and an expiry — and the secret key
// never appears in it.
func TestPresignIsScopedAndExpiring(t *testing.T) {
	tier := newFakeTier(t)
	store := testStore(t, tier)

	href, err := store.Presign(http.MethodGet, "lfs/tenant-a/ab/object", 10*time.Minute)
	if err != nil {
		t.Fatalf("Presign: %v", err)
	}
	parsed, err := url.Parse(href)
	if err != nil {
		t.Fatalf("presigned URL does not parse: %v", err)
	}
	query := parsed.Query()
	if query.Get("X-Amz-Signature") == "" {
		t.Fatal("the URL carries no signature")
	}
	if query.Get("X-Amz-Expires") != "600" {
		t.Fatalf("expiry = %q, want 600 seconds", query.Get("X-Amz-Expires"))
	}
	if !strings.Contains(parsed.Path, "lfs/tenant-a/ab/object") {
		t.Fatalf("path = %q, want the one object it authorizes", parsed.Path)
	}
	if strings.Contains(href, "secret") {
		t.Fatal("the secret key appeared in the presigned URL")
	}

	// A GET credential and a PUT credential for the same object differ, so one
	// cannot be replayed as the other.
	put, err := store.Presign(http.MethodPut, "lfs/tenant-a/ab/object", 10*time.Minute)
	if err != nil {
		t.Fatalf("Presign PUT: %v", err)
	}
	if signatureOf(t, put) == signatureOf(t, href) {
		t.Fatal("the GET and PUT credentials share a signature")
	}

	// And a credential for another object differs too.
	other, err := store.Presign(http.MethodGet, "lfs/tenant-a/cd/other", 10*time.Minute)
	if err != nil {
		t.Fatalf("Presign other: %v", err)
	}
	if signatureOf(t, other) == signatureOf(t, href) {
		t.Fatal("two objects share one credential")
	}
}

func signatureOf(t *testing.T, href string) string {
	t.Helper()
	parsed, err := url.Parse(href)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return parsed.Query().Get("X-Amz-Signature")
}

// A credential's lifetime is bounded, and a method this store will not sign is
// refused rather than signed anyway.
func TestPresignRefusesWhatItMustNotSign(t *testing.T) {
	tier := newFakeTier(t)
	store := testStore(t, tier)

	for _, ttl := range []time.Duration{0, -time.Minute, 24 * time.Hour} {
		if _, err := store.Presign(http.MethodGet, "lfs/tenant-a/ab/object", ttl); err == nil {
			t.Errorf("a %s credential was signed", ttl)
		}
	}
	for _, method := range []string{http.MethodDelete, http.MethodPost, "TRACE"} {
		if _, err := store.Presign(method, "lfs/tenant-a/ab/object", time.Minute); err == nil {
			t.Errorf("a %s credential was signed", method)
		}
	}
	if _, err := store.Presign(http.MethodGet, "", time.Minute); err == nil {
		t.Error("a credential naming no object was signed")
	}
}

// Configuration is explicit: a store with a missing field fails at construction,
// and the error names what is missing without echoing what was configured.
func TestIncompleteConfigurationIsRefused(t *testing.T) {
	_, err := New(Config{Endpoint: "https://objects.test", Region: "us-east-1", SecretKey: "top-secret"})
	if err == nil {
		t.Fatal("an incomplete configuration was accepted")
	}
	if !strings.Contains(err.Error(), "bucket") || !strings.Contains(err.Error(), "access key") {
		t.Fatalf("error = %v, want it to name the missing fields", err)
	}
	if strings.Contains(err.Error(), "top-secret") {
		t.Fatalf("error leaked a secret: %v", err)
	}
}

// List names what a prefix holds, sorted, and follows continuation when a page
// does not hold the whole answer. The report-store retention sweep and the CI
// ingest read-back both rest on this (SPEC-0037 AC1, AC9).
func TestStoreListIsPrefixedSortedAndPaginated(t *testing.T) {
	tier := newFakeTier(t)
	tier.pageLimit = 2
	store := testStore(t, tier)

	want := make([]string, 0, 5)
	for i := range 5 {
		payload := "report body " + itoa(i)
		digest := sha256Hex(payload)
		key := "ci-scan-reports/tenant-a/job/attempt/class" + itoa(i) + "/" + digest
		if _, err := store.Put(t.Context(), key, int64(len(payload)), digest, strings.NewReader(payload)); err != nil {
			t.Fatalf("Put %d: %v", i, err)
		}
		want = append(want, key)
	}
	// A neighbour under another prefix must not appear.
	other := "ci-scan-reports/tenant-b/job/attempt/class/" + sha256Hex("elsewhere")
	if _, err := store.Put(t.Context(), other, 9, sha256Hex("elsewhere"), strings.NewReader("elsewhere")); err != nil {
		t.Fatalf("Put other: %v", err)
	}
	slices.Sort(want)

	got, err := store.List(t.Context(), "ci-scan-reports/tenant-a/")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("List = %v, want %v", got, want)
	}

	// Five keys at two per page means three ListObjectsV2 requests, each signed.
	listRequests := 0
	for _, request := range tier.requests {
		if request.Method == http.MethodGet && request.URL.Query().Get("list-type") == "2" {
			listRequests++
			if !strings.HasPrefix(request.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE/") {
				t.Fatal("a list request was not signed")
			}
		}
	}
	if listRequests != 3 {
		t.Fatalf("list requests = %d, want 3 (5 keys, 2 per page)", listRequests)
	}
}

// A listing with an empty prefix would name the whole bucket; it is refused, as
// is a listing whose requests fail.
func TestStoreListRefusesAnEmptyPrefix(t *testing.T) {
	tier := newFakeTier(t)
	store := testStore(t, tier)
	if _, err := store.List(t.Context(), ""); err == nil {
		t.Fatal("a prefixless listing was allowed")
	}
}

// Delete removes one object and, like S3, reports success whether or not the
// object existed: the retention sweep must not fail because a concurrent sweep
// already took a report.
func TestStoreDeleteRemovesAndIsIdempotent(t *testing.T) {
	tier := newFakeTier(t)
	store := testStore(t, tier)
	payload := "to be retained out"
	digest := sha256Hex(payload)
	key := "ci-scan-reports/tenant-a/job/attempt/class/" + digest
	if _, err := store.Put(t.Context(), key, int64(len(payload)), digest, strings.NewReader(payload)); err != nil {
		t.Fatalf("Put: %v", err)
	}

	if err := store.Delete(t.Context(), key); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := store.Stat(t.Context(), key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Stat after Delete = %v, want ErrNotFound", err)
	}
	if err := store.Delete(t.Context(), key); err != nil {
		t.Fatalf("deleting an absent object must succeed: %v", err)
	}
	for _, request := range tier.requests {
		if request.Method == http.MethodDelete && !strings.HasPrefix(request.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE/") {
			t.Fatal("the delete request was not signed")
		}
	}
	if err := store.Delete(t.Context(), ""); err == nil {
		t.Fatal("a keyless delete was allowed")
	}
}
