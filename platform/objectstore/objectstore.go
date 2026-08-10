// Package objectstore is the S3 tier for large objects — Git LFS today, CI
// artifacts and registry blobs later (ADR-0004, ADR-0020, ADR-0033 decision 4,
// SPEC-0023).
//
// It speaks the subset of S3 the platform actually needs — put one object, read
// one object, presign one operation on one object — over net/http with SigV4
// signing written here. That is a deliberate choice against pulling in an S3 SDK:
// the whole surface is three verbs, both planes ship as `scratch` images, and a
// dependency that brings a credential chain, a retry policy, and a plugin system
// with it is a larger thing to audit than the ~150 lines of signing below.
//
// What this package does NOT do: discover credentials from an environment chain,
// assume a role, or reach any endpoint it was not configured with. Configuration
// is explicit and per-environment (invariant 13).
package objectstore

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ErrNotFound is returned when an object is absent. It is deliberately distinct
// from a transport failure: "this object was never stored" and "the tier could
// not be reached" must not be conflated, because an import that treats the second
// as the first would report a repository complete when it is not (SPEC-0023 AC7).
var ErrNotFound = errors.New("objectstore: object not found")

// ErrDigestMismatch is returned when stored bytes do not hash to the digest they
// were announced under (SPEC-0023 AC5).
var ErrDigestMismatch = errors.New("objectstore: content does not match its declared digest")

// Config is the per-environment object-tier configuration. Every field is
// required; there is no default endpoint and no credential discovery, so a
// misconfigured deployment fails at construction rather than silently reaching
// somewhere unintended.
type Config struct {
	// Endpoint is the S3 base URL, e.g. https://seaweedfs-s3.gitfrok.svc:8333.
	Endpoint  string
	Region    string
	Bucket    string
	AccessKey string
	SecretKey string
	// HTTPClient is the transport. A nil client uses a bounded default rather
	// than http.DefaultClient, which has no timeout.
	HTTPClient *http.Client
	// Now is the clock, injectable so a signature can be asserted in a test.
	Now func() time.Time
}

// Store is the object tier.
type Store struct {
	config Config
	client *http.Client
	now    func() time.Time
}

// New validates the configuration and returns the store.
func New(config Config) (*Store, error) {
	missing := []string{}
	for name, value := range map[string]string{
		"endpoint": config.Endpoint, "region": config.Region, "bucket": config.Bucket,
		"access key": config.AccessKey, "secret key": config.SecretKey,
	} {
		if value == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		// The message names what is missing and never what was configured: a
		// secret must not reach an error string.
		return nil, fmt.Errorf("objectstore: incomplete configuration, missing %s", strings.Join(missing, ", "))
	}
	if _, err := url.Parse(config.Endpoint); err != nil {
		return nil, fmt.Errorf("objectstore: endpoint is not a URL: %w", err)
	}
	client := config.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Minute}
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}
	return &Store{config: config, client: client, now: now}, nil
}

// Put stores one object under key and verifies on the way in that its content
// hashes to sha256Hex.
//
// The verification is the point of doing this here rather than streaming
// straight through: an object stored under a name that lies about its content is
// worse than a refused write, because every later reader trusts the name
// (SPEC-0023 AC5). The bytes are hashed as they are read, so a mismatch is
// detected without buffering the whole object.
func (s *Store) Put(ctx context.Context, key string, size int64, sha256Hex string, body io.Reader) (int64, error) {
	if key == "" || sha256Hex == "" || size < 0 {
		return 0, errors.New("objectstore: put needs a key, a size and a digest")
	}
	hasher := sha256.New()
	counter := &countingReader{inner: io.TeeReader(body, hasher)}

	request, err := http.NewRequestWithContext(ctx, http.MethodPut, s.objectURL(key), counter)
	if err != nil {
		return 0, err
	}
	request.ContentLength = size
	// UNSIGNED-PAYLOAD: the object is streamed, so its digest is not known before
	// the request is signed. The content is verified against sha256Hex below —
	// the payload signature would prove the bytes arrived intact, and the digest
	// check proves they are the bytes that were promised, which is the stronger
	// claim.
	s.sign(request, "UNSIGNED-PAYLOAD")

	response, err := s.client.Do(request)
	if err != nil {
		return 0, err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode/100 != 2 {
		return 0, fmt.Errorf("objectstore: put %s: unexpected status %d", key, response.StatusCode)
	}
	if got := hex.EncodeToString(hasher.Sum(nil)); got != sha256Hex {
		// The object is on the tier under a name that does not describe it. Say so
		// rather than reporting success; the caller's contract is to treat this as
		// a failed write (SPEC-0023 AC5).
		return counter.count, fmt.Errorf("%w: stored %s, promised %s", ErrDigestMismatch, got, sha256Hex)
	}
	return counter.count, nil
}

// Stat reports an object's size, or ErrNotFound.
func (s *Store) Stat(ctx context.Context, key string) (int64, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodHead, s.objectURL(key), nil)
	if err != nil {
		return 0, err
	}
	s.sign(request, emptyPayloadHash)
	response, err := s.client.Do(request)
	if err != nil {
		return 0, err
	}
	defer func() { _ = response.Body.Close() }()
	switch {
	case response.StatusCode == http.StatusNotFound:
		return 0, ErrNotFound
	case response.StatusCode/100 != 2:
		return 0, fmt.Errorf("objectstore: stat %s: unexpected status %d", key, response.StatusCode)
	}
	return response.ContentLength, nil
}

// Get streams one object. The caller closes the returned reader.
func (s *Store) Get(ctx context.Context, key string) (io.ReadCloser, int64, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, s.objectURL(key), nil)
	if err != nil {
		return nil, 0, err
	}
	s.sign(request, emptyPayloadHash)
	response, err := s.client.Do(request)
	if err != nil {
		return nil, 0, err
	}
	switch {
	case response.StatusCode == http.StatusNotFound:
		_ = response.Body.Close()
		return nil, 0, ErrNotFound
	case response.StatusCode/100 != 2:
		_ = response.Body.Close()
		return nil, 0, fmt.Errorf("objectstore: get %s: unexpected status %d", key, response.StatusCode)
	}
	return response.Body, response.ContentLength, nil
}

// Presign returns a URL that authorizes exactly one method on exactly one key,
// expiring after ttl (SPEC-0023 decision 1).
//
// The scope is the whole safety argument. A presigned URL cannot be revoked
// mid-transfer, so its lifetime *is* the revocation window: it is short, it names
// one object, and it authorizes one method — a download credential cannot be
// replayed as an upload, and cannot be pointed at a second object, because both
// are inside the signature.
func (s *Store) Presign(method, key string, ttl time.Duration) (string, error) {
	if key == "" {
		return "", errors.New("objectstore: presign needs a key")
	}
	if ttl <= 0 || ttl > maxPresignTTL {
		return "", fmt.Errorf("objectstore: presign ttl must be within (0, %s]", maxPresignTTL)
	}
	switch method {
	case http.MethodGet, http.MethodPut:
	default:
		return "", fmt.Errorf("objectstore: presign will not sign %s", method)
	}

	target, err := url.Parse(s.objectURL(key))
	if err != nil {
		return "", err
	}
	now := s.now().UTC()
	stamp := now.Format("20060102T150405Z")
	day := now.Format("20060102")
	scope := day + "/" + s.config.Region + "/s3/aws4_request"

	query := url.Values{}
	query.Set("X-Amz-Algorithm", "AWS4-HMAC-SHA256")
	query.Set("X-Amz-Credential", s.config.AccessKey+"/"+scope)
	query.Set("X-Amz-Date", stamp)
	query.Set("X-Amz-Expires", strconv.Itoa(int(ttl.Seconds())))
	query.Set("X-Amz-SignedHeaders", "host")
	target.RawQuery = query.Encode()

	canonical := strings.Join([]string{
		method,
		target.EscapedPath(),
		target.RawQuery,
		"host:" + target.Host + "\n",
		"host",
		"UNSIGNED-PAYLOAD",
	}, "\n")
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256", stamp, scope, sha256Hex(canonical),
	}, "\n")
	signature := hex.EncodeToString(hmacSHA256(s.signingKey(day), stringToSign))

	query.Set("X-Amz-Signature", signature)
	target.RawQuery = query.Encode()
	return target.String(), nil
}

// maxPresignTTL bounds how long an unrevokable credential may live. Fifteen
// minutes is long enough for a large object on a slow link and short enough that
// a leaked URL is not a standing grant.
const maxPresignTTL = 15 * time.Minute

// emptyPayloadHash is SHA-256 of the empty string, which SigV4 requires for a
// request with no body.
const emptyPayloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func (s *Store) objectURL(key string) string {
	// Path-style addressing: SeaweedFS-S3 serves buckets on the path, and
	// virtual-host style would require per-bucket DNS the cluster does not have.
	return strings.TrimSuffix(s.config.Endpoint, "/") + "/" + s.config.Bucket + "/" + escapePath(key)
}

// sign adds the SigV4 Authorization header for one request.
func (s *Store) sign(request *http.Request, payloadHash string) {
	now := s.now().UTC()
	stamp := now.Format("20060102T150405Z")
	day := now.Format("20060102")
	scope := day + "/" + s.config.Region + "/s3/aws4_request"

	request.Header.Set("X-Amz-Date", stamp)
	request.Header.Set("X-Amz-Content-Sha256", payloadHash)

	canonical := strings.Join([]string{
		request.Method,
		request.URL.EscapedPath(),
		request.URL.RawQuery,
		"host:" + request.URL.Host + "\n" +
			"x-amz-content-sha256:" + payloadHash + "\n" +
			"x-amz-date:" + stamp + "\n",
		"host;x-amz-content-sha256;x-amz-date",
		payloadHash,
	}, "\n")
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256", stamp, scope, sha256Hex(canonical),
	}, "\n")
	signature := hex.EncodeToString(hmacSHA256(s.signingKey(day), stringToSign))

	request.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+s.config.AccessKey+"/"+scope+
		", SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature="+signature)
}

func (s *Store) signingKey(day string) []byte {
	key := hmacSHA256([]byte("AWS4"+s.config.SecretKey), day)
	key = hmacSHA256(key, s.config.Region)
	key = hmacSHA256(key, "s3")
	return hmacSHA256(key, "aws4_request")
}

func hmacSHA256(key []byte, data string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(data))
	return mac.Sum(nil)
}

func sha256Hex(data string) string {
	sum := sha256.Sum256([]byte(data))
	return hex.EncodeToString(sum[:])
}

// escapePath percent-encodes each path segment, keeping the separators. S3
// canonicalization escapes everything except unreserved characters and the
// slashes between segments.
func escapePath(key string) string {
	segments := strings.Split(key, "/")
	for i, segment := range segments {
		segments[i] = url.PathEscape(segment)
	}
	return strings.Join(segments, "/")
}

// countingReader counts the bytes actually read, which is what the storage tier
// received — not what a caller claimed it would send.
type countingReader struct {
	inner io.Reader
	count int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.inner.Read(p)
	c.count += int64(n)
	return n, err
}
