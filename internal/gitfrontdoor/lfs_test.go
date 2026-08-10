package gitfrontdoor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	gitv1 "github.com/gitfrok/backend/gen/proto/git/v1"
	identityapi "github.com/gitfrok/backend/modules/identity/api"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
	"github.com/gitfrok/backend/platform/objectstore"
)

const (
	testOID = "1111111111111111111111111111111111111111111111111111111111111111"
	testPAT = "pat-secret"
)

// lfsRouter is the same authenticated routing the Smart-HTTP surface uses: the
// tenant and repository come from the handle, never from the request body.
func lfsRouter() Router {
	return Router{Authenticator: &fakeAuthenticator{
		principal: identityapi.Principal{TenantID: "tenant-a", ActorID: "actor-a", Roles: []string{"member"}},
		ok:        true,
	}}
}

// fakeTier is a presigner over a fixed set of stored objects.
type fakeTier struct {
	stored   map[string]int64
	presigns []string
}

func (f *fakeTier) Stat(_ context.Context, key string) (int64, error) {
	size, ok := f.stored[key]
	if !ok {
		return 0, objectstore.ErrNotFound
	}
	return size, nil
}

func (f *fakeTier) Presign(method, key string, ttl time.Duration) (string, error) {
	f.presigns = append(f.presigns, method+" "+key)
	return "https://objects.test/" + key + "?method=" + method + "&ttl=" + ttl.String(), nil
}

// actionPDP grants only the listed actions and records what it was asked.
type actionPDP struct {
	allow map[string]bool
	asked []policyapi.Request
}

func (p *actionPDP) Decide(_ context.Context, req policyapi.Request) (policyapi.Decision, error) {
	p.asked = append(p.asked, req)
	return policyapi.Decision{Allowed: p.allow[req.Action], DecisionID: "d", PolicyRevision: "r"}, nil
}

// stubObjects is the batch surface's port, so the HTTP layer can be tested
// without a tier at all.
type stubObjects struct {
	href    string
	size    int64
	err     error
	upErr   error
	asked   []string
	upAsked []string
}

func (s *stubObjects) Download(_ context.Context, _ *gitv1.OperationContext, oid string) (string, int64, time.Duration, error) {
	s.asked = append(s.asked, oid)
	if s.err != nil {
		return "", 0, 0, s.err
	}
	return s.href, s.size, 10 * time.Minute, nil
}

func (s *stubObjects) Upload(_ context.Context, _ *gitv1.OperationContext, oid string, _ int64) (string, time.Duration, error) {
	s.upAsked = append(s.upAsked, oid)
	if s.upErr != nil {
		return "", 0, s.upErr
	}
	return s.href, 5 * time.Minute, nil
}

func batchRequestBody(operation, oid string, size int64) string {
	body, _ := json.Marshal(map[string]any{
		"operation": operation,
		"transfers": []string{"basic"},
		"objects":   []map[string]any{{"oid": oid, "size": size}},
	})
	return string(body)
}

// A download batch returns a per-object action pointing at the object tier, and
// the response is never cacheable: it carries a credential (SPEC-0023 AC1).
func TestBatchDownloadReturnsAScopedAction(t *testing.T) {
	objects := &stubObjects{href: "https://objects.test/lfs/tenant-a/11/" + testOID, size: 42}
	handler := LFS{Router: lfsRouter(), Objects: objects, RequestID: func() string { return "request-1" }}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost,
		"/git/tenant-a/repo-a.git/info/lfs/objects/batch",
		strings.NewReader(batchRequestBody("download", testOID, 42)))
	request.SetBasicAuth("token", testPAT)
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("Cache-Control"); got != "private, no-store" {
		t.Fatalf("Cache-Control = %q — a response carrying a credential must not be cached", got)
	}
	var response struct {
		Transfer string `json:"transfer"`
		Objects  []struct {
			OID     string `json:"oid"`
			Size    int64  `json:"size"`
			Actions struct {
				Download *struct {
					Href      string `json:"href"`
					ExpiresIn int    `json:"expires_in"`
				} `json:"download"`
			} `json:"actions"`
		} `json:"objects"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("body is not a batch response: %v", err)
	}
	if response.Transfer != "basic" || len(response.Objects) != 1 {
		t.Fatalf("response = %+v", response)
	}
	object := response.Objects[0]
	if object.Actions.Download == nil || object.Actions.Download.Href == "" {
		t.Fatal("no download action was returned")
	}
	if object.Actions.Download.ExpiresIn <= 0 {
		t.Fatal("the action carries no expiry, so the credential never stops working")
	}
	if object.Size != 42 {
		t.Fatalf("size = %d, want the stored size the tier reported", object.Size)
	}
}

// An absent object is reported per object, not as a failed batch: the rest of the
// batch still resolves.
func TestBatchDownloadReportsAMissingObject(t *testing.T) {
	objects := &stubObjects{err: ErrObjectMissing}
	handler := LFS{Router: lfsRouter(), Objects: objects, RequestID: func() string { return "request-1" }}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost,
		"/git/tenant-a/repo-a.git/info/lfs/objects/batch",
		strings.NewReader(batchRequestBody("download", testOID, 42)))
	request.SetBasicAuth("token", testPAT)
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), `"code":404`) {
		t.Fatalf("body = %s, want a per-object 404", recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), `"actions"`) {
		t.Fatal("a missing object was given an action")
	}
}

// An unauthenticated batch request never reaches the object port.
func TestBatchWithoutCredentialsIsRefused(t *testing.T) {
	objects := &stubObjects{}
	handler := LFS{Router: lfsRouter(), Objects: objects, RequestID: func() string { return "request-1" }}

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost,
		"/git/tenant-a/repo-a.git/info/lfs/objects/batch",
		strings.NewReader(batchRequestBody("download", testOID, 42))))

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", recorder.Code)
	}
	if len(objects.asked) != 0 {
		t.Fatal("the object port was reached without credentials")
	}
}

// Only the batch path exists on this surface. Anything else is absent rather than
// proxied — the same rule the Smart-HTTP surface follows.
func TestOnlyTheBatchPathIsServed(t *testing.T) {
	handler := LFS{Router: lfsRouter(), Objects: &stubObjects{}, RequestID: func() string { return "request-1" }}
	for _, path := range []string{
		"/git/tenant-a/repo-a.git/info/lfs/objects",
		"/git/tenant-a/repo-a.git/info/lfs/locks",
		"/git/tenant-a/repo-a.git/info/lfs/objects/batch/extra",
		"/git/tenant-a/info/lfs/objects/batch",
		"/lfs/objects/batch",
	} {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(batchRequestBody("download", testOID, 1)))
		request.SetBasicAuth("token", testPAT)
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusNotFound {
			t.Errorf("%s served with status %d, want 404", path, recorder.Code)
		}
	}
}

// A transfer adapter this platform does not serve is refused rather than answered
// with `basic` actions the client did not ask for.
func TestUnsupportedTransferIsRefused(t *testing.T) {
	handler := LFS{Router: lfsRouter(), Objects: &stubObjects{}, RequestID: func() string { return "request-1" }}
	body, _ := json.Marshal(map[string]any{
		"operation": "download",
		"transfers": []string{"multipart"},
		"objects":   []map[string]any{{"oid": testOID, "size": 1}},
	})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/git/tenant-a/repo-a.git/info/lfs/objects/batch", strings.NewReader(string(body)))
	request.SetBasicAuth("token", testPAT)
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501", recorder.Code)
	}
}

// LFS read and write are their own PDP actions: a subject that may read the
// repository but holds no LFS grant is denied (SPEC-0023 AC3).
func TestLFSIsItsOwnPermission(t *testing.T) {
	tier := &fakeTier{stored: map[string]int64{objectKey("tenant-a", testOID): 42}}
	pdp := &actionPDP{allow: map[string]bool{"repo.read": true, "repo.write": true}}
	objects, err := NewObjectTier(pdp, tier)
	if err != nil {
		t.Fatalf("NewObjectTier: %v", err)
	}
	operation := &gitv1.OperationContext{
		TenantId: "tenant-a", RepositoryId: "repo-a", ActorId: "actor-a",
		ActorRoles: []string{"member"}, RequestId: "request-1",
	}

	if _, _, _, err := objects.Download(context.Background(), operation, testOID); err == nil {
		t.Fatal("a repository reader with no LFS grant was allowed to fetch an object")
	}
	if len(pdp.asked) == 0 || pdp.asked[0].Action != actionLFSRead {
		t.Fatalf("PDP was asked %+v, want %s", pdp.asked, actionLFSRead)
	}
	if len(tier.presigns) != 0 {
		t.Fatal("a denied read still signed a credential")
	}

	pdp.allow[actionLFSRead] = true
	href, size, ttl, err := objects.Download(context.Background(), operation, testOID)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	if size != 42 || ttl <= 0 || !strings.Contains(href, "method=GET") {
		t.Fatalf("download = %q size %d ttl %s", href, size, ttl)
	}
}

// The credential names one object in one tenant, and a download credential is
// never a write credential (SPEC-0023 AC4, decision 1).
func TestCredentialIsScopedToOneObjectAndOneMethod(t *testing.T) {
	tier := &fakeTier{stored: map[string]int64{objectKey("tenant-a", testOID): 42}}
	pdp := &actionPDP{allow: map[string]bool{actionLFSRead: true, actionLFSWrite: true}}
	objects, _ := NewObjectTier(pdp, tier)

	inA := &gitv1.OperationContext{TenantId: "tenant-a", RepositoryId: "repo-a", ActorId: "actor-a", RequestId: "r"}
	inB := &gitv1.OperationContext{TenantId: "tenant-b", RepositoryId: "repo-b", ActorId: "actor-b", RequestId: "r"}

	if _, _, _, err := objects.Download(context.Background(), inA, testOID); err != nil {
		t.Fatalf("tenant A download: %v", err)
	}
	// The same OID in another tenant is another object, and that one is not stored.
	if _, _, _, err := objects.Download(context.Background(), inB, testOID); err == nil {
		t.Fatal("tenant B read tenant A's object by naming its OID")
	}

	if len(tier.presigns) != 1 {
		t.Fatalf("presigns = %v, want exactly the one authorized read", tier.presigns)
	}
	if !strings.HasPrefix(tier.presigns[0], "GET lfs/tenant-a/") {
		t.Fatalf("credential = %q, want a GET scoped to tenant-a's key", tier.presigns[0])
	}
}

// An object already stored gets no upload credential: the tier is
// content-addressed, so a write credential for it is only an opportunity to
// replace bytes that already match their name.
func TestUploadOfAStoredObjectIsRefused(t *testing.T) {
	tier := &fakeTier{stored: map[string]int64{objectKey("tenant-a", testOID): 42}}
	pdp := &actionPDP{allow: map[string]bool{actionLFSWrite: true}}
	objects, _ := NewObjectTier(pdp, tier)
	operation := &gitv1.OperationContext{TenantId: "tenant-a", RepositoryId: "repo-a", ActorId: "actor-a", RequestId: "r"}

	if _, _, err := objects.Upload(context.Background(), operation, testOID, 42); err == nil {
		t.Fatal("an already-stored object was given an upload credential")
	}
}

// An OID that is not a lowercase hex SHA-256 never reaches the tier: it would
// become part of a storage key.
func TestMalformedOIDNeverReachesTheTier(t *testing.T) {
	tier := &fakeTier{stored: map[string]int64{}}
	pdp := &actionPDP{allow: map[string]bool{actionLFSRead: true, actionLFSWrite: true}}
	objects, _ := NewObjectTier(pdp, tier)
	operation := &gitv1.OperationContext{TenantId: "tenant-a", RepositoryId: "repo-a", ActorId: "actor-a", RequestId: "r"}

	for _, oid := range []string{
		"", "short", strings.Repeat("A", 64), "../../etc/passwd",
		strings.Repeat("1", 63) + "/", strings.Repeat("1", 65),
	} {
		if _, _, _, err := objects.Download(context.Background(), operation, oid); err == nil {
			t.Errorf("download accepted OID %q", oid)
		}
		if _, _, err := objects.Upload(context.Background(), operation, oid, 1); err == nil {
			t.Errorf("upload accepted OID %q", oid)
		}
	}
	if len(tier.presigns) != 0 {
		t.Fatalf("a malformed OID reached the tier: %v", tier.presigns)
	}
}
