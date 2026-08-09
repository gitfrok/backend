package gitfrontdoor

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	gitv1 "github.com/gitfrok/backend/gen/proto/git/v1"
	identityapi "github.com/gitfrok/backend/modules/identity/api"
)

type recordingStorage struct {
	called  string
	context *gitv1.OperationContext
	input   []byte
}

func (s *recordingStorage) UploadPack(_ context.Context, operation *gitv1.OperationContext, input io.Reader, output io.Writer) error {
	s.called, s.context = "upload", operation
	s.input, _ = io.ReadAll(input)
	_, _ = output.Write([]byte("advertisement"))
	return nil
}

func (s *recordingStorage) ReceivePack(_ context.Context, operation *gitv1.OperationContext, input io.Reader, output io.Writer) error {
	s.called, s.context = "receive", operation
	s.input, _ = io.ReadAll(input)
	_, _ = output.Write([]byte("receive-status"))
	return nil
}

func TestSmartHTTPAuthenticatesBeforeOpeningStorageAndStreamsAdvertisement(t *testing.T) {
	storage := &recordingStorage{}
	handler := SmartHTTP{Router: Router{Authenticator: &fakeAuthenticator{principal: identityapi.Principal{TenantID: "tenant-a", ActorID: "actor-a", Roles: []string{"member"}}, ok: true}}, Storage: storage, RequestID: func() string { return "request-1" }}
	request := httptest.NewRequest(http.MethodGet, "https://git.test/git/tenant-a/repo-a.git/info/refs?service=git-upload-pack", nil)
	request.SetBasicAuth("ignored", "pat-secret")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK || storage.called != "upload" {
		t.Fatalf("status=%d storage=%q", response.Code, storage.called)
	}
	if got := response.Header().Get("Content-Type"); got != "application/x-git-upload-pack-advertisement" {
		t.Fatalf("content type = %q", got)
	}
	if want := "001e# service=git-upload-pack\n0000advertisement"; response.Body.String() != want {
		t.Fatalf("body = %q, want %q", response.Body.String(), want)
	}
	if storage.context.GetTenantId() != "tenant-a" || storage.context.GetRepositoryId() != "repo-a" || storage.context.GetActorId() != "actor-a" {
		t.Fatalf("storage context = %+v", storage.context)
	}
	if storage.context.GetTransport() != gitv1.GitTransport_GIT_TRANSPORT_SMART_HTTP_DISCOVERY {
		t.Fatalf("transport = %s", storage.context.GetTransport())
	}
}

func TestSmartHTTPDeniedCredentialNeverOpensStorage(t *testing.T) {
	storage := &recordingStorage{}
	handler := SmartHTTP{Router: Router{Authenticator: &fakeAuthenticator{}}, Storage: storage, RequestID: func() string { return "request-1" }}
	request := httptest.NewRequest(http.MethodPost, "https://git.test/git/tenant-a/repo-a.git/git-receive-pack", bytes.NewBufferString("pack"))
	request.SetBasicAuth("ignored", "bad-token")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized || storage.called != "" {
		t.Fatalf("status=%d storage=%q", response.Code, storage.called)
	}
}

func TestSmartHTTPReceivePackStreamsRequestWithoutFilesystemAccess(t *testing.T) {
	storage := &recordingStorage{}
	handler := SmartHTTP{Router: Router{Authenticator: &fakeAuthenticator{principal: identityapi.Principal{TenantID: "tenant-a", ActorID: "actor-a"}, ok: true}}, Storage: storage, RequestID: func() string { return "request-1" }}
	request := httptest.NewRequest(http.MethodPost, "https://git.test/git/tenant-a/repo-a.git/git-receive-pack", bytes.NewBufferString("pack-bytes"))
	request.SetBasicAuth("ignored", "pat-secret")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK || storage.called != "receive" || string(storage.input) != "pack-bytes" || response.Body.String() != "receive-status" {
		t.Fatalf("status=%d storage=%q input=%q output=%q", response.Code, storage.called, storage.input, response.Body.String())
	}
	if storage.context.GetTransport() != gitv1.GitTransport_GIT_TRANSPORT_SMART_HTTP_RPC {
		t.Fatalf("transport = %s", storage.context.GetTransport())
	}
}
