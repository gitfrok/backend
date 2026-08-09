package gitfrontdoor

import (
	"context"
	"io"
	"net/http"
	"strings"

	gitv1 "github.com/gitfrok/backend/gen/proto/git/v1"
)

// Storage bridges unmodified Git protocol bytes to GitStorage. Implementations
// must stream both directions; callers never receive a repository path.
type Storage interface {
	UploadPack(context.Context, *gitv1.OperationContext, io.Reader, io.Writer) error
	ReceivePack(context.Context, *gitv1.OperationContext, io.Reader, io.Writer) error
}

// SmartHTTP is the Git Smart-HTTP boundary described by ADR-0041. It accepts
// only discovery, upload-pack and receive-pack endpoints; all other paths are
// deliberately absent rather than becoming a generic HTTP or filesystem proxy.
type SmartHTTP struct {
	Router    Router
	Storage   Storage
	RequestID func() string
}

func (h SmartHTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.Storage == nil || h.RequestID == nil {
		http.NotFound(w, r)
		return
	}
	handle, service, discovery, ok := smartHTTPPath(r.URL.Path)
	if !ok || (discovery && (r.Method != http.MethodGet || r.URL.Query().Get("service") != service)) || (!discovery && r.Method != http.MethodPost) {
		http.NotFound(w, r)
		return
	}
	_, token, basic := r.BasicAuth()
	if !basic {
		httpUnauthorized(w)
		return
	}
	transport := gitv1.GitTransport_GIT_TRANSPORT_SMART_HTTP_RPC
	if discovery {
		transport = gitv1.GitTransport_GIT_TRANSPORT_SMART_HTTP_DISCOVERY
	}
	operation, err := h.Router.RoutePAT(r.Context(), handle, token, h.RequestID(), transport)
	if err != nil {
		httpUnauthorized(w)
		return
	}

	if discovery {
		w.Header().Set("Content-Type", "application/x-git-upload-pack-advertisement")
		_, _ = io.WriteString(w, "001e# service=git-upload-pack\n0000")
		if err := h.Storage.UploadPack(r.Context(), operation, strings.NewReader(""), w); err != nil {
			return
		}
		return
	}

	switch service {
	case "git-upload-pack":
		w.Header().Set("Content-Type", "application/x-git-upload-pack-result")
		_ = h.Storage.UploadPack(r.Context(), operation, r.Body, w)
	case "git-receive-pack":
		w.Header().Set("Content-Type", "application/x-git-receive-pack-result")
		_ = h.Storage.ReceivePack(r.Context(), operation, r.Body, w)
	default:
		http.NotFound(w, r)
	}
}

func httpUnauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="gitfrok"`)
	http.Error(w, "authentication required", http.StatusUnauthorized)
}

func smartHTTPPath(path string) (handle, service string, discovery, ok bool) {
	const prefix = "/git/"
	if !strings.HasPrefix(path, prefix) {
		return "", "", false, false
	}
	parts := strings.Split(strings.TrimPrefix(path, prefix), "/")
	if len(parts) < 3 {
		return "", "", false, false
	}
	handle = parts[0] + "/" + parts[1]
	switch {
	case len(parts) == 4 && parts[2] == "info" && parts[3] == "refs":
		return handle, "git-upload-pack", true, true
	case len(parts) == 3 && (parts[2] == "git-upload-pack" || parts[2] == "git-receive-pack"):
		return handle, parts[2], false, true
	default:
		return "", "", false, false
	}
}
