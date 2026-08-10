package gitfrontdoor

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	gitv1 "github.com/gitfrok/backend/gen/proto/git/v1"
)

// The Git LFS batch API (SPEC-0023 AC1/AC3), terminated where every other Git
// protocol endpoint is: at the front door, which authenticates the caller, routes
// the handle to a tenant-scoped operation context, and forwards.
//
// The front door never touches the object tier. It asks the object port for a
// short, scoped, single-object credential and hands that to the client, so bytes
// travel client-to-tier and this process stays out of the data path (SPEC-0023
// decision 1).

// LFSObjects is the object port the batch surface needs. It is separate from
// Storage because these are different operations on a different tier, and a
// deployment can have Git without LFS.
type LFSObjects interface {
	// Download returns a URL that authorizes fetching exactly this object, and the
	// object's size. ErrObjectMissing means the object is not stored.
	Download(ctx context.Context, operation *gitv1.OperationContext, oid string) (href string, size int64, expires time.Duration, err error)
	// Upload returns a URL that authorizes storing exactly this object.
	Upload(ctx context.Context, operation *gitv1.OperationContext, oid string, size int64) (href string, expires time.Duration, err error)
}

// ErrObjectMissing reports an object the tier does not hold. It is distinct from
// a refusal: a client that asked for something absent gets told so per object,
// which is what the batch protocol expects, while a caller who may not read the
// repository at all never reaches this point.
var ErrObjectMissing = errors.New("gitfrontdoor: object not stored")

// LFS serves the batch endpoint for one repository handle.
type LFS struct {
	Router    Router
	Objects   LFSObjects
	RequestID func() string
}

// maxBatchObjects bounds one batch request. A client asking about ten thousand
// objects in one call is asking this process to sign ten thousand URLs before it
// answers anything; git-lfs itself batches in the low hundreds.
const maxBatchObjects = 500

type batchRequest struct {
	Operation string   `json:"operation"`
	Transfers []string `json:"transfers"`
	Objects   []struct {
		OID  string `json:"oid"`
		Size int64  `json:"size"`
	} `json:"objects"`
}

type batchAction struct {
	Href      string `json:"href"`
	ExpiresIn int    `json:"expires_in"`
}

type batchObject struct {
	OID     string `json:"oid"`
	Size    int64  `json:"size"`
	Actions *struct {
		Download *batchAction `json:"download,omitempty"`
		Upload   *batchAction `json:"upload,omitempty"`
	} `json:"actions,omitempty"`
	Error *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

type batchResponse struct {
	Transfer string        `json:"transfer"`
	Objects  []batchObject `json:"objects"`
}

func (h LFS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.Objects == nil || h.RequestID == nil {
		http.NotFound(w, r)
		return
	}
	handle, ok := lfsBatchPath(r.URL.Path)
	if !ok || r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	_, token, basic := r.BasicAuth()
	if !basic {
		httpUnauthorized(w)
		return
	}

	var request batchRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&request); err != nil {
		http.Error(w, "malformed batch request", http.StatusBadRequest)
		return
	}
	if len(request.Objects) == 0 || len(request.Objects) > maxBatchObjects {
		http.Error(w, "unsupported batch size", http.StatusBadRequest)
		return
	}

	// The transport a caller asks for is not negotiable to something we do not
	// serve: only `basic` exists here (SPEC-0023 out of scope).
	if len(request.Transfers) > 0 && !contains(request.Transfers, "basic") {
		http.Error(w, "no acceptable transfer", http.StatusNotImplemented)
		return
	}

	// Read and write are different permissions, asked as different actions. The
	// transport is the RPC transport because this is an authenticated Git
	// operation over HTTP, and the routing derives tenant and repository from the
	// handle — a caller cannot assert either (invariant 2).
	transport := gitv1.GitTransport_GIT_TRANSPORT_SMART_HTTP_RPC
	operation, err := h.Router.RoutePAT(r.Context(), handle, token, h.RequestID(), transport)
	if err != nil {
		httpUnauthorized(w)
		return
	}

	response := batchResponse{Transfer: "basic"}
	switch request.Operation {
	case "download":
		for _, object := range request.Objects {
			response.Objects = append(response.Objects, h.downloadObject(r.Context(), operation, object.OID, object.Size))
		}
	case "upload":
		for _, object := range request.Objects {
			response.Objects = append(response.Objects, h.uploadObject(r.Context(), operation, object.OID, object.Size))
		}
	default:
		http.Error(w, "unsupported operation", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/vnd.git-lfs+json")
	// A batch response carries credentials. It must never be cached by anything
	// between here and the client.
	w.Header().Set("Cache-Control", "private, no-store")
	_ = json.NewEncoder(w).Encode(response)
}

func (h LFS) downloadObject(ctx context.Context, operation *gitv1.OperationContext, oid string, size int64) batchObject {
	href, storedSize, expires, err := h.Objects.Download(ctx, operation, oid)
	switch {
	case errors.Is(err, ErrObjectMissing):
		return objectError(oid, size, http.StatusNotFound, "object not stored")
	case err != nil:
		// One coarse per-object failure. It distinguishes nothing about why, for
		// the same reason every other refusal on this surface does not.
		return objectError(oid, size, http.StatusUnprocessableEntity, "object unavailable")
	}
	out := batchObject{OID: oid, Size: storedSize}
	out.Actions = &struct {
		Download *batchAction `json:"download,omitempty"`
		Upload   *batchAction `json:"upload,omitempty"`
	}{Download: &batchAction{Href: href, ExpiresIn: int(expires.Seconds())}}
	return out
}

func (h LFS) uploadObject(ctx context.Context, operation *gitv1.OperationContext, oid string, size int64) batchObject {
	href, expires, err := h.Objects.Upload(ctx, operation, oid, size)
	if err != nil {
		return objectError(oid, size, http.StatusUnprocessableEntity, "object unavailable")
	}
	out := batchObject{OID: oid, Size: size}
	out.Actions = &struct {
		Download *batchAction `json:"download,omitempty"`
		Upload   *batchAction `json:"upload,omitempty"`
	}{Upload: &batchAction{Href: href, ExpiresIn: int(expires.Seconds())}}
	return out
}

func objectError(oid string, size int64, code int, message string) batchObject {
	out := batchObject{OID: oid, Size: size}
	out.Error = &struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}{Code: code, Message: message}
	return out
}

// lfsBatchPath matches /git/{tenant}/{repository}.git/info/lfs/objects/batch and
// nothing else. Like smartHTTPPath, the endpoints this surface serves are
// enumerated rather than derived, so it cannot become a generic proxy.
func lfsBatchPath(path string) (handle string, ok bool) {
	const prefix = "/git/"
	if !strings.HasPrefix(path, prefix) {
		return "", false
	}
	parts := strings.Split(strings.TrimPrefix(path, prefix), "/")
	if len(parts) != 6 {
		return "", false
	}
	if parts[2] != "info" || parts[3] != "lfs" || parts[4] != "objects" || parts[5] != "batch" {
		return "", false
	}
	return parts[0] + "/" + parts[1], true
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
