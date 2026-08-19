// Package api is the Release context's in-process surface (ADR-0025). Other modules and the plane
// binaries depend ONLY on this package — never on internal/*. It exposes no infrastructure types
// (invariant 20), only plain data and behavioural ports.
//
// A release is a NAME FOR A COMMIT plus prose about it (SPEC-0056, ADR-0075). ADR-0075 accepted the
// tags-and-notes increment only: there is no artifact here, and check 15 in check-contracts.sh
// keeps the wire free of one.
package api

import (
	"context"
	"errors"
	"time"
)

// Bounds. Notes are prose, not a document store.
const (
	MaxNotesBytes = 64 << 10
	MaxTagLength  = 255
)

var (
	// ErrAlreadyPublished reports a second release of the same tag. Two releases of v1.2.0 is not
	// a state this product has an answer for, so it is refused rather than resolved.
	ErrAlreadyPublished = errors.New("release: this tag already has a release")
	// ErrNotFound is the coarse absence. A release of another tenant and a release that never
	// existed reach it identically.
	ErrNotFound = errors.New("release: not found")
	// ErrInvalid reports a shape the contract does not name.
	ErrInvalid = errors.New("release: invalid request")
)

// Release is the record.
//
// PublishedCommit is the commit the tag pointed at WHEN THIS WAS PUBLISHED, and it is the field
// that makes a release a record rather than a view. A tag is a mutable pointer: without this, moving
// v1.2.0 would silently rewrite what an already-published release describes.
type Release struct {
	TenantID        string
	RepositoryID    string
	Tag             string
	PublishedCommit string
	Notes           string
	PublishedBy     string
	PublishedAt     time.Time
	// Zero until the notes are first edited.
	NotesUpdatedAt time.Time
}

// Context carries the verified caller. There is no publisher field: who published is the session's
// identity, and a caller-assertable one would be an unauthenticated authorship claim.
type Context struct {
	TenantID     string
	RepositoryID string
	ActorID      string
	RequestID    string
	ActorRoles   []string
}

// PublishRequest names the tag and the prose. The commit is resolved server-side at publish time
// and has no field here.
type PublishRequest struct {
	Context Context
	Tag     string
	Notes   string
	// PublishedCommit is filled by the composition root from Repository/Git before the service
	// sees it. It is not caller-assertable: the field exists on this in-process shape because the
	// resolution happens outside this context, which may not depend on Repository/Git (ADR-0022).
	PublishedCommit string
}

// ListQuery asks for a repository's releases. No filter, and no field for one.
type ListQuery struct {
	Context   Context
	PageToken string
	PageSize  int32
}

// ListPage is one page of releases. No total: no field may express how many a caller cannot see.
type ListPage struct {
	Releases      []Release
	NextPageToken string
}

// Releases is the context's synchronous surface.
type Releases interface {
	Publish(context.Context, PublishRequest) (Release, error)
	Get(context.Context, Context, string) (Release, error)
	List(context.Context, ListQuery) (ListPage, error)
	UpdateNotes(context.Context, Context, string, string) (Release, error)
}
