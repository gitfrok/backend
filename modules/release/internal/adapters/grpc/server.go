// Package grpc adapts the Release context to its contract (T-0064, SPEC-0056).
//
// The one piece of judgement here is where a tag becomes a commit. The Release context may not
// depend on Repository/Git (ADR-0022), so it never resolves a tag — it is handed one already
// resolved. This adapter holds the TagResolver the composition root supplies, resolves at publish
// time, and records the answer.
package grpc

import (
	"context"
	"errors"

	releasev1 "github.com/gitfrok/backend/gen/proto/release/v1"
	"github.com/gitfrok/backend/modules/release/api"
	"github.com/gitfrok/backend/platform/tenancy"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TagResolver answers what a tag points at right now. It is satisfied by a Repository/Git client in
// the composition root; this package names the need without naming that context.
type TagResolver interface {
	ResolveTag(ctx context.Context, tenantID, repositoryID, actorID string, actorRoles []string, tag string) (string, error)
}

// Server is the gRPC adapter.
type Server struct {
	releasev1.UnimplementedReleaseServiceServer
	releases api.Releases
	tags     TagResolver
}

// NewServer builds the adapter. A nil resolver means this deployment cannot publish — publishing
// refuses rather than recording a commit it did not observe.
func NewServer(releases api.Releases, tags TagResolver) *Server {
	return &Server{releases: releases, tags: tags}
}

// denial is the one coarse refusal. Absent, cross-tenant and unauthorized reach it identically.
func denial() error { return status.Error(codes.NotFound, "release: unavailable") }

func contextOf(rc *releasev1.ReleaseContext) (api.Context, bool) {
	if rc == nil || rc.GetTenantId() == "" || rc.GetRepositoryId() == "" || rc.GetActorId() == "" {
		return api.Context{}, false
	}
	return api.Context{
		TenantID: rc.GetTenantId(), RepositoryID: rc.GetRepositoryId(),
		ActorID: rc.GetActorId(), RequestID: rc.GetRequestId(), ActorRoles: rc.GetActorRoles(),
	}, true
}

func view(r api.Release) *releasev1.Release {
	out := &releasev1.Release{
		Tag: r.Tag, PublishedCommit: r.PublishedCommit, Notes: r.Notes,
		PublishedBy: r.PublishedBy, PublishedAt: r.PublishedAt.UTC().Format(rfc3339),
	}
	// Empty until the notes are first edited — never the zero instant, which would put 1970 on a
	// record that has simply never been corrected.
	if !r.NotesUpdatedAt.IsZero() {
		out.NotesUpdatedAt = r.NotesUpdatedAt.UTC().Format(rfc3339)
	}
	return out
}

const rfc3339 = "2006-01-02T15:04:05Z07:00"

// PublishRelease resolves the tag, then records what it resolved to.
func (s *Server) PublishRelease(ctx context.Context, req *releasev1.PublishReleaseRequest) (*releasev1.PublishReleaseResponse, error) {
	rc, ok := contextOf(req.GetContext())
	if !ok {
		return nil, denial()
	}
	if s.tags == nil {
		return nil, denial()
	}
	ctx = tenancy.WithTenant(ctx, tenancy.ID(rc.TenantID))

	// Resolved here, once, at publish time. This is the instant the platform observed what the tag
	// meant, and every later reading is a comparison against it.
	commit, err := s.tags.ResolveTag(ctx, rc.TenantID, rc.RepositoryID, rc.ActorID, rc.ActorRoles, req.GetTag())
	if err != nil || commit == "" {
		return nil, denial()
	}

	record, err := s.releases.Publish(ctx, api.PublishRequest{
		Context: rc, Tag: req.GetTag(), Notes: req.GetNotes(), PublishedCommit: commit,
	})
	if err != nil {
		// A second release of the same tag is the one refusal worth distinguishing: it tells a
		// caller their request conflicted with a state they can see, which is not a disclosure.
		if errors.Is(err, api.ErrAlreadyPublished) {
			return nil, status.Error(codes.AlreadyExists, "release: this tag already has a release")
		}
		return nil, denial()
	}
	return &releasev1.PublishReleaseResponse{Release: view(record)}, nil
}

// GetRelease returns the record as recorded. It does not ask what the tag means now.
func (s *Server) GetRelease(ctx context.Context, req *releasev1.GetReleaseRequest) (*releasev1.GetReleaseResponse, error) {
	rc, ok := contextOf(req.GetContext())
	if !ok {
		return nil, denial()
	}
	ctx = tenancy.WithTenant(ctx, tenancy.ID(rc.TenantID))
	record, err := s.releases.Get(ctx, rc, req.GetTag())
	if err != nil {
		return nil, denial()
	}
	return &releasev1.GetReleaseResponse{Release: view(record)}, nil
}

// ListReleases pages a repository's releases, newest first.
func (s *Server) ListReleases(ctx context.Context, req *releasev1.ListReleasesRequest) (*releasev1.ListReleasesResponse, error) {
	rc, ok := contextOf(req.GetContext())
	if !ok {
		return nil, denial()
	}
	ctx = tenancy.WithTenant(ctx, tenancy.ID(rc.TenantID))
	page, err := s.releases.List(ctx, api.ListQuery{
		Context: rc, PageToken: req.GetPageToken(), PageSize: req.GetPageSize(),
	})
	if err != nil {
		return nil, denial()
	}
	out := &releasev1.ListReleasesResponse{
		Releases:      make([]*releasev1.Release, 0, len(page.Releases)),
		NextPageToken: page.NextPageToken,
	}
	for _, r := range page.Releases {
		out.Releases = append(out.Releases, view(r))
	}
	return out, nil
}

// UpdateReleaseNotes corrects the prose. There is no method that moves a release.
func (s *Server) UpdateReleaseNotes(ctx context.Context, req *releasev1.UpdateReleaseNotesRequest) (*releasev1.UpdateReleaseNotesResponse, error) {
	rc, ok := contextOf(req.GetContext())
	if !ok {
		return nil, denial()
	}
	ctx = tenancy.WithTenant(ctx, tenancy.ID(rc.TenantID))
	record, err := s.releases.UpdateNotes(ctx, rc, req.GetTag(), req.GetNotes())
	if err != nil {
		return nil, denial()
	}
	return &releasev1.UpdateReleaseNotesResponse{Release: view(record)}, nil
}
