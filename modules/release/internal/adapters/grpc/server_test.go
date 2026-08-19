package grpc_test

import (
	"context"
	"errors"
	"testing"
	"time"

	releasev1 "github.com/gitfrok/backend/gen/proto/release/v1"
	"github.com/gitfrok/backend/modules/release/api"
	releasegrpc "github.com/gitfrok/backend/modules/release/internal/adapters/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// SPEC-0056 AC2, AC6: the tag is resolved once at publish time and recorded;
// reads return what was recorded and ask git nothing.

type fakeReleases struct {
	published api.PublishRequest
	record    api.Release
	err       error
	gets      int
}

func (f *fakeReleases) Publish(_ context.Context, req api.PublishRequest) (api.Release, error) {
	f.published = req
	if f.err != nil {
		return api.Release{}, f.err
	}
	return api.Release{
		Tag: req.Tag, PublishedCommit: req.PublishedCommit, Notes: req.Notes,
		PublishedBy: req.Context.ActorID, PublishedAt: time.Unix(1755590400, 0).UTC(),
	}, nil
}
func (f *fakeReleases) Get(context.Context, api.Context, string) (api.Release, error) {
	f.gets++
	return f.record, f.err
}
func (f *fakeReleases) List(context.Context, api.ListQuery) (api.ListPage, error) {
	return api.ListPage{Releases: []api.Release{f.record}}, f.err
}
func (f *fakeReleases) UpdateNotes(_ context.Context, _ api.Context, tag, notes string) (api.Release, error) {
	if f.err != nil {
		return api.Release{}, f.err
	}
	r := f.record
	r.Tag, r.Notes, r.NotesUpdatedAt = tag, notes, time.Unix(1755676800, 0).UTC()
	return r, nil
}

type fakeResolver struct {
	commit string
	err    error
	calls  int
	gotTag string
}

func (r *fakeResolver) ResolveTag(_ context.Context, _, _, _ string, _ []string, tag string) (string, error) {
	r.calls++
	r.gotTag = tag
	return r.commit, r.err
}

func rc() *releasev1.ReleaseContext {
	return &releasev1.ReleaseContext{
		TenantId: "t-1", RepositoryId: "repo-1", ActorId: "dev@x", RequestId: "req-1",
		ActorRoles: []string{"member"},
	}
}

func TestPublishResolvesTheTagOnceAndRecordsWhatItResolvedTo(t *testing.T) {
	releases := &fakeReleases{}
	resolver := &fakeResolver{commit: "abc123"}
	srv := releasegrpc.NewServer(releases, resolver)

	got, err := srv.PublishRelease(context.Background(), &releasev1.PublishReleaseRequest{
		Context: rc(), Tag: "v1.0.0", Notes: "what changed",
	})
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if resolver.calls != 1 || resolver.gotTag != "v1.0.0" {
		t.Fatalf("resolver calls=%d tag=%q", resolver.calls, resolver.gotTag)
	}
	if releases.published.PublishedCommit != "abc123" {
		t.Fatalf("recorded %q", releases.published.PublishedCommit)
	}
	if got.GetRelease().GetPublishedCommit() != "abc123" {
		t.Fatalf("returned %+v", got.GetRelease())
	}
}

// AC6: reading does not resolve. A read that asked git what the tag means now
// would defeat the entire point of recording what it meant then.
func TestReadingNeverResolvesTheTag(t *testing.T) {
	resolver := &fakeResolver{commit: "now999"}
	releases := &fakeReleases{record: api.Release{
		Tag: "v1.0.0", PublishedCommit: "then111", PublishedAt: time.Unix(1755590400, 0).UTC(),
	}}
	srv := releasegrpc.NewServer(releases, resolver)

	got, err := srv.GetRelease(context.Background(), &releasev1.GetReleaseRequest{Context: rc(), Tag: "v1.0.0"})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if resolver.calls != 0 {
		t.Fatal("a read resolved the tag — the recorded commit is the answer")
	}
	if got.GetRelease().GetPublishedCommit() != "then111" {
		t.Fatalf("returned %q, want the recorded commit", got.GetRelease().GetPublishedCommit())
	}
}

// A publish that cannot observe the tag records nothing: better no release than
// one describing a commit the platform never saw.
func TestPublishRefusesWhenTheTagCannotBeResolved(t *testing.T) {
	for name, resolver := range map[string]*fakeResolver{
		"error": {err: errors.New("git down")},
		"empty": {commit: ""},
	} {
		releases := &fakeReleases{}
		srv := releasegrpc.NewServer(releases, resolver)
		if _, err := srv.PublishRelease(context.Background(), &releasev1.PublishReleaseRequest{
			Context: rc(), Tag: "v1.0.0",
		}); status.Code(err) != codes.NotFound {
			t.Fatalf("%s: want NotFound, got %v", name, err)
		}
		if releases.published.Tag != "" {
			t.Fatalf("%s: recorded a release anyway", name)
		}
	}
}

func TestPublishRefusesWithNoResolverAtAll(t *testing.T) {
	srv := releasegrpc.NewServer(&fakeReleases{}, nil)
	if _, err := srv.PublishRelease(context.Background(), &releasev1.PublishReleaseRequest{
		Context: rc(), Tag: "v1.0.0",
	}); status.Code(err) != codes.NotFound {
		t.Fatalf("want NotFound, got %v", err)
	}
}

// A duplicate is the one refusal worth distinguishing: it tells a caller their
// request conflicted with a state they can already see.
func TestASecondReleaseOfTheSameTagIsAlreadyExists(t *testing.T) {
	srv := releasegrpc.NewServer(&fakeReleases{err: api.ErrAlreadyPublished}, &fakeResolver{commit: "abc"})
	_, err := srv.PublishRelease(context.Background(), &releasev1.PublishReleaseRequest{Context: rc(), Tag: "v1.0.0"})
	if status.Code(err) != codes.AlreadyExists {
		t.Fatalf("want AlreadyExists, got %v", err)
	}
}

func TestEveryOtherFailureIsTheOneCoarseRefusal(t *testing.T) {
	srv := releasegrpc.NewServer(&fakeReleases{err: errors.New("store down")}, &fakeResolver{commit: "abc"})
	for name, call := range map[string]func() error{
		"get": func() error {
			_, e := srv.GetRelease(context.Background(), &releasev1.GetReleaseRequest{Context: rc(), Tag: "v1"})
			return e
		},
		"list": func() error {
			_, e := srv.ListReleases(context.Background(), &releasev1.ListReleasesRequest{Context: rc()})
			return e
		},
		"notes": func() error {
			_, e := srv.UpdateReleaseNotes(context.Background(), &releasev1.UpdateReleaseNotesRequest{Context: rc(), Tag: "v1"})
			return e
		},
	} {
		if err := call(); status.Code(err) != codes.NotFound {
			t.Fatalf("%s: want NotFound, got %v", name, err)
		}
	}
}

func TestARequestWithoutAVerifiedCallerIsRefused(t *testing.T) {
	srv := releasegrpc.NewServer(&fakeReleases{}, &fakeResolver{commit: "abc"})
	for name, ctxMsg := range map[string]*releasev1.ReleaseContext{
		"nil":       nil,
		"no tenant": {RepositoryId: "r", ActorId: "a"},
		"no repo":   {TenantId: "t", ActorId: "a"},
		"no actor":  {TenantId: "t", RepositoryId: "r"},
	} {
		if _, err := srv.GetRelease(context.Background(), &releasev1.GetReleaseRequest{Context: ctxMsg, Tag: "v1"}); status.Code(err) != codes.NotFound {
			t.Fatalf("%s: want NotFound, got %v", name, err)
		}
	}
}

// An unedited release reports no edit time rather than the zero instant.
func TestAnUneditedReleaseReportsNoEditTime(t *testing.T) {
	srv := releasegrpc.NewServer(&fakeReleases{record: api.Release{
		Tag: "v1.0.0", PublishedCommit: "abc", PublishedAt: time.Unix(1755590400, 0).UTC(),
	}}, &fakeResolver{commit: "abc"})
	got, err := srv.GetRelease(context.Background(), &releasev1.GetReleaseRequest{Context: rc(), Tag: "v1.0.0"})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.GetRelease().GetNotesUpdatedAt() != "" {
		t.Fatalf("reported an edit time of %q on an unedited release", got.GetRelease().GetNotesUpdatedAt())
	}
}

// The contract must carry no artifact anywhere, asserted on the descriptor.
func TestTheReleaseMessageCarriesNoArtifact(t *testing.T) {
	fields := (&releasev1.Release{}).ProtoReflect().Descriptor().Fields()
	for i := 0; i < fields.Len(); i++ {
		switch name := string(fields.Get(i).Name()); name {
		case "tag", "published_commit", "notes", "published_by", "published_at", "notes_updated_at":
		default:
			t.Fatalf("Release carries %q — artifacts are outside ADR-0075's accepted increment", name)
		}
	}
}
