// The repocontent adapter's claim is that Code Search reaches repository content ONLY through
// the RepositoryReader contract — GetTree for the listing, GetFile for the bytes (SPEC-0035
// AC7, ADR-0022). These tests drive the adapter through that contract's client interface with a
// fake, so the only way content can arrive here is the contract's own messages.
package repocontent

import (
	"context"
	"errors"
	"io"
	"testing"

	repositoryv1 "github.com/gitfrok/backend/gen/proto/repository/v1"
	"google.golang.org/grpc"
)

// fakeStream is a client-side GetFile stream backed by a fixed chunk list.
type fakeStream struct {
	grpc.ClientStream
	chunks []*repositoryv1.FileChunk
	idx    int
	err    error
}

func (s *fakeStream) Recv() (*repositoryv1.FileChunk, error) {
	if s.err != nil {
		return nil, s.err
	}
	if s.idx >= len(s.chunks) {
		return nil, io.EOF
	}
	c := s.chunks[s.idx]
	s.idx++
	return c, nil
}

// fakeReader records the requests and answers GetTree/GetFile from canned data, so a test can
// assert the adapter asked through the contract and only through it.
type fakeReader struct {
	treePages map[string][]*repositoryv1.GetTreeResponse // key: repo@revision
	fileData  map[string][]*repositoryv1.FileChunk       // key: repo@revision@path
	treeCalls []*repositoryv1.GetTreeRequest
	fileCalls []*repositoryv1.GetFileRequest
	streamErr error
}

func key(t, r, rev string) string { return t + "/" + r + "@" + rev }

func (f *fakeReader) GetTree(_ context.Context, in *repositoryv1.GetTreeRequest, _ ...grpc.CallOption) (*repositoryv1.GetTreeResponse, error) {
	f.treeCalls = append(f.treeCalls, in)
	k := key(in.GetContext().GetTenantId(), in.GetContext().GetRepositoryId(), in.GetRevision())
	pages := f.treePages[k]
	token := 0
	if in.GetPageToken() != "" {
		for _, c := range in.GetPageToken() {
			token = token*10 + int(c-'0')
		}
	}
	if token >= len(pages) {
		return &repositoryv1.GetTreeResponse{}, nil
	}
	// Build a fresh response rather than copying the canned one: proto messages carry a lock.
	out := &repositoryv1.GetTreeResponse{Entries: pages[token].GetEntries()}
	if token+1 < len(pages) {
		out.NextPageToken = string(rune('0' + token + 1))
	}
	return out, nil
}

func (f *fakeReader) GetFile(_ context.Context, in *repositoryv1.GetFileRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[repositoryv1.FileChunk], error) {
	f.fileCalls = append(f.fileCalls, in)
	if f.streamErr != nil {
		return nil, f.streamErr
	}
	k := key(in.GetContext().GetTenantId(), in.GetContext().GetRepositoryId(), in.GetRevision()) + "/" + in.GetPath()
	chunks, ok := f.fileData[k]
	if !ok {
		return nil, errors.New("no such file")
	}
	return &fakeStream{chunks: chunks}, nil
}

// GetDiff completes the contract interface; Code Search never calls it.
func (f *fakeReader) GetDiff(context.Context, *repositoryv1.GetDiffRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[repositoryv1.DiffChunk], error) {
	return nil, errors.New("repocontent: GetDiff is not a code-search route")
}

// GetMergeBase completes the contract interface; Code Search never calls it.
func (f *fakeReader) GetMergeBase(context.Context, *repositoryv1.GetMergeBaseRequest, ...grpc.CallOption) (*repositoryv1.GetMergeBaseResponse, error) {
	return nil, errors.New("repocontent: GetMergeBase is not a code-search route")
}

func (f *fakeReader) GetHistory(context.Context, *repositoryv1.GetHistoryRequest, ...grpc.CallOption) (*repositoryv1.GetHistoryResponse, error) {
	return nil, errors.New("repocontent: GetHistory is not a code-search route")
}

func (f *fakeReader) GetBlame(context.Context, *repositoryv1.GetBlameRequest, ...grpc.CallOption) (*repositoryv1.GetBlameResponse, error) {
	return nil, errors.New("repocontent: GetBlame is not a code-search route")
}

func entry(kind repositoryv1.EntryKind, path string, size int64) *repositoryv1.TreeEntry {
	return &repositoryv1.TreeEntry{Kind: kind, Path: path, SizeBytes: size}
}

// ListFiles walks every tree page and returns only regular files: directories and symlinks are
// not content the index may follow (a symlink could point outside the revision).
func TestListFilesPagesAndFiltersToRegularFiles(t *testing.T) {
	f := &fakeReader{
		treePages: map[string][]*repositoryv1.GetTreeResponse{
			key("t-1", "repo-1", "rev-1"): {
				{Entries: []*repositoryv1.TreeEntry{
					entry(repositoryv1.EntryKind_ENTRY_KIND_FILE, "a.go", 10),
					entry(repositoryv1.EntryKind_ENTRY_KIND_DIRECTORY, "dir", 0),
				}},
				{Entries: []*repositoryv1.TreeEntry{
					entry(repositoryv1.EntryKind_ENTRY_KIND_SYMLINK, "link", 0),
					entry(repositoryv1.EntryKind_ENTRY_KIND_FILE, "b.go", 20),
				}},
			},
		},
	}
	g := NewGRPC(f)
	files, err := g.ListFiles(context.Background(), "t-1", "repo-1", "rev-1")
	if err != nil {
		t.Fatalf("ListFiles: %v", err)
	}
	if len(files) != 2 {
		t.Fatalf("want only the two regular files, got %+v", files)
	}
	byPath := map[string]int64{}
	for _, fe := range files {
		byPath[fe.Path] = fe.SizeBytes
	}
	if byPath["a.go"] != 10 || byPath["b.go"] != 20 {
		t.Fatalf("want a.go=10 b.go=20, got %+v", byPath)
	}
	// The adapter asked through the contract, tenant- and revision-scoped, paging until empty.
	if len(f.treeCalls) != 2 {
		t.Fatalf("want two tree pages, got %d", len(f.treeCalls))
	}
	for _, c := range f.treeCalls {
		if c.GetContext().GetTenantId() != "t-1" || c.GetContext().GetRepositoryId() != "repo-1" ||
			c.GetRevision() != "rev-1" {
			t.Fatalf("tree call must carry the verified read context: %+v", c)
		}
	}
}

// ReadFile assembles the streamed chunks into the file's bytes, stopping at EOF.
func TestReadFileAssemblesStreamedChunks(t *testing.T) {
	f := &fakeReader{
		fileData: map[string][]*repositoryv1.FileChunk{
			key("t-1", "repo-1", "rev-1") + "/a.go": {
				{Data: []byte("package ")},
				{Data: []byte("main\n"), Eof: true},
			},
		},
	}
	g := NewGRPC(f)
	got, err := g.ReadFile(context.Background(), "t-1", "repo-1", "rev-1", "a.go")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "package main\n" {
		t.Fatalf("want the assembled bytes, got %q", got)
	}
	if len(f.fileCalls) != 1 {
		t.Fatalf("want one file call, got %d", len(f.fileCalls))
	}
	c := f.fileCalls[0]
	if c.GetContext().GetTenantId() != "t-1" || c.GetContext().GetRepositoryId() != "repo-1" ||
		c.GetRevision() != "rev-1" || c.GetPath() != "a.go" {
		t.Fatalf("file call must carry the verified read context and path: %+v", c)
	}
}

// ReadFile also stops cleanly when the stream reports EOF without an explicit eof chunk.
func TestReadFileStopsOnStreamEOF(t *testing.T) {
	f := &fakeReader{
		fileData: map[string][]*repositoryv1.FileChunk{
			key("t-1", "repo-1", "rev-1") + "/a.go": {
				{Data: []byte("only-chunk")},
			},
		},
	}
	g := NewGRPC(f)
	got, err := g.ReadFile(context.Background(), "t-1", "repo-1", "rev-1", "a.go")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "only-chunk" {
		t.Fatalf("want the single chunk, got %q", got)
	}
}

// Contract failures surface as errors the indexer treats as skip-this-revision, never a panic.
func TestContractErrorsPropagate(t *testing.T) {
	f := &fakeReader{streamErr: errors.New("reader: unavailable")}
	g := NewGRPC(f)
	if _, err := g.ReadFile(context.Background(), "t-1", "repo-1", "rev-1", "a.go"); err == nil {
		t.Fatal("a failed stream open must propagate")
	}
	if _, err := g.ListFiles(context.Background(), "t-1", "missing", "rev-1"); err != nil {
		t.Fatalf("an empty tree is a valid empty listing, got %v", err)
	}
}
