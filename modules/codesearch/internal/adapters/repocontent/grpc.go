// Package repocontent adapts the Repository/Git contract surface to the Code Search context's
// ContentSource port. It is the module's one route to repository content — GetTree and GetFile
// over the RepositoryReader service (SPEC-0035 assumption, satisfied without a new repository
// RPC) — never Git storage directly and never another context's tables (ADR-0022, SPEC-0035
// AC7). The boundary test at the module root holds this package to that claim.
package repocontent

import (
	"context"
	"io"

	repositoryv1 "github.com/gitfrok/backend/gen/proto/repository/v1"
	"github.com/gitfrok/backend/modules/codesearch/api"
)

// treePageSize is one bounded tree page; the contract pages, so the adapter follows.
const treePageSize = 1000

// GRPC fetches repository content through the RepositoryReader contract.
type GRPC struct {
	client repositoryv1.RepositoryReaderClient
}

// NewGRPC builds the adapter over the contract client.
func NewGRPC(client repositoryv1.RepositoryReaderClient) *GRPC { return &GRPC{client: client} }

// ListFiles walks every tree page at the revision and returns the regular files. Directories
// and symlinks are not content the index may follow: a symlink could point outside the
// repository, and indexing where it points would serve content the revision does not contain.
func (g *GRPC) ListFiles(ctx context.Context, tenantID, repoID, revision string) ([]api.FileEntry, error) {
	var out []api.FileEntry
	token := ""
	for {
		resp, err := g.client.GetTree(ctx, &repositoryv1.GetTreeRequest{
			Context:   &repositoryv1.ReadContext{TenantId: tenantID, RepositoryId: repoID},
			Revision:  revision,
			PageToken: token,
			PageSize:  treePageSize,
		})
		if err != nil {
			return nil, err
		}
		for _, e := range resp.GetEntries() {
			if e.GetKind() == repositoryv1.EntryKind_ENTRY_KIND_FILE {
				out = append(out, api.FileEntry{Path: e.GetPath(), SizeBytes: e.GetSizeBytes()})
			}
		}
		token = resp.GetNextPageToken()
		if token == "" {
			return out, nil
		}
	}
}

// ReadFile streams one file's chunks at the revision and returns the assembled bytes.
func (g *GRPC) ReadFile(ctx context.Context, tenantID, repoID, revision, path string) ([]byte, error) {
	stream, err := g.client.GetFile(ctx, &repositoryv1.GetFileRequest{
		Context:  &repositoryv1.ReadContext{TenantId: tenantID, RepositoryId: repoID},
		Revision: revision,
		Path:     path,
	})
	if err != nil {
		return nil, err
	}
	var buf []byte
	for {
		chunk, err := stream.Recv()
		if err == io.EOF {
			return buf, nil
		}
		if err != nil {
			return nil, err
		}
		if len(chunk.GetData()) > 0 {
			buf = append(buf, chunk.GetData()...)
		}
		if chunk.GetEof() {
			return buf, nil
		}
	}
}

var _ api.ContentSource = (*GRPC)(nil)
