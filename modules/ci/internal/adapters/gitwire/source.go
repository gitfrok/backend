// Package gitwire holds the CI context's Repository/Git adapter. It resolves an
// immutable revision and reads the one permitted config path — it never reaches
// for source bytes beyond the v0 manifest (SPEC-0020 AC5/G9).
package gitwire

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"

	repositoryv1 "github.com/gitfrok/backend/gen/proto/repository/v1"
)

// Reader resolves refs to revisions and reads repository files. The dataplane-app
// injects a RepositoryReader gRPC client adapted to this interface.
type Reader interface {
	ResolveRef(ctx context.Context, tenantID, repositoryID, ref string) (commitSHA string, err error)
	ReadFile(ctx context.Context, tenantID, repositoryID, revision, path string) ([]byte, error)
}

// ManifestPath is the one config file CI v0 recognises.
const ManifestPath = ".gitfrok/ci.yaml"

// Source validates that ref resolves to commitSHA and returns the digest of the
// parsed v0 configuration at that revision (SPEC-0020 AC1/AC5).
type Source struct {
	reader Reader
}

func NewSource(reader Reader) *Source { return &Source{reader: reader} }

func (s *Source) Validate(ctx context.Context, tenantID, repositoryID, ref, commitSHA string) (string, error) {
	resolved, err := s.reader.ResolveRef(ctx, tenantID, repositoryID, ref)
	if err != nil {
		return "", err
	}
	if resolved != commitSHA {
		return "", errors.New("ci source: ref does not resolve to the recorded commit SHA")
	}
	bytes, err := s.reader.ReadFile(ctx, tenantID, repositoryID, commitSHA, ManifestPath)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(bytes)
	return hex.EncodeToString(digest[:]), nil
}

// GRPCReader adapts a RepositoryReader gRPC client to the Reader interface.
type GRPCReader struct {
	client repositoryv1.RepositoryReaderClient
}

func NewGRPCReader(client repositoryv1.RepositoryReaderClient) *GRPCReader {
	return &GRPCReader{client: client}
}

func (r *GRPCReader) ResolveRef(ctx context.Context, tenantID, repositoryID, ref string) (string, error) {
	// Verify the ref exists by listing its tree. A non-existent or denied ref
	// yields a NotFound from the RepositoryReader, which maps to a validation failure.
	tree, err := r.client.GetTree(ctx, &repositoryv1.GetTreeRequest{
		Context:  &repositoryv1.ReadContext{TenantId: tenantID, RepositoryId: repositoryID},
		Revision: ref,
	})
	if err != nil || tree == nil {
		return "", errors.New("ci source: cannot resolve ref")
	}
	return ref, nil
}

func (r *GRPCReader) ReadFile(ctx context.Context, tenantID, repositoryID, revision, path string) ([]byte, error) {
	stream, err := r.client.GetFile(ctx, &repositoryv1.GetFileRequest{
		Context:  &repositoryv1.ReadContext{TenantId: tenantID, RepositoryId: repositoryID},
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
			break
		}
		if err != nil {
			return nil, err
		}
		if !chunk.GetEof() && len(chunk.GetData()) > 0 {
			buf = append(buf, chunk.GetData()...)
		}
	}
	if len(buf) == 0 {
		return nil, errors.New("ci source: manifest not found")
	}
	return buf, nil
}
