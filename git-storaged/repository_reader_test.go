package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	repositoryv1 "github.com/gitfrok/backend/gen/proto/repository/v1"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
	"github.com/gitfrok/backend/platform/bus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func TestRepositoryReaderPaginatesTreeAndStreamsFileAndDiff(t *testing.T) {
	root, tenantID, repositoryID, base := seededRepository(t)
	bare := filepath.Join(root, tenantID, repositoryID+".git")
	work := t.TempDir()
	mustRunGit(t, work, "clone", "--branch", "main", bare, ".")
	mustRunGit(t, work, "config", "user.email", "dev@gitsaas.test")
	mustRunGit(t, work, "config", "user.name", "GitFrok test")
	if err := os.WriteFile(filepath.Join(work, "SECOND.md"), []byte("second\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	large := bytes.Repeat([]byte("x"), readChunkSize+31)
	if err := os.WriteFile(filepath.Join(work, "LARGE.bin"), large, 0o600); err != nil {
		t.Fatal(err)
	}
	mustRunGit(t, work, "add", "SECOND.md", "LARGE.bin")
	mustRunGit(t, work, "commit", "-m", "second")
	mustRunGit(t, work, "push", "origin", "HEAD:main")
	head := mustGitOutput(t, work, "rev-parse", "HEAD")

	client, closeClient := newReaderClient(t, root, allowPDP{})
	defer closeClient()
	ctx := readContext(tenantID, repositoryID)
	first, err := client.GetTree(context.Background(), &repositoryv1.GetTreeRequest{Context: ctx, Revision: head, PageSize: 1})
	if err != nil || len(first.GetEntries()) != 1 || first.GetNextPageToken() == "" {
		t.Fatalf("first tree page = %#v, %v", first, err)
	}
	second, err := client.GetTree(context.Background(), &repositoryv1.GetTreeRequest{Context: ctx, Revision: head, PageSize: 1, PageToken: first.GetNextPageToken()})
	if err != nil || len(second.GetEntries()) != 1 {
		t.Fatalf("second tree page = %#v, %v", second, err)
	}
	if _, err := client.GetTree(context.Background(), &repositoryv1.GetTreeRequest{Context: ctx, Revision: head, PageToken: "forged"}); status.Code(err) != codes.NotFound {
		t.Fatalf("forged token error = %v", err)
	}

	file, err := client.GetFile(context.Background(), &repositoryv1.GetFileRequest{Context: ctx, Revision: head, Path: "LARGE.bin"})
	if err != nil {
		t.Fatal(err)
	}
	var content bytes.Buffer
	metadataCount := 0
	for {
		chunk, recvErr := file.Recv()
		if errors.Is(recvErr, io.EOF) {
			break
		}
		if recvErr != nil {
			t.Fatal(recvErr)
		}
		if chunk.GetMetadata() != nil {
			metadataCount++
			if chunk.GetMetadata().GetPath() != "LARGE.bin" || chunk.GetMetadata().GetSizeBytes() != int64(len(large)) {
				t.Fatalf("file metadata = %#v", chunk.GetMetadata())
			}
		}
		if len(chunk.GetData()) > readChunkSize {
			t.Fatalf("chunk = %d bytes, want <= %d", len(chunk.GetData()), readChunkSize)
		}
		content.Write(chunk.GetData())
		if chunk.GetEof() {
			break
		}
	}
	if metadataCount != 1 || !bytes.Equal(content.Bytes(), large) {
		t.Fatalf("file metadata count=%d bytes=%d", metadataCount, content.Len())
	}

	diff, err := client.GetDiff(context.Background(), &repositoryv1.GetDiffRequest{Context: ctx, BaseRevision: base, HeadRevision: head})
	if err != nil {
		t.Fatal(err)
	}
	var patch bytes.Buffer
	for {
		chunk, recvErr := diff.Recv()
		if errors.Is(recvErr, io.EOF) {
			break
		}
		if recvErr != nil {
			t.Fatal(recvErr)
		}
		patch.Write(chunk.GetData())
		if chunk.GetEof() {
			break
		}
	}
	if !bytes.Contains(patch.Bytes(), []byte("SECOND.md")) {
		t.Fatalf("diff does not contain changed file: %q", patch.Bytes())
	}
}

func TestRepositoryReaderWrongTenantSendsNoContent(t *testing.T) {
	root, _, repositoryID, head := seededRepository(t)
	called := false
	client, closeClient := newReaderClientWithConfig(t, Config{RepositoryRoot: root, PDP: allowPDP{}, Events: bus.NewInProcess(), command: func(context.Context, string, ...string) *exec.Cmd {
		called = true
		return exec.Command("false")
	}})
	defer closeClient()
	_, err := client.GetTree(context.Background(), &repositoryv1.GetTreeRequest{Context: readContext("tenant-b", repositoryID), Revision: head})
	if status.Code(err) != codes.NotFound || called {
		t.Fatalf("wrong-tenant error=%v command-started=%t", err, called)
	}
}

func newReaderClient(t *testing.T, root string, pdp policyapi.DecisionPoint) (repositoryv1.RepositoryReaderClient, func()) {
	t.Helper()
	return newReaderClientWithConfig(t, Config{RepositoryRoot: root, PDP: pdp, Events: bus.NewInProcess(), command: testGitCommand})
}

func newReaderClientWithConfig(t *testing.T, config Config) (repositoryv1.RepositoryReaderClient, func()) {
	t.Helper()
	server, err := NewServer(config)
	if err != nil {
		t.Fatal(err)
	}
	listener := bufconn.Listen(1 << 20)
	grpcServer := grpc.NewServer()
	repositoryv1.RegisterRepositoryReaderServer(grpcServer, server)
	go func() { _ = grpcServer.Serve(listener) }()
	conn, err := grpc.NewClient("passthrough:///repository-reader", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }), grpc.WithInsecure())
	if err != nil {
		t.Fatal(err)
	}
	return repositoryv1.NewRepositoryReaderClient(conn), func() { _ = conn.Close(); grpcServer.Stop(); _ = listener.Close() }
}

func readContext(tenantID, repositoryID string) *repositoryv1.ReadContext {
	return &repositoryv1.ReadContext{TenantId: tenantID, RepositoryId: repositoryID, ActorId: "actor-a", RequestId: "request-" + time.Now().UTC().Format("150405.000000000")}
}
