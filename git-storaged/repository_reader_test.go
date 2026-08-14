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
	"github.com/gitfrok/backend/modules/repository"
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
	first, err := client.GetTree(t.Context(), &repositoryv1.GetTreeRequest{Context: ctx, Revision: head, PageSize: 1})
	if err != nil || len(first.GetEntries()) != 1 || first.GetNextPageToken() == "" {
		t.Fatalf("first tree page = %#v, %v", first, err)
	}
	second, err := client.GetTree(t.Context(), &repositoryv1.GetTreeRequest{Context: ctx, Revision: head, PageSize: 1, PageToken: first.GetNextPageToken()})
	if err != nil || len(second.GetEntries()) != 1 {
		t.Fatalf("second tree page = %#v, %v", second, err)
	}
	if _, err := client.GetTree(t.Context(), &repositoryv1.GetTreeRequest{Context: ctx, Revision: head, PageToken: "forged"}); status.Code(err) != codes.NotFound {
		t.Fatalf("forged token error = %v", err)
	}

	file, err := client.GetFile(t.Context(), &repositoryv1.GetFileRequest{Context: ctx, Revision: head, Path: "LARGE.bin"})
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

	diff, err := client.GetDiff(t.Context(), &repositoryv1.GetDiffRequest{Context: ctx, BaseRevision: base, HeadRevision: head})
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

func TestRepositoryReaderGetMergeBase(t *testing.T) {
	root, tenantID, repositoryID, head := seededRepository(t)
	bare := filepath.Join(root, tenantID, repositoryID+".git")
	work := t.TempDir()
	mustRunGit(t, work, "clone", "--branch", "main", bare, ".")
	mustRunGit(t, work, "config", "user.email", "dev@gitsaas.test")
	mustRunGit(t, work, "config", "user.name", "GitFrok test")

	// A feature branch advancing away from main: the merge base is main's head.
	mustRunGit(t, work, "checkout", "-b", "feature")
	if err := os.WriteFile(filepath.Join(work, "FEATURE.md"), []byte("feature\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	mustRunGit(t, work, "add", "FEATURE.md")
	mustRunGit(t, work, "commit", "-m", "feature")
	mustRunGit(t, work, "push", "origin", "HEAD:refs/heads/feature")

	// An orphan branch sharing no history with main.
	mustRunGit(t, work, "checkout", "main")
	mustRunGit(t, work, "checkout", "--orphan", "lonely")
	mustRunGit(t, work, "rm", "-rf", ".")
	if err := os.WriteFile(filepath.Join(work, "LONELY.md"), []byte("lonely\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	mustRunGit(t, work, "add", "LONELY.md")
	mustRunGit(t, work, "commit", "-m", "lonely")
	mustRunGit(t, work, "push", "origin", "HEAD:refs/heads/lonely")

	client, closeClient := newReaderClient(t, root, allowPDP{})
	defer closeClient()
	ctx := readContext(tenantID, repositoryID)

	// The common ancestor of feature and main is main's head.
	resp, err := client.GetMergeBase(t.Context(), &repositoryv1.GetMergeBaseRequest{Context: ctx, RefA: "refs/heads/feature", RefB: "refs/heads/main"})
	if err != nil || !resp.GetFound() || resp.GetMergeBase() != head {
		t.Fatalf("merge base = %#v, %v, want found=%t base=%s", resp, err, true, head)
	}

	// No common ancestor is an answered question, not an error.
	resp, err = client.GetMergeBase(t.Context(), &repositoryv1.GetMergeBaseRequest{Context: ctx, RefA: "refs/heads/lonely", RefB: "refs/heads/main"})
	if err != nil || resp.GetFound() || resp.GetMergeBase() != "" {
		t.Fatalf("unrelated merge base = %#v, %v, want found=false", resp, err)
	}

	// An invalid ref is refused before Git starts, with the coarse refusal.
	if _, err := client.GetMergeBase(t.Context(), &repositoryv1.GetMergeBaseRequest{Context: ctx, RefA: "refs/heads/main", RefB: "refs/heads/../escape"}); status.Code(err) != codes.NotFound {
		t.Fatalf("invalid ref error = %v", err)
	}
	// A ref that does not exist reads as unavailable, same as every other refusal.
	if _, err := client.GetMergeBase(t.Context(), &repositoryv1.GetMergeBaseRequest{Context: ctx, RefA: "refs/heads/absent", RefB: "refs/heads/main"}); status.Code(err) != codes.NotFound {
		t.Fatalf("absent ref error = %v", err)
	}
}

func TestRepositoryReaderGetMergeBaseWrongTenantNeverStartsGit(t *testing.T) {
	root, _, repositoryID, head := seededRepository(t)
	called := false
	client, closeClient := newReaderClientWithConfig(t, Config{RepositoryRoot: root, PDP: allowPDP{}, Events: bus.NewInProcess(), command: func(context.Context, string, ...string) *exec.Cmd {
		called = true
		return exec.Command("false")
	}})
	defer closeClient()
	_, err := client.GetMergeBase(t.Context(), &repositoryv1.GetMergeBaseRequest{Context: readContext("tenant-b", repositoryID), RefA: head, RefB: head})
	if status.Code(err) != codes.NotFound || called {
		t.Fatalf("wrong-tenant error=%v command-started=%t", err, called)
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
	_, err := client.GetTree(t.Context(), &repositoryv1.GetTreeRequest{Context: readContext("tenant-b", repositoryID), Revision: head})
	if status.Code(err) != codes.NotFound || called {
		t.Fatalf("wrong-tenant error=%v command-started=%t", err, called)
	}
}

func TestRepositoryReaderPDPDenialSendsNoFileContent(t *testing.T) {
	root, tenantID, repositoryID, head := seededRepository(t)
	called := false
	client, closeClient := newReaderClientWithConfig(t, Config{RepositoryRoot: root, PDP: denyPDP{}, Events: bus.NewInProcess(), command: func(context.Context, string, ...string) *exec.Cmd {
		called = true
		return exec.Command("false")
	}})
	defer closeClient()

	stream, err := client.GetFile(t.Context(), &repositoryv1.GetFileRequest{Context: readContext(tenantID, repositoryID), Revision: head, Path: "README.md"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = stream.Recv()
	if status.Code(err) != codes.NotFound || called {
		t.Fatalf("PDP denial error=%v command-started=%t", err, called)
	}
}

type denyPDP struct{}

func (denyPDP) Decide(context.Context, policyapi.Request) (policyapi.Decision, error) {
	return policyapi.Decision{}, nil
}

func newReaderClient(t *testing.T, root string, pdp policyapi.DecisionPoint) (repositoryv1.RepositoryReaderClient, func()) {
	t.Helper()
	return newReaderClientWithConfig(t, Config{RepositoryRoot: root, PDP: pdp, Events: bus.NewInProcess(), command: testGitCommand})
}

func newReaderClientWithConfig(t *testing.T, config Config) (repositoryv1.RepositoryReaderClient, func()) {
	t.Helper()
	if config.Coordinator == nil {
		config.Coordinator = repository.NewInMemoryCoordinator(testNodeID, config.Events)
	}
	if config.NodeID == "" {
		config.NodeID = testNodeID
	}
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
