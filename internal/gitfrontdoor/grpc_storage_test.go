package gitfrontdoor

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"

	gitv1 "github.com/gitfrok/backend/gen/proto/git/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
)

type echoStorageServer struct {
	gitv1.UnimplementedGitStorageServer
	context *gitv1.OperationContext
}

func (s *echoStorageServer) UploadPack(stream gitv1.GitStorage_UploadPackServer) error {
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	s.context = first.GetContext()
	for {
		request, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if request.GetClose() {
			return nil
		}
		if data := request.GetData(); len(data) > 0 {
			if err := stream.Send(&gitv1.UploadPackResponse{Data: append([]byte("reply:"), data...)}); err != nil {
				return err
			}
		}
	}
}

func TestGRPCStorageStreamsContextThenChunksBidirectionally(t *testing.T) {
	server := &echoStorageServer{}
	listener := bufconn.Listen(1 << 20)
	grpcServer := grpc.NewServer()
	gitv1.RegisterGitStorageServer(grpcServer, server)
	go func() { _ = grpcServer.Serve(listener) }()
	defer grpcServer.Stop()
	defer listener.Close()

	connection, err := grpc.NewClient("passthrough:///git-storage", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
		return listener.Dial()
	}), grpc.WithInsecure())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()

	storage := GRPCStorage{Client: gitv1.NewGitStorageClient(connection)}
	var output bytes.Buffer
	operation := &gitv1.OperationContext{TenantId: "tenant-a", RepositoryId: "repo-a", ActorId: "actor-a", RequestId: "request-1"}
	if err := storage.UploadPack(context.Background(), operation, &chunkReader{chunks: [][]byte{[]byte("one"), []byte("two")}}, &output); err != nil {
		t.Fatal(err)
	}
	if server.context == nil || server.context.GetTenantId() != "tenant-a" || server.context.GetRepositoryId() != "repo-a" {
		t.Fatalf("first request context = %+v", server.context)
	}
	if got, want := output.String(), "reply:onereply:two"; got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
}

type chunkReader struct {
	chunks [][]byte
}

func (r *chunkReader) Read(p []byte) (int, error) {
	if len(r.chunks) == 0 {
		return 0, io.EOF
	}
	chunk := r.chunks[0]
	r.chunks = r.chunks[1:]
	return copy(p, chunk), nil
}
