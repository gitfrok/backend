// Command git-storaged serves the approved internal GitStorage RPC contract.
//
// Smart-HTTP and SSH authenticate at their own boundary (T-0011). This process still resolves
// only tenant-scoped repository handles and asks the PDP before every Git subprocess starts.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	gitv1 "github.com/gitfrok/backend/gen/proto/git/v1"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
	repoapi "github.com/gitfrok/backend/modules/repository/api"
	"github.com/gitfrok/backend/platform/bus"
	"github.com/gitfrok/backend/platform/ids"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ErrFUSERepositoryRoot refuses the filesystem that ADR-0033 disqualifies for live Git repos.
var ErrFUSERepositoryRoot = errors.New("git-storaged: repository root is on FUSE")

// Config is the process-local composition for one storage node. RepositoryRoot is a volume mount
// selected by deployment configuration; Git-RPC callers can only provide opaque tenant and repo IDs.
type Config struct {
	RepositoryRoot string
	PDP            policyapi.DecisionPoint
	Events         bus.Bus

	// command is test-only command construction. Production leaves it nil and uses exec.CommandContext.
	command func(context.Context, string, ...string) *exec.Cmd
}

// Server implements gitsaas.git.v1.GitStorage.
type Server struct {
	gitv1.UnimplementedGitStorageServer

	root    string
	pdp     policyapi.DecisionPoint
	events  bus.Bus
	command func(context.Context, string, ...string) *exec.Cmd
}

// NewServer validates process wiring and the live-repository filesystem before the service accepts
// traffic. Failing deployment rather than serving a FUSE-backed root preserves Git rename semantics.
func NewServer(config Config) (*Server, error) { return newServer(config, systemMount{}) }

func newServer(config Config, mount mountChecker) (*Server, error) {
	if config.RepositoryRoot == "" {
		return nil, errors.New("git-storaged: repository root is required")
	}
	info, err := os.Stat(config.RepositoryRoot)
	if err != nil {
		return nil, fmt.Errorf("git-storaged: repository root: %w", err)
	}
	if !info.IsDir() {
		return nil, errors.New("git-storaged: repository root is not a directory")
	}
	if config.PDP == nil {
		return nil, errors.New("git-storaged: PDP is required")
	}
	if config.Events == nil {
		return nil, errors.New("git-storaged: event bus is required")
	}
	if err := mount.Check(config.RepositoryRoot); err != nil {
		return nil, err
	}
	command := config.command
	if command == nil {
		command = exec.CommandContext
	}
	return &Server{root: config.RepositoryRoot, pdp: config.PDP, events: config.Events, command: command}, nil
}

// UploadPack executes git-upload-pack after the tenant-scoped handle and PDP decision pass.
func (s *Server) UploadPack(stream gitv1.GitStorage_UploadPackServer) error {
	first, err := stream.Recv()
	if err != nil {
		return unavailable()
	}
	operation, ok := first.Payload.(*gitv1.UploadPackRequest_Context)
	if !ok {
		return unavailable()
	}
	_, err = s.exchange(stream.Context(), operation.Context, "repo.read", "git-upload-pack", func() ([]byte, bool, error) {
		req, recvErr := stream.Recv()
		if recvErr != nil {
			return nil, false, recvErr
		}
		switch payload := req.Payload.(type) {
		case *gitv1.UploadPackRequest_Data:
			return payload.Data, false, nil
		case *gitv1.UploadPackRequest_Close:
			return nil, payload.Close, nil
		default:
			return nil, false, status.Error(codes.InvalidArgument, "invalid Git stream payload")
		}
	}, func(data []byte) error {
		return stream.Send(&gitv1.UploadPackResponse{Data: data})
	})
	return err
}

// ReceivePack executes git-receive-pack and publishes every ref mutation after a successful push.
func (s *Server) ReceivePack(stream gitv1.GitStorage_ReceivePackServer) error {
	first, err := stream.Recv()
	if err != nil {
		return unavailable()
	}
	operation, ok := first.Payload.(*gitv1.ReceivePackRequest_Context)
	if !ok {
		return unavailable()
	}
	repository, err := s.exchange(stream.Context(), operation.Context, "repo.write", "git-receive-pack", func() ([]byte, bool, error) {
		req, recvErr := stream.Recv()
		if recvErr != nil {
			return nil, false, recvErr
		}
		switch payload := req.Payload.(type) {
		case *gitv1.ReceivePackRequest_Data:
			return payload.Data, false, nil
		case *gitv1.ReceivePackRequest_Close:
			return nil, payload.Close, nil
		default:
			return nil, false, status.Error(codes.InvalidArgument, "invalid Git stream payload")
		}
	}, func(data []byte) error {
		return stream.Send(&gitv1.ReceivePackResponse{Data: data})
	})
	if err != nil {
		return err
	}
	return s.publishRefUpdates(stream.Context(), repository)
}

type repositoryOperation struct {
	tenantID     string
	repositoryID string
	actorID      string
	path         string
	before       map[string]string
}

type receive func() (data []byte, close bool, err error)
type send func([]byte) error

func (s *Server) exchange(ctx context.Context, op *gitv1.OperationContext, action, binary string, incoming receive, outgoing send) (repositoryOperation, error) {
	repository, err := s.prepare(ctx, op, action)
	if err != nil {
		return repositoryOperation{}, err
	}
	if action == "repo.write" {
		repository.before, err = refs(ctx, repository.path)
		if err != nil {
			return repositoryOperation{}, unavailable()
		}
	}

	args := []string{repository.path}
	if binary == "git-upload-pack" {
		args = append([]string{"--strict"}, args...)
	}
	command := s.command(ctx, binary, args...)
	stdin, err := command.StdinPipe()
	if err != nil {
		return repositoryOperation{}, unavailable()
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		return repositoryOperation{}, unavailable()
	}
	if err := command.Start(); err != nil {
		return repositoryOperation{}, unavailable()
	}

	var sendWG sync.WaitGroup
	sendWG.Add(1)
	var sendErr error
	go func() {
		defer sendWG.Done()
		buffer := make([]byte, 32*1024)
		for {
			count, readErr := stdout.Read(buffer)
			if count > 0 {
				if err := outgoing(append([]byte(nil), buffer[:count]...)); err != nil {
					sendErr = err
					return
				}
			}
			if readErr != nil {
				if !errors.Is(readErr, io.EOF) {
					sendErr = readErr
				}
				return
			}
		}
	}()

	for {
		data, closeStream, recvErr := incoming()
		if errors.Is(recvErr, io.EOF) || closeStream {
			_ = stdin.Close()
			break
		}
		if recvErr != nil {
			_ = stdin.Close()
			sendWG.Wait()
			_ = command.Wait()
			return repositoryOperation{}, recvErr
		}
		if len(data) == 0 {
			continue
		}
		if _, err := stdin.Write(data); err != nil {
			_ = stdin.Close()
			sendWG.Wait()
			_ = command.Wait()
			return repositoryOperation{}, unavailable()
		}
	}

	sendWG.Wait()
	waitErr := command.Wait()
	if waitErr != nil || sendErr != nil {
		return repositoryOperation{}, unavailable()
	}
	return repository, nil
}

func (s *Server) prepare(ctx context.Context, op *gitv1.OperationContext, action string) (repositoryOperation, error) {
	if op == nil || !validHandle(op.GetTenantId()) || !validHandle(op.GetRepositoryId()) || op.GetActorId() == "" || op.GetRequestId() == "" {
		return repositoryOperation{}, unavailable()
	}
	path := filepath.Join(s.root, op.GetTenantId(), op.GetRepositoryId()+".git")
	relative, err := filepath.Rel(s.root, path)
	if err != nil || relative == "." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || relative == ".." {
		return repositoryOperation{}, unavailable()
	}

	decision, err := s.pdp.Decide(ctx, policyapi.Request{
		TenantID: op.GetTenantId(),
		Subject:  policyapi.Subject{ID: op.GetActorId(), TenantID: op.GetTenantId()},
		Action:   action,
		Resource: policyapi.Resource{Type: "repository", ID: op.GetRepositoryId()},
		Context:  map[string]string{"request_id": op.GetRequestId()},
	})
	if err != nil || !decision.Allowed {
		return repositoryOperation{}, unavailable()
	}
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return repositoryOperation{}, unavailable()
	}
	return repositoryOperation{tenantID: op.GetTenantId(), repositoryID: op.GetRepositoryId(), actorID: op.GetActorId(), path: path}, nil
}

func (s *Server) publishRefUpdates(ctx context.Context, repository repositoryOperation) error {
	after, err := refs(ctx, repository.path)
	if err != nil {
		return unavailable()
	}
	for ref, newSHA := range after {
		if oldSHA := repository.before[ref]; oldSHA != newSHA {
			if err := s.events.Publish(ctx, repoapi.RefUpdated{
				EventID:    ids.NewULID(),
				TenantID:   repository.tenantID,
				RepoID:     repository.repositoryID,
				Ref:        ref,
				OldSha:     zeroSHA(oldSHA),
				NewSha:     zeroSHA(newSHA),
				ActorID:    repository.actorID,
				OccurredAt: time.Now().UTC(),
			}); err != nil {
				return unavailable()
			}
		}
	}
	for ref, oldSHA := range repository.before {
		if _, exists := after[ref]; !exists {
			if err := s.events.Publish(ctx, repoapi.RefUpdated{
				EventID:    ids.NewULID(),
				TenantID:   repository.tenantID,
				RepoID:     repository.repositoryID,
				Ref:        ref,
				OldSha:     zeroSHA(oldSHA),
				NewSha:     strings.Repeat("0", 40),
				ActorID:    repository.actorID,
				OccurredAt: time.Now().UTC(),
			}); err != nil {
				return unavailable()
			}
		}
	}
	return nil
}

func refs(ctx context.Context, repositoryPath string) (map[string]string, error) {
	command := exec.CommandContext(ctx, "git", "-C", repositoryPath, "for-each-ref", "--format=%(refname) %(objectname)")
	output, err := command.Output()
	if err != nil {
		return nil, err
	}
	result := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 {
			result[fields[0]] = fields[1]
		}
	}
	return result, nil
}

func zeroSHA(value string) string {
	if value == "" {
		return strings.Repeat("0", 40)
	}
	return value
}

var handle = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)

func validHandle(value string) bool { return handle.MatchString(value) }

func unavailable() error { return status.Error(codes.NotFound, "repository unavailable") }
