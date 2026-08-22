// Command git-storaged serves the approved internal GitStorage RPC contract.
//
// Smart-HTTP and SSH authenticate at their own boundary (T-0011). This process still resolves
// only tenant-scoped repository handles and asks the PDP before every Git subprocess starts.
package main

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	gitv1 "github.com/gitfrok/backend/gen/proto/git/v1"
	repositoryv1 "github.com/gitfrok/backend/gen/proto/repository/v1"
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

	// LandingIdentity is the author and committer produced merge commits carry
	// (SPEC-0065 AC2): the platform's own service identity, never a caller's
	// name. Defaults apply when unset.
	LandingIdentityName  string
	LandingIdentityEmail string

	// Coordinator gates push acknowledgment on the sync-replica durability quorum (SPEC-0018,
	// ADR-0047). It is required: a storage node that has no quorum cannot acknowledge a push and
	// must deny writes it cannot durably replicate. Single-node dev runs are served by an
	// in-process coordinator that treats this node as its own sync replica.
	Coordinator repoapi.Coordinator
	// NodeID is this storage node's opaque identity, used to classify which replica a durability
	// acknowledgement comes from.
	NodeID string
	// QuorumTimeout is how long a write waits for the sync replica to durably acknowledge before the
	// push acknowledgment is withheld. Zero falls back to a sane default.
	QuorumTimeout time.Duration

	// Protection is this node's tenant-scoped projection of branch-protection
	// facts. Without one no ref is treated as protected, which is the correct
	// state for a node that has been told about none — but a deployment that
	// wants the protected-branch rule enforced must supply it (SPEC-0019 AC3).
	Protection Protection

	// Objects is the large-object tier (SPEC-0023). Without one this node serves no
	// LFS: an import carrying pointers fails rather than landing a repository whose
	// large files are absent, and the batch API refuses rather than returning
	// actions nothing can honour.
	Objects ObjectStore

	// command is test-only command construction. Production leaves it nil and uses exec.CommandContext.
	command func(context.Context, string, ...string) *exec.Cmd
}

// Server implements gitsaas.git.v1.GitStorage.
type Server struct {
	gitv1.UnimplementedGitStorageServer
	repositoryv1.UnimplementedRepositoryReaderServer

	root    string
	pdp     policyapi.DecisionPoint
	events  bus.Bus
	command func(context.Context, string, ...string) *exec.Cmd
	pageKey []byte

	coordinator   repoapi.Coordinator
	nodeID        string
	quorumTimeout time.Duration
	protection    Protection
	objects       ObjectStore
	sourceLFS     *sourceLFSClient

	refMu   sync.Mutex
	refSubs []*refSubscriber

	// The identity produced commits are authored and committed as (SPEC-0065
	// AC2), configured per environment with defaults an unset deployment says
	// only about itself. The rebase-landing capability probe caches here too.
	landingName       string
	landingEmail      string
	replayMu          sync.Mutex
	replayProvenCache bool
	replayProvenVal   bool
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
	if config.Coordinator == nil {
		return nil, errors.New("git-storaged: replica coordinator is required")
	}
	if config.NodeID == "" {
		return nil, errors.New("git-storaged: node ID is required")
	}
	command := config.command
	if command == nil {
		command = exec.CommandContext
	}

	pageKey := make([]byte, 32)
	if _, err := rand.Read(pageKey); err != nil {
		return nil, fmt.Errorf("git-storaged: generate tree page key: %w", err)
	}
	quorumTimeout := config.QuorumTimeout
	if quorumTimeout <= 0 {
		quorumTimeout = 5 * time.Second
	}
	server := &Server{
		root:          config.RepositoryRoot,
		pdp:           config.PDP,
		events:        config.Events,
		command:       command,
		pageKey:       pageKey,
		coordinator:   config.Coordinator,
		nodeID:        config.NodeID,
		quorumTimeout: quorumTimeout,
		protection:    config.Protection,
		objects:       config.Objects,
		sourceLFS:     newSourceLFSClient(),
		landingName:   config.LandingIdentityName,
		landingEmail:  config.LandingIdentityEmail,
	}
	bus.SubscribeTyped(config.Events, server.forwardRefUpdate)
	return server, nil
}

const (
	defaultTreePageSize = 100
	maxTreePageSize     = 500
	readChunkSize       = 64 * 1024
)

type treeCursor struct {
	TenantID, RepositoryID, Revision string
	Offset                           int
}

// GetTree serves one bounded tree page. The signed token binds the cursor to
// the tenant, repository and revision so a token from one read cannot continue
// another read (SPEC-0017 AC1).
func (s *Server) GetTree(ctx context.Context, req *repositoryv1.GetTreeRequest) (*repositoryv1.GetTreeResponse, error) {
	op, err := s.prepareRead(ctx, req.GetContext())
	if err != nil || !validRevision(req.GetRevision()) {
		return nil, unavailable()
	}
	pageSize := int(req.GetPageSize())
	if pageSize == 0 {
		pageSize = defaultTreePageSize
	}
	if pageSize < 0 || pageSize > maxTreePageSize {
		return nil, unavailable()
	}
	offset := 0
	if req.GetPageToken() != "" {
		cursor, ok := s.parseTreeCursor(req.GetPageToken())
		if !ok || cursor.TenantID != op.tenantID || cursor.RepositoryID != op.repositoryID || cursor.Revision != req.GetRevision() {
			return nil, unavailable()
		}
		offset = cursor.Offset
	}
	entries, more, err := s.treePage(ctx, op.path, req.GetRevision(), offset, pageSize)
	if err != nil {
		return nil, unavailable()
	}
	response := &repositoryv1.GetTreeResponse{Entries: entries}
	if more {
		response.NextPageToken = s.treeCursor(treeCursor{TenantID: op.tenantID, RepositoryID: op.repositoryID, Revision: req.GetRevision(), Offset: offset + len(entries)})
	}
	return response, nil
}

// GetFile emits a metadata-bearing first chunk and then streams at most 64 KiB
// per message. It never materializes a repository blob in application memory.
func (s *Server) GetFile(req *repositoryv1.GetFileRequest, stream repositoryv1.RepositoryReader_GetFileServer) error {
	op, err := s.prepareRead(stream.Context(), req.GetContext())
	if err != nil || !validRevision(req.GetRevision()) || !validRepositoryPath(req.GetPath()) {
		return unavailable()
	}
	entry, err := s.fileEntry(stream.Context(), op.path, req.GetRevision(), req.GetPath())
	if err != nil {
		return unavailable()
	}
	return s.streamGit(stream.Context(), op.path, []string{"show", req.GetRevision() + ":" + req.GetPath()}, func(data []byte, eof bool) error {
		chunk := &repositoryv1.FileChunk{Data: data, Eof: eof}
		if entry != nil {
			chunk.Metadata = entry
			entry = nil
		}
		return stream.Send(chunk)
	})
}

// GetDiff streams a Git patch under the same preflight and PDP decision as
// trees and blobs. A failed preflight sends no chunks.
func (s *Server) GetDiff(req *repositoryv1.GetDiffRequest, stream repositoryv1.RepositoryReader_GetDiffServer) error {
	op, err := s.prepareRead(stream.Context(), req.GetContext())
	if err != nil || !validRevision(req.GetBaseRevision()) || !validRevision(req.GetHeadRevision()) || (req.GetPath() != "" && !validRepositoryPath(req.GetPath())) {
		return unavailable()
	}
	args := []string{"diff", "--no-ext-diff", req.GetBaseRevision(), req.GetHeadRevision()}
	if req.GetPath() != "" {
		args = append(args, "--", req.GetPath())
	}
	return s.streamGit(stream.Context(), op.path, args, func(data []byte, eof bool) error {
		return stream.Send(&repositoryv1.DiffChunk{Data: data, Eof: eof})
	})
}

// GetMergeBase computes the best common ancestor of two refs or commits under
// the same preflight and PDP decision as every other read. No common ancestor
// is an answered question, not a failure: the response says so and the caller
// decides what that means (SPEC-0028). A refused context, an invalid ref, or
// an unreadable repository is the same coarse unavailability as everywhere
// else (SPEC-0001).
func (s *Server) GetMergeBase(ctx context.Context, req *repositoryv1.GetMergeBaseRequest) (*repositoryv1.GetMergeBaseResponse, error) {
	op, err := s.prepareRead(ctx, req.GetContext())
	if err != nil || !validRevision(req.GetRefA()) || !validRevision(req.GetRefB()) {
		return nil, unavailable()
	}
	command := s.command(ctx, "git", "-C", op.path, "merge-base", req.GetRefA(), req.GetRefB())
	output, err := command.Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() == 1 {
			// Git exits 1 when the refs share no common ancestor: that is
			// the answer, reported honestly rather than as an error.
			return &repositoryv1.GetMergeBaseResponse{Found: false}, nil
		}
		return nil, unavailable()
	}
	base := strings.TrimSpace(string(output))
	if base == "" {
		return nil, unavailable()
	}
	return &repositoryv1.GetMergeBaseResponse{Found: true, MergeBase: base}, nil
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
	// The push is only acknowledged after the sync replica has durably stored it under the leased
	// term (ADR-0042, SPEC-0018 AC1); withholding the ack here is what bounds the acknowledged RPO
	// to zero. A failed quorum returns an error and suppresses the RefUpdated event.
	if err := s.requireQuorum(stream.Context(), repository); err != nil {
		return err
	}
	return s.publishRefUpdates(stream.Context(), repository)
}

// requireQuorum records this node's primary durability acknowledgement and waits for the in-sync
// replica to durably acknowledge the same operation under the same term. A refused acknowledgement
// or a timeout withholds the push acknowledgement — the caller observes a failure and no RefUpdated
// event is published.
func (s *Server) requireQuorum(ctx context.Context, repository repositoryOperation) error {
	if s.coordinator == nil || repository.fencingTerm == 0 {
		return nil
	}
	if _, err := s.coordinator.AckDurable(ctx, repository.tenantID, repository.repositoryID, repository.requestID, s.nodeID, repository.fencingTerm); err != nil {
		return unavailable()
	}
	if err := s.coordinator.WaitForQuorum(ctx, repository.tenantID, repository.repositoryID, repository.requestID, repository.fencingTerm, s.quorumTimeout); err != nil {
		return unavailable()
	}
	return nil
}

type repositoryOperation struct {
	tenantID     string
	repositoryID string
	actorID      string
	actorRoles   []string
	path         string
	before       map[string]string

	// requestID is the opaque receive-pack operation handle used to track this push's
	// primary/sync durability acknowledgements (SPEC-0018).
	requestID string
	// fencingTerm is the term this operation's write was leased under; it is attached to the
	// durability acknowledgements so a stale primary or a quorum reached under a superseded term
	// cannot be honored (ADR-0042 §2).
	fencingTerm uint64
}

type receive func() (data []byte, close bool, err error)
type send func([]byte) error

func (s *Server) exchange(ctx context.Context, op *gitv1.OperationContext, action, binary string, incoming receive, outgoing send) (repositoryOperation, error) {
	if op == nil || !validGitTransport(op.GetTransport()) {
		return repositoryOperation{}, unavailable()
	}
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

	args, err := gitCommandArgs(binary, op.GetTransport(), repository.path)
	if err != nil {
		return repositoryOperation{}, unavailable()
	}
	command := s.command(ctx, binary, args...)
	if action == "repo.write" {
		// A protected ref is refused before git applies it, not detected after.
		// The PDP makes the decision here; the hook only carries it out, because
		// once git-receive-pack has run the refs have already moved.
		if err := installPreReceiveHook(repository.path); err != nil {
			return repositoryOperation{}, unavailable()
		}
		command.Env = hookEnvironment(command.Env, s.rejectedRefs(ctx, op))
	}
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
	var sendErr error
	sendWG.Go(func() {
		buffer := make([]byte, 32*1024)
		for {
			count, readErr := stdout.Read(buffer)
			if count > 0 {
				if err := outgoing(slices.Clone(buffer[:count])); err != nil {
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
	})

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
	return s.prepareWith(ctx, op, action, nil)
}

// prepareWith resolves the tenant-scoped handle and asks the PDP, adding the
// caller's attributes to the decision context. Those attributes describe the
// operation storage is about to perform; every one of them is derived here, and
// none of them can carry an authorization result.
func (s *Server) prepareWith(ctx context.Context, op *gitv1.OperationContext, action string, attributes map[string]string) (repositoryOperation, error) {
	if op == nil || !validHandle(op.GetTenantId()) || !validHandle(op.GetRepositoryId()) || op.GetActorId() == "" || op.GetRequestId() == "" {
		return repositoryOperation{}, unavailable()
	}
	decisionContext := map[string]string{"request_id": op.GetRequestId()}
	for name, value := range attributes {
		decisionContext[name] = value
	}
	path := filepath.Join(s.root, op.GetTenantId(), op.GetRepositoryId()+".git")
	relative, err := filepath.Rel(s.root, path)
	if err != nil || relative == "." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || relative == ".." {
		return repositoryOperation{}, unavailable()
	}

	decision, err := s.pdp.Decide(ctx, policyapi.Request{
		TenantID: op.GetTenantId(),
		// Roles arrive only from a verified Identity&Access principal through the
		// front door. They are PDP input, never a client-provided allow result.
		Subject:  policyapi.Subject{ID: op.GetActorId(), TenantID: op.GetTenantId(), Roles: slices.Clone(op.GetActorRoles())},
		Action:   action,
		Resource: policyapi.Resource{Type: "repository", ID: op.GetRepositoryId()},
		Context:  decisionContext,
	})
	if err != nil || !decision.Allowed {
		return repositoryOperation{}, unavailable()
	}
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return repositoryOperation{}, unavailable()
	}
	repository := repositoryOperation{
		tenantID:     op.GetTenantId(),
		repositoryID: op.GetRepositoryId(),
		actorID:      op.GetActorId(),
		actorRoles:   slices.Clone(op.GetActorRoles()),
		path:         path,
		requestID:    op.GetRequestId(),
	}
	// repo.write is gated on the replica lease before any Git subprocess starts: a shard that is not
	// healthy, not write-ready, or not led by this primary is denied so write activity never races a
	// term change (ADR-0042 §2/§4).
	if action == "repo.write" {
		term, err := s.acquireWriteLease(ctx, op)
		if err != nil {
			return repositoryOperation{}, unavailable()
		}
		repository.fencingTerm = term
	}
	return repository, nil
}

// acquireWriteLease obtains the current shard record and leases the write-route to this node for the
// receive-pack operation carried in op. It returns the fencing term the lease was granted under, or
// an error (treated as a denial) when the shard is not writable by this node.
func (s *Server) acquireWriteLease(ctx context.Context, op *gitv1.OperationContext) (uint64, error) {
	rec, err := s.coordinator.GetShard(ctx, op.GetTenantId(), op.GetRepositoryId(), 0)
	if err != nil {
		return 0, unavailable()
	}
	if rec.State != repoapi.ShardStateHealthy || !rec.WriteReady || rec.PrimaryNode != s.nodeID {
		return 0, unavailable()
	}
	lease, err := s.coordinator.BindLease(ctx, op.GetTenantId(), op.GetRepositoryId(), op.GetRequestId(), s.nodeID, rec.FencingTerm)
	if err != nil || !lease.Granted {
		return 0, unavailable()
	}
	return lease.Term, nil
}

func validGitTransport(transport gitv1.GitTransport) bool {
	return transport == gitv1.GitTransport_GIT_TRANSPORT_SSH || transport == gitv1.GitTransport_GIT_TRANSPORT_SMART_HTTP_DISCOVERY || transport == gitv1.GitTransport_GIT_TRANSPORT_SMART_HTTP_RPC
}

func gitCommandArgs(binary string, transport gitv1.GitTransport, repositoryPath string) ([]string, error) {
	switch binary {
	case "git-upload-pack":
		switch transport {
		case gitv1.GitTransport_GIT_TRANSPORT_SSH:
			return []string{"--strict", repositoryPath}, nil
		case gitv1.GitTransport_GIT_TRANSPORT_SMART_HTTP_DISCOVERY:
			return []string{"--stateless-rpc", "--advertise-refs", repositoryPath}, nil
		case gitv1.GitTransport_GIT_TRANSPORT_SMART_HTTP_RPC:
			return []string{"--stateless-rpc", repositoryPath}, nil
		}
	case "git-receive-pack":
		switch transport {
		case gitv1.GitTransport_GIT_TRANSPORT_SSH:
			return []string{repositoryPath}, nil
		case gitv1.GitTransport_GIT_TRANSPORT_SMART_HTTP_DISCOVERY:
			return []string{"--stateless-rpc", "--advertise-refs", repositoryPath}, nil
		case gitv1.GitTransport_GIT_TRANSPORT_SMART_HTTP_RPC:
			return []string{"--stateless-rpc", repositoryPath}, nil
		}
	}
	return nil, errors.New("git-storaged: invalid transport framing")
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
				ActorRoles: slices.Clone(repository.actorRoles),
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
				ActorRoles: slices.Clone(repository.actorRoles),
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
	for line := range strings.SplitSeq(strings.TrimSpace(string(output)), "\n") {
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

func (s *Server) prepareRead(ctx context.Context, read *repositoryv1.ReadContext) (repositoryOperation, error) {
	if read == nil {
		return repositoryOperation{}, unavailable()
	}
	return s.prepare(ctx, &gitv1.OperationContext{
		TenantId: read.GetTenantId(), RepositoryId: read.GetRepositoryId(), ActorId: read.GetActorId(), RequestId: read.GetRequestId(), ActorRoles: slices.Clone(read.GetActorRoles()),
	}, "repo.read")
}

func validRevision(value string) bool {
	if value == "" || len(value) > 256 || strings.HasPrefix(value, "-") || strings.Contains(value, "..") || strings.ContainsAny(value, "\\\x00 \t\n\r~^:?*[") {
		return false
	}
	return true
}

func validRepositoryPath(value string) bool {
	if value == "" || len(value) > 4096 || strings.HasPrefix(value, "/") || strings.Contains(value, "\\") || strings.ContainsRune(value, '\x00') {
		return false
	}
	for segment := range strings.SplitSeq(value, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func (s *Server) treePage(ctx context.Context, repositoryPath, revision string, offset, pageSize int) ([]*repositoryv1.TreeEntry, bool, error) {
	command := s.command(ctx, "git", "-C", repositoryPath, "ls-tree", "-z", "-l", revision)
	output, err := command.StdoutPipe()
	if err != nil {
		return nil, false, err
	}
	if err := command.Start(); err != nil {
		return nil, false, err
	}
	reader := bufio.NewReader(output)
	entries := make([]*repositoryv1.TreeEntry, 0, pageSize)
	index := 0
	more := false
	for {
		record, readErr := reader.ReadString('\x00')
		if len(record) != 0 {
			entry, parseErr := parseTreeEntry(strings.TrimSuffix(record, "\x00"))
			if parseErr != nil {
				_ = command.Wait()
				return nil, false, parseErr
			}
			if index >= offset {
				if len(entries) < pageSize {
					entries = append(entries, entry)
				} else {
					more = true
				}
			}
			index++
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			_ = command.Wait()
			return nil, false, readErr
		}
	}
	if err := command.Wait(); err != nil {
		return nil, false, err
	}
	return entries, more, nil
}

func parseTreeEntry(record string) (*repositoryv1.TreeEntry, error) {
	parts := strings.SplitN(record, "\t", 2)
	if len(parts) != 2 || !validRepositoryPath(parts[1]) {
		return nil, errors.New("invalid tree entry")
	}
	fields := strings.Fields(parts[0])
	if len(fields) != 4 {
		return nil, errors.New("invalid tree metadata")
	}
	mode, err := strconv.ParseUint(fields[0], 8, 32)
	if err != nil {
		return nil, err
	}
	size, err := strconv.ParseInt(fields[3], 10, 64)
	if err != nil && fields[3] != "-" {
		return nil, err
	}
	kind := repositoryv1.EntryKind_ENTRY_KIND_UNSPECIFIED
	switch fields[1] {
	case "blob":
		if fields[0] == "120000" {
			kind = repositoryv1.EntryKind_ENTRY_KIND_SYMLINK
		} else {
			kind = repositoryv1.EntryKind_ENTRY_KIND_FILE
		}
	case "tree":
		kind = repositoryv1.EntryKind_ENTRY_KIND_DIRECTORY
	case "commit":
		kind = repositoryv1.EntryKind_ENTRY_KIND_SYMLINK
	}
	if kind == repositoryv1.EntryKind_ENTRY_KIND_UNSPECIFIED {
		return nil, errors.New("unsupported tree entry")
	}
	return &repositoryv1.TreeEntry{Path: parts[1], Kind: kind, ObjectId: fields[2], Mode: uint32(mode), SizeBytes: size}, nil
}

func (s *Server) fileEntry(ctx context.Context, repositoryPath, revision, path string) (*repositoryv1.FileMetadata, error) {
	command := s.command(ctx, "git", "-C", repositoryPath, "ls-tree", "-z", "-l", revision, "--", path)
	output, err := command.Output()
	if err != nil {
		return nil, err
	}
	entry, err := parseTreeEntry(strings.TrimSuffix(string(output), "\x00"))
	if err != nil || entry.Kind != repositoryv1.EntryKind_ENTRY_KIND_FILE || entry.Path != path {
		return nil, errors.New("file unavailable")
	}
	return &repositoryv1.FileMetadata{Path: entry.Path, ObjectId: entry.ObjectId, Mode: entry.Mode, SizeBytes: entry.SizeBytes}, nil
}

func (s *Server) streamGit(ctx context.Context, repositoryPath string, args []string, send func([]byte, bool) error) error {
	command := s.command(ctx, "git", append([]string{"-C", repositoryPath}, args...)...)
	output, err := command.StdoutPipe()
	if err != nil {
		return unavailable()
	}
	if err := command.Start(); err != nil {
		return unavailable()
	}
	read := func() ([]byte, error) {
		buffer := make([]byte, readChunkSize)
		count, err := output.Read(buffer)
		return buffer[:count], err
	}
	pending, readErr := read()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		_ = command.Wait()
		return unavailable()
	}
	if len(pending) == 0 && errors.Is(readErr, io.EOF) {
		if err := command.Wait(); err != nil {
			return unavailable()
		}
		return send(nil, true)
	}
	for {
		next, nextErr := read()
		if err := send(pending, errors.Is(nextErr, io.EOF)); err != nil {
			_ = command.Process.Kill()
			_ = command.Wait()
			return err
		}
		if errors.Is(nextErr, io.EOF) {
			if err := command.Wait(); err != nil {
				return unavailable()
			}
			return nil
		}
		if nextErr != nil {
			_ = command.Wait()
			return unavailable()
		}
		pending = next
	}
}

func (s *Server) treeCursor(cursor treeCursor) string {
	payload, _ := json.Marshal(cursor)
	mac := hmac.New(sha256.New, s.pageKey)
	_, _ = mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (s *Server) parseTreeCursor(value string) (treeCursor, bool) {
	parts := strings.Split(value, ".")
	if len(parts) != 2 {
		return treeCursor{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return treeCursor{}, false
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return treeCursor{}, false
	}
	mac := hmac.New(sha256.New, s.pageKey)
	_, _ = mac.Write(payload)
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return treeCursor{}, false
	}
	var cursor treeCursor
	if err := json.Unmarshal(payload, &cursor); err != nil || cursor.Offset < 0 {
		return treeCursor{}, false
	}
	return cursor, true
}

func unavailable() error { return status.Error(codes.NotFound, "repository unavailable") }
