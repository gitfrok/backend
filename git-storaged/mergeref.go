package main

import (
	"context"
	"strings"
	"time"

	gitv1 "github.com/gitfrok/backend/gen/proto/git/v1"
	repoapi "github.com/gitfrok/backend/modules/repository/api"
	"github.com/gitfrok/backend/platform/ids"
)

// MergeRef moves one exact branch ref to an existing revision on behalf of an
// authorized merge (SPEC-0019).
//
// It is the only route by which a ref changes without a Git protocol exchange,
// and it is deliberately narrower than one: one ref, one revision, no pack bytes,
// no force, no delete. Code Review has already asked its own PDP before calling
// this; storage asks again with its own server-derived context, because a caller
// that was allowed by one enforcement point is not therefore trusted by another.
//
// The move is a compare-and-swap on both sides: the caller states the revision it
// last saw, and git's own update-ref applies the change only if the ref is still
// there. A merge decided against one state therefore cannot land on a different
// one, whatever happened in between.
func (s *Server) MergeRef(ctx context.Context, req *gitv1.MergeRefRequest) (*gitv1.MergeRefResponse, error) {
	principal := req.GetContext()
	targetRef, revision := req.GetTargetRef(), req.GetRevision()
	if principal == nil || !validBranchRef(targetRef) || !validObjectID(revision) {
		return nil, unavailable()
	}
	if expected := req.GetExpectedCurrentRevision(); expected != "" && !validObjectID(expected) {
		return nil, unavailable()
	}

	operation := &gitv1.OperationContext{
		TenantId:     principal.GetTenantId(),
		RepositoryId: principal.GetRepositoryId(),
		ActorId:      principal.GetActorId(),
		RequestId:    principal.GetRequestId(),
		ActorRoles:   principal.GetActorRoles(),
	}
	// operation distinguishes this from a direct push, which policy refuses on a
	// protected ref. The value is set here, by storage, and cannot arrive from a
	// caller — that is the whole reason the protected-branch rule is safe.
	repository, err := s.prepareWith(ctx, operation, "repo.write", map[string]string{
		"operation":  "merge",
		"target_ref": targetRef,
	})
	if err != nil {
		return nil, err
	}

	// The revision must already be in this repository. Without this a merge could
	// name an object that was never pushed here and leave a ref pointing at nothing
	// resolvable.
	if _, err := s.resolveRevision(ctx, repository.path, revision+"^{commit}"); err != nil {
		return nil, unavailable()
	}
	current, err := s.currentRef(ctx, repository.path, targetRef)
	if err != nil {
		return nil, unavailable()
	}
	if current != req.GetExpectedCurrentRevision() {
		return nil, unavailable()
	}

	// A merge is a write, so it takes the same durability path as a push: the ref
	// move is acknowledged only once the primary and the in-sync replica have both
	// acknowledged it under the leased term (SPEC-0018).
	if err := s.updateRef(ctx, repository.path, targetRef, revision, current); err != nil {
		return nil, unavailable()
	}
	if err := s.requireQuorum(ctx, repository); err != nil {
		return nil, unavailable()
	}

	if err := s.events.Publish(ctx, repoapi.RefUpdated{
		EventID:    ids.NewULID(),
		TenantID:   repository.tenantID,
		RepoID:     repository.repositoryID,
		Ref:        targetRef,
		OldSha:     zeroSHA(current),
		NewSha:     revision,
		ActorID:    repository.actorID,
		ActorRoles: append([]string(nil), repository.actorRoles...),
		OccurredAt: time.Now().UTC(),
	}); err != nil {
		return nil, unavailable()
	}
	return &gitv1.MergeRefResponse{TargetRef: targetRef, Revision: revision}, nil
}

// currentRef returns the revision targetRef points at, or "" when it does not
// exist. A ref that is absent is not an error: it is the state an empty
// expected-current-revision describes.
func (s *Server) currentRef(ctx context.Context, repositoryPath, targetRef string) (string, error) {
	output, err := s.command(ctx, "git", "-C", repositoryPath, "show-ref", "--verify", "--hash", targetRef).Output()
	if err != nil {
		// show-ref exits non-zero for a ref that is not there, which is a state
		// rather than a failure. Anything worse surfaces on the next command.
		return "", nil
	}
	return strings.TrimSpace(string(output)), nil
}

func (s *Server) resolveRevision(ctx context.Context, repositoryPath, revision string) (string, error) {
	output, err := s.command(ctx, "git", "-C", repositoryPath, "rev-parse", "--verify", "--quiet", revision).Output()
	if err != nil {
		return "", err
	}
	resolved := strings.TrimSpace(string(output))
	if resolved == "" {
		return "", unavailable()
	}
	return resolved, nil
}

// updateRef performs git's own compare-and-swap. Passing the old value is what
// makes a concurrent change lose rather than be silently overwritten; an absent
// ref is expressed as the zero object ID.
func (s *Server) updateRef(ctx context.Context, repositoryPath, targetRef, revision, current string) error {
	old := current
	if old == "" {
		old = strings.Repeat("0", 40)
	}
	return s.command(ctx, "git", "-C", repositoryPath, "update-ref", targetRef, revision, old).Run()
}

// validBranchRef accepts only an exact branch ref. Pattern syntax, path escapes,
// and the option-like names git itself would reinterpret are all refused.
func validBranchRef(ref string) bool {
	const prefix = "refs/heads/"
	if !strings.HasPrefix(ref, prefix) || len(ref) == len(prefix) || len(ref) > 512 {
		return false
	}
	name := ref[len(prefix):]
	if strings.HasPrefix(name, "/") || strings.HasSuffix(name, "/") || strings.Contains(name, "//") ||
		strings.HasSuffix(name, ".lock") {
		return false
	}
	for _, segment := range strings.Split(name, "/") {
		if segment == "" || segment == "." || segment == ".." || strings.HasPrefix(segment, "-") {
			return false
		}
	}
	return !strings.ContainsAny(name, "*?[]^~: \t\n\\\x7f\x00")
}

// validObjectID accepts a full hexadecimal object ID and nothing else. A revision
// expression could name something other than the object the caller decided about.
func validObjectID(revision string) bool {
	if len(revision) != 40 && len(revision) != 64 {
		return false
	}
	for _, r := range revision {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}
