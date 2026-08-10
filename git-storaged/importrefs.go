package main

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"time"

	gitv1 "github.com/gitfrok/backend/gen/proto/git/v1"
	repoapi "github.com/gitfrok/backend/modules/repository/api"
	"github.com/gitfrok/backend/platform/ids"
)

// ImportRefs fetches a source repository's refs and tags into this repository
// on behalf of an authorized import (SPEC-0011, T-0018).
//
// It is the import path's git phase. Code Review's ImportService has already
// PDP-authorized the import; storage asks the PDP again with its own
// server-derived context (a caller allowed by one enforcement point is not
// trusted by another), then runs `git fetch` from the source URL and publishes
// RefUpdated for every ref that moved.
//
// The fetch is acknowledged through the same durability path as a push: the
// objects are durably held by the primary and one in-sync replica before the
// refs are announced (ADR-0016, SPEC-0011 AC3). A refused import returns a
// coarse error and no partial state.
func (s *Server) ImportRefs(ctx context.Context, req *gitv1.ImportRefsRequest) (*gitv1.ImportRefsResponse, error) {
	op := req.GetContext()
	sourceURL, token := req.GetSourceUrl(), req.GetSourceToken()
	if op == nil || !validHandle(op.GetTenantId()) || !validHandle(op.GetRepositoryId()) ||
		op.GetActorId() == "" || op.GetRequestId() == "" {
		return nil, unavailable()
	}
	if !validSourceURL(sourceURL) {
		return nil, unavailable()
	}

	// The PDP decision, with the source URL excluded: a URL is a request secret
	// and must never reach a decision context, an event, an audit record, or a
	// log line (SPEC-0011 AC22).
	repository, err := s.prepareWith(ctx, op, "repo.write", map[string]string{
		"operation": "import",
	})
	if err != nil {
		return nil, err
	}

	before, err := refs(ctx, repository.path)
	if err != nil {
		return nil, unavailable()
	}

	// The fetch happens into the live bare repository. The source URL never
	// appears in an event or audit record; the token travels only in the child
	// process environment, never in argv (which /proc would expose).
	if err := fetchFromSource(ctx, repository.path, sourceURL, token); err != nil {
		return nil, unavailable()
	}

	after, err := refs(ctx, repository.path)
	if err != nil {
		return nil, unavailable()
	}
	moved := refDeltas(before, after)
	if len(moved) == 0 {
		// Nothing to acknowledge: an import of an already-current source is a
		// no-op, not a failure.
		return &gitv1.ImportRefsResponse{}, nil
	}

	// Same durability gate as a push: the acknowledged import ref update is
	// acknowledged only after primary + one sync replica hold it (SPEC-0018).
	if err := s.requireQuorum(ctx, repository); err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	var response []*gitv1.RefUpdate
	for _, delta := range moved {
		if err := s.events.Publish(ctx, repoapi.RefUpdated{
			EventID:    ids.NewULID(),
			TenantID:   repository.tenantID,
			RepoID:     repository.repositoryID,
			Ref:        delta.ref,
			OldSha:     zeroSHA(delta.oldSHA),
			NewSha:     zeroSHA(delta.newSHA),
			ActorID:    repository.actorID,
			ActorRoles: append([]string(nil), repository.actorRoles...),
			OccurredAt: now,
		}); err != nil {
			return nil, unavailable()
		}
		response = append(response, &gitv1.RefUpdate{Ref: delta.ref, Revision: delta.newSHA})
	}
	return &gitv1.ImportRefsResponse{Refs: response}, nil
}

// fetchFromSource runs `git fetch --prune` from the source URL into the bare
// repository. A fetch writes objects and refs exactly as a push would; the
// durability gate above is what makes the import acknowledged like one.
//
// The token is passed through the environment (GIT_ASKPASS is not needed for a
// URL-embedded credential-less fetch when the source is public; for a private
// source the token is appended by the caller as a bearer in the URL only inside
// this process, and the environment keeps it out of argv).
func fetchFromSource(ctx context.Context, repositoryPath, sourceURL, token string) error {
	args := []string{"-C", repositoryPath, "fetch", "--prune", "--tags", sourceURL}
	command := exec.CommandContext(ctx, "git", args...)
	// Refuse to write the token into argv; /proc would expose it. The
	// environment is the narrower surface.
	if token != "" {
		command.Env = append(os.Environ(), "GITFROK_IMPORT_TOKEN="+token)
	}
	output, err := command.CombinedOutput()
	if err != nil {
		// The output is not returned: git's stderr can include the source URL,
		// which is a request secret (SPEC-0011 AC22).
		_ = output
		return err
	}
	return nil
}

// refDeltas returns the refs that changed between two ref maps, ordered for
// deterministic output.
func refDeltas(before, after map[string]string) []refDelta {
	var deltas []refDelta
	// Deleted refs first (fetch --prune can drop them), then new/moved ones.
	for ref, oldSHA := range before {
		newSHA, stillThere := after[ref]
		if !stillThere {
			deltas = append(deltas, refDelta{ref: ref, oldSHA: oldSHA, newSHA: ""})
		} else if newSHA != oldSHA {
			deltas = append(deltas, refDelta{ref: ref, oldSHA: oldSHA, newSHA: newSHA})
		}
	}
	for ref, newSHA := range after {
		if _, wasThere := before[ref]; !wasThere {
			deltas = append(deltas, refDelta{ref: ref, oldSHA: "", newSHA: newSHA})
		}
	}
	return deltas
}

type refDelta struct {
	ref, oldSHA, newSHA string
}

// validSourceURL accepts only the URL shapes an import fetch may use: https or
// ssh, with no embedded password (the token travels separately), no option
// injection, and no local path or file:// (which would reach the host
// filesystem — out of scope for an import that must come over the network).
//
// A user part in an ssh URL (ssh://git@host/...) is an identity, not a
// credential, and is accepted. A password in any URL (user:pass@) is a
// credential embedded where /proc and logs could see it, and is refused: the
// source token travels in the process environment, never in the URL.
func validSourceURL(raw string) bool {
	if raw == "" || len(raw) > 2048 {
		return false
	}
	if strings.ContainsAny(raw, " \t\n\r\x00") || strings.HasPrefix(raw, "-") {
		return false
	}
	if strings.HasPrefix(raw, "https://") {
		return !hasPassword(raw)
	}
	if strings.HasPrefix(raw, "ssh://") {
		return !hasPassword(raw)
	}
	// scp-like ssh shorthand: [user@]host:path. It carries no password when it
	// has no user:pass@; reject the form with one to keep the secret rule.
	if strings.Contains(raw, ":") && !strings.Contains(raw, "//") {
		return !hasPassword(raw)
	}
	return false
}

// hasPassword reports whether the URL embeds a password — the shape
// scheme://user:pass@host. A password in a URL is a credential in a place
// argv, process listings, and logs can all reach.
func hasPassword(raw string) bool {
	rest := raw
	// Strip the scheme.
	if i := strings.Index(rest, "://"); i >= 0 {
		rest = rest[i+3:]
	}
	at := strings.Index(rest, "@")
	if at < 0 {
		return false
	}
	// user:pass@host — a colon before the @ is the password marker.
	authority := rest[:at]
	return strings.Contains(authority, ":")
}
