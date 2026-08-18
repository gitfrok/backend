package main

import (
	"bufio"
	"context"
	"errors"
	"io"
	"strconv"
	"strings"

	repositoryv1 "github.com/gitfrok/backend/gen/proto/repository/v1"
)

// GetBlame attributes a file's lines at a revision (T-0056, SPEC-0053 AC2).
//
// The path is mandatory here — a blame with no file is not a question — and it is validated before
// any argument is assembled, then placed after `--`. See history.go for why the separator alone is
// not the safeguard.
func (s *Server) GetBlame(ctx context.Context, req *repositoryv1.GetBlameRequest) (*repositoryv1.GetBlameResponse, error) {
	op, err := s.prepareRead(ctx, req.GetContext())
	if err != nil || !validRevision(req.GetRevision()) || !validRepositoryPath(req.GetPath()) {
		return nil, unavailable()
	}
	ranges, capped, err := s.blame(ctx, op.path, req.GetRevision(), req.GetPath())
	if err != nil {
		return nil, unavailable()
	}
	return &repositoryv1.GetBlameResponse{Ranges: ranges, Capped: capped}, nil
}

// blameArgs assembles the git-blame invocation. Named for the same reason historyArgs is: the
// separator's presence and the path's position after it are the property under test.
func blameArgs(repositoryPath, revision, path string) []string {
	return []string{
		"-C", repositoryPath, "blame",
		// Porcelain gives one header per line with the commit and its identity, which is what
		// makes contiguous runs collapsible without a second pass over the file.
		"--line-porcelain",
		// Rename and copy detection are deliberately absent (SPEC-0053 open question 1): both are
		// heuristics, and a heuristic rendered without its uncertainty is an overclaim.
		revision,
		"--", path,
	}
}

// blame parses --line-porcelain into contiguous ranges.
//
// Porcelain repeats the full identity block for every line. Collapsing consecutive lines that share
// a commit is what keeps a 5000-line file from becoming 5000 near-identical messages — the ranges
// carry the same information in the shape a reader actually consumes it.
func (s *Server) blame(ctx context.Context, repositoryPath, revision, path string) ([]*repositoryv1.BlameRange, bool, error) {
	command := s.command(ctx, "git", blameArgs(repositoryPath, revision, path)...)
	output, err := command.StdoutPipe()
	if err != nil {
		return nil, false, err
	}
	if err := command.Start(); err != nil {
		return nil, false, err
	}

	var ranges []*repositoryv1.BlameRange
	var current *repositoryv1.BlameRange
	identities := map[string]*repositoryv1.CommitIdentity{}

	var commitID string
	var line int32
	var identity *repositoryv1.CommitIdentity
	capped := false

	scanner := bufio.NewScanner(output)
	scanner.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for scanner.Scan() {
		text := scanner.Text()
		switch {
		case strings.HasPrefix(text, "\t"):
			// The content line closes the current header block.
			if commitID == "" {
				continue
			}
			if identity == nil {
				identity = identities[commitID]
			} else {
				identities[commitID] = identity
			}
			if line > maxBlameLines {
				capped = true
				// Stop reading rather than keep parsing a file we will not attribute. The
				// response says capped, so what is returned is not mistakable for the whole.
				_ = command.Process.Kill()
				goto done
			}
			if current != nil && current.GetCommitId() == commitID {
				current.EndLine = line
			} else {
				current = &repositoryv1.BlameRange{
					StartLine: line, EndLine: line, CommitId: commitID, Identity: identity,
				}
				ranges = append(ranges, current)
			}
			commitID, identity = "", nil
		case strings.HasPrefix(text, "author "):
			identity = ensureIdentity(identity)
			identity.GitAuthorName = strings.TrimPrefix(text, "author ")
		case strings.HasPrefix(text, "author-mail "):
			identity = ensureIdentity(identity)
			identity.GitAuthorEmail = strings.Trim(strings.TrimPrefix(text, "author-mail "), "<>")
		case strings.HasPrefix(text, "committer "):
			identity = ensureIdentity(identity)
			identity.GitCommitterName = strings.TrimPrefix(text, "committer ")
		case strings.HasPrefix(text, "committer-mail "):
			identity = ensureIdentity(identity)
			identity.GitCommitterEmail = strings.Trim(strings.TrimPrefix(text, "committer-mail "), "<>")
		default:
			// A header line: "<sha> <orig-line> <final-line> [<count>]".
			fields := strings.Fields(text)
			if len(fields) >= 3 && len(fields[0]) >= 7 {
				if n, convErr := strconv.Atoi(fields[2]); convErr == nil {
					commitID = fields[0]
					line = int32(n)
				}
			}
		}
	}
	if err := scanner.Err(); err != nil && !errors.Is(err, io.EOF) {
		_ = command.Wait()
		return nil, false, err
	}

done:
	// A killed process reports an error that is not a failure of the read, so the capped case
	// deliberately does not surface it.
	if waitErr := command.Wait(); waitErr != nil && !capped {
		return nil, false, waitErr
	}
	return ranges, capped, nil
}

func ensureIdentity(i *repositoryv1.CommitIdentity) *repositoryv1.CommitIdentity {
	if i == nil {
		return &repositoryv1.CommitIdentity{}
	}
	return i
}
