package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"strconv"
	"strings"

	repositoryv1 "github.com/gitfrok/backend/gen/proto/repository/v1"
)

// History and blame (T-0056, SPEC-0053). Both are `git` invocations in the process that already
// shells out for ls-tree and for-each-ref, and both go through the same prepareRead — so they are
// the same `repo.read` decision the rest of this surface makes, not a second one.
//
// The dangerous input here is the PATH. It reaches a command line, and `git log -- <path>` with a
// path beginning `-` is a flag rather than a path: `--upload-pack=...` on the wrong side of the
// separator is a command execution primitive. Every invocation below places `--` before any
// caller-supplied path AND validates the path first, because the separator alone is one habit away
// from being dropped.

const (
	defaultHistoryPageSize = 50
	maxHistoryPageSize     = 200
	// maxBlameLines bounds one blame. A file longer than this is attributed up to the cap and the
	// response says `capped`, so a partial attribution can never be read as a whole one.
	maxBlameLines = 5000
)

// historyRecordSeparator and historyFieldSeparator are ASCII control characters that cannot appear
// in a git identity or subject, so a name containing a newline or a tab cannot forge a record
// boundary.
const (
	historyRecordSeparator = "\x1e"
	historyFieldSeparator  = "\x1f"
)

// historyFormat asks git for exactly the fields CommitIdentity carries — all of them git's own
// word, none of them a platform principal (SPEC-0053 AC8).
var historyFormat = strings.Join([]string{
	"%H", "%an", "%ae", "%cn", "%ce", "%aI", "%cI", "%s",
}, historyFieldSeparator) + historyRecordSeparator

// GetHistory returns a ref's commits, newest first.
func (s *Server) GetHistory(ctx context.Context, req *repositoryv1.GetHistoryRequest) (*repositoryv1.GetHistoryResponse, error) {
	op, err := s.prepareRead(ctx, req.GetContext())
	if err != nil || !validRevision(req.GetRevision()) {
		return nil, unavailable()
	}
	// An absent path means the whole ref. A present one must be a path, and the check happens
	// before any argument is assembled.
	path := req.GetPath()
	if path != "" && !validRepositoryPath(path) {
		return nil, unavailable()
	}

	pageSize := int(req.GetPageSize())
	if pageSize == 0 {
		pageSize = defaultHistoryPageSize
	}
	if pageSize < 0 || pageSize > maxHistoryPageSize {
		return nil, unavailable()
	}

	skip := 0
	if req.GetPageToken() != "" {
		cursor, ok := s.parseHistoryCursor(req.GetPageToken())
		// The cursor is bound to every input that shapes the walk. A cursor from another
		// repository, revision or path is refused rather than reinterpreted — reinterpreting it
		// would resume someone else's walk in this caller's tenant.
		if !ok || cursor.TenantID != op.tenantID || cursor.RepositoryID != op.repositoryID ||
			cursor.Revision != req.GetRevision() || cursor.Path != path {
			return nil, unavailable()
		}
		skip = cursor.Skip
	}

	commits, more, err := s.historyPage(ctx, op.path, req.GetRevision(), path, skip, pageSize)
	if err != nil {
		return nil, unavailable()
	}
	response := &repositoryv1.GetHistoryResponse{Commits: commits}
	if more {
		response.NextPageToken = s.historyCursor(historyCursor{
			TenantID: op.tenantID, RepositoryID: op.repositoryID,
			Revision: req.GetRevision(), Path: path, Skip: skip + len(commits),
		})
	}
	return response, nil
}

// historyArgs assembles the git-log invocation.
//
// It is a named function so the argument order is testable without running git: the `--` separator
// and the path's position after it are the property under test, and a test that had to execute git
// to see them would be proving something else.
func historyArgs(repositoryPath, revision, path string, skip, pageSize int) []string {
	args := []string{
		"-C", repositoryPath, "log",
		"--format=" + historyFormat,
		"--skip=" + strconv.Itoa(skip),
		// One more than the page, so "is there another page" is answered by the walk rather than
		// by a count the caller would have to trust.
		"--max-count=" + strconv.Itoa(pageSize+1),
		revision,
	}
	// The separator goes in whether or not there is a path: an empty tail after `--` is harmless,
	// and a separator that is only sometimes present is one refactor away from sometimes missing.
	args = append(args, "--")
	if path != "" {
		args = append(args, path)
	}
	return args
}

func (s *Server) historyPage(ctx context.Context, repositoryPath, revision, path string, skip, pageSize int) ([]*repositoryv1.Commit, bool, error) {
	command := s.command(ctx, "git", historyArgs(repositoryPath, revision, path, skip, pageSize)...)
	output, err := command.StdoutPipe()
	if err != nil {
		return nil, false, err
	}
	if err := command.Start(); err != nil {
		return nil, false, err
	}
	reader := bufio.NewReader(output)
	commits := make([]*repositoryv1.Commit, 0, pageSize)
	more := false
	for {
		record, readErr := reader.ReadString(historyRecordSeparator[0])
		if trimmed := strings.Trim(strings.TrimSuffix(record, historyRecordSeparator), "\n"); trimmed != "" {
			commit, parseErr := parseCommit(trimmed)
			if parseErr != nil {
				_ = command.Wait()
				return nil, false, parseErr
			}
			if len(commits) < pageSize {
				commits = append(commits, commit)
			} else {
				more = true
			}
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
	return commits, more, nil
}

func parseCommit(record string) (*repositoryv1.Commit, error) {
	fields := strings.Split(record, historyFieldSeparator)
	if len(fields) != 8 {
		return nil, errors.New("git-storaged: malformed history record")
	}
	return &repositoryv1.Commit{
		CommitId: fields[0],
		Identity: &repositoryv1.CommitIdentity{
			GitAuthorName:     fields[1],
			GitAuthorEmail:    fields[2],
			GitCommitterName:  fields[3],
			GitCommitterEmail: fields[4],
			AuthoredAt:        fields[5],
			CommittedAt:       fields[6],
		},
		Subject: fields[7],
	}, nil
}

// historyCursor is a position in the walk, bound to everything that shapes it.
type historyCursor struct {
	TenantID     string
	RepositoryID string
	Revision     string
	Path         string
	Skip         int
}

func (s *Server) historyCursor(c historyCursor) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strings.Join([]string{
		"v1", c.TenantID, c.RepositoryID, c.Revision, c.Path, strconv.Itoa(c.Skip),
	}, "\x00")))
}

func (s *Server) parseHistoryCursor(token string) (historyCursor, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return historyCursor{}, false
	}
	parts := strings.Split(string(raw), "\x00")
	if len(parts) != 6 || parts[0] != "v1" {
		return historyCursor{}, false
	}
	skip, err := strconv.Atoi(parts[5])
	if err != nil || skip < 0 {
		return historyCursor{}, false
	}
	return historyCursor{
		TenantID: parts[1], RepositoryID: parts[2], Revision: parts[3], Path: parts[4], Skip: skip,
	}, true
}
