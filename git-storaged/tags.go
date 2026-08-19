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

// Tags (T-0064, SPEC-0056 AC1). Another `git for-each-ref` on the surface that already reads the
// bare repository, through the same prepareRead every other read here uses.
//
// A tag's target is dereferenced with `^{}` so an ANNOTATED tag reports the commit it points at
// rather than the tag object's own SHA. Without that, an annotated release tag would record a
// commit that is not a commit, and every later comparison against it would be false.

const (
	defaultTagPageSize = 100
	maxTagPageSize     = 500
)

// ListTags serves a repository's tags with the commit each points at NOW.
func (s *Server) ListTags(ctx context.Context, req *repositoryv1.ListTagsRequest) (*repositoryv1.ListTagsResponse, error) {
	op, err := s.prepareRead(ctx, req.GetContext())
	if err != nil {
		return nil, unavailable()
	}
	pageSize := int(req.GetPageSize())
	if pageSize == 0 {
		pageSize = defaultTagPageSize
	}
	if pageSize < 0 || pageSize > maxTagPageSize {
		return nil, unavailable()
	}
	offset := 0
	if req.GetPageToken() != "" {
		cursor, ok := s.parseTagCursor(req.GetPageToken())
		if !ok || cursor.TenantID != op.tenantID || cursor.RepositoryID != op.repositoryID {
			return nil, unavailable()
		}
		offset = cursor.Offset
	}
	tags, more, err := s.tagPage(ctx, op.path, offset, pageSize)
	if err != nil {
		return nil, unavailable()
	}
	response := &repositoryv1.ListTagsResponse{Tags: tags}
	if more {
		response.NextPageToken = s.tagCursor(tagCursor{
			TenantID: op.tenantID, RepositoryID: op.repositoryID, Offset: offset + len(tags),
		})
	}
	return response, nil
}

// tagArgs assembles the invocation. Named so the format is testable without running git.
//
// `creatordate` sorts newest first for both lightweight and annotated tags. `*objectname` is the
// dereferenced target and is empty for a lightweight tag, where `objectname` already is the commit.
func tagArgs(repositoryPath string) []string {
	return []string{
		"-C", repositoryPath, "for-each-ref",
		"--sort=-creatordate",
		"--format=%(refname:short)\x1f%(objectname)\x1f%(*objectname)",
		"refs/tags",
	}
}

func (s *Server) tagPage(ctx context.Context, repositoryPath string, offset, pageSize int) ([]*repositoryv1.Tag, bool, error) {
	command := s.command(ctx, "git", tagArgs(repositoryPath)...)
	output, err := command.StdoutPipe()
	if err != nil {
		return nil, false, err
	}
	if err := command.Start(); err != nil {
		return nil, false, err
	}
	reader := bufio.NewReader(output)
	tags := make([]*repositoryv1.Tag, 0, pageSize)
	index := 0
	more := false
	for {
		line, readErr := reader.ReadString('\n')
		if trimmed := strings.TrimRight(line, "\n"); trimmed != "" {
			if tag := parseTag(trimmed); tag != nil {
				if index >= offset {
					if len(tags) < pageSize {
						tags = append(tags, tag)
					} else {
						more = true
					}
				}
				index++
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
	return tags, more, nil
}

// parseTag reads one for-each-ref record.
//
// The dereferenced target wins when present: an annotated tag's own objectname is the tag object,
// not the commit, and recording the wrong one would make a release describe something that is not
// a commit.
func parseTag(record string) *repositoryv1.Tag {
	fields := strings.Split(record, "\x1f")
	if len(fields) != 3 || fields[0] == "" {
		return nil
	}
	commit := fields[1]
	if fields[2] != "" {
		commit = fields[2]
	}
	if commit == "" {
		return nil
	}
	return &repositoryv1.Tag{Name: fields[0], CommitId: commit}
}

type tagCursor struct {
	TenantID     string
	RepositoryID string
	Offset       int
}

func (s *Server) tagCursor(c tagCursor) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strings.Join([]string{
		"v1", c.TenantID, c.RepositoryID, strconv.Itoa(c.Offset),
	}, "\x00")))
}

func (s *Server) parseTagCursor(token string) (tagCursor, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return tagCursor{}, false
	}
	parts := strings.Split(string(raw), "\x00")
	if len(parts) != 4 || parts[0] != "v1" {
		return tagCursor{}, false
	}
	offset, err := strconv.Atoi(parts[3])
	if err != nil || offset < 0 {
		return tagCursor{}, false
	}
	return tagCursor{TenantID: parts[1], RepositoryID: parts[2], Offset: offset}, true
}
