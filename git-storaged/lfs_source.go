package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// The source side of an LFS import (SPEC-0023 AC6, decision 2).
//
// The platform speaks the source's LFS batch API itself rather than shelling out
// to `git lfs`. Two reasons, both recorded at spec review: the source token stays
// in the request this process makes and never reaches a child process's
// configuration (SPEC-0011 AC22), and the platform keeps control of what it
// fetches and how that work is paced.

// lfsBatchRequest is the batch API request body.
type lfsBatchRequest struct {
	Operation string           `json:"operation"`
	Transfers []string         `json:"transfers"`
	Objects   []lfsBatchObject `json:"objects"`
}

type lfsBatchObject struct {
	OID  string `json:"oid"`
	Size int64  `json:"size"`
}

// lfsBatchResponse is the subset of the response this client uses.
type lfsBatchResponse struct {
	Transfer string `json:"transfer"`
	Objects  []struct {
		OID     string `json:"oid"`
		Size    int64  `json:"size"`
		Actions struct {
			Download *struct {
				Href   string            `json:"href"`
				Header map[string]string `json:"header"`
			} `json:"download"`
		} `json:"actions"`
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	} `json:"objects"`
}

// lfsSourceEndpoint derives the source's LFS endpoint from its clone URL, which
// is what a git-lfs client does when a repository declares no explicit endpoint.
//
// Only https is accepted. An ssh clone URL has no LFS endpoint without asking the
// server for one over ssh, and this client does not: an import whose LFS endpoint
// cannot be derived says so rather than guessing a hostname.
func lfsSourceEndpoint(sourceURL string) (string, error) {
	if !strings.HasPrefix(sourceURL, "https://") {
		return "", fmt.Errorf("lfs: no LFS endpoint can be derived from %q", schemeOf(sourceURL))
	}
	parsed, err := url.Parse(sourceURL)
	if err != nil {
		return "", fmt.Errorf("lfs: source URL is not a URL: %w", err)
	}
	parsed.User = nil
	parsed.Path = strings.TrimSuffix(parsed.Path, "/")
	if !strings.HasSuffix(parsed.Path, ".git") {
		parsed.Path += ".git"
	}
	parsed.Path += "/info/lfs"
	return parsed.String(), nil
}

// schemeOf names a URL's scheme for an error message without ever echoing the URL
// itself, which is a request secret (SPEC-0011 AC22).
func schemeOf(raw string) string {
	if scheme, _, found := strings.Cut(raw, "://"); found {
		return scheme + "://…"
	}
	return "a URL with no scheme"
}

// sourceLFSClient fetches objects from a source's LFS endpoint.
type sourceLFSClient struct {
	http *http.Client
	// pace is called before each source request, so an import yields to
	// interactive traffic (SPEC-0011 AC21 applied to LFS, SPEC-0023 §non-functional).
	pace func(context.Context) error
}

func newSourceLFSClient() *sourceLFSClient {
	return &sourceLFSClient{
		http: &http.Client{Timeout: 10 * time.Minute},
		pace: func(context.Context) error { return nil },
	}
}

// batchDownload asks the source where the given objects can be fetched from.
//
// The token travels as a bearer header on this request only. It is never written
// to a log, an event, or an error: the errors below name a status code and an
// object, never a URL or a credential (SPEC-0011 AC22, SPEC-0023 AC8).
func (c *sourceLFSClient) batchDownload(ctx context.Context, endpoint, token string, pointers []lfsPointer) (*lfsBatchResponse, error) {
	objects := make([]lfsBatchObject, 0, len(pointers))
	for _, pointer := range pointers {
		objects = append(objects, lfsBatchObject{OID: pointer.oid, Size: pointer.size})
	}
	body, err := json.Marshal(lfsBatchRequest{
		Operation: "download",
		Transfers: []string{"basic"},
		Objects:   objects,
	})
	if err != nil {
		return nil, err
	}
	if err := c.pace(ctx); err != nil {
		return nil, err
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/objects/batch", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/vnd.git-lfs+json")
	request.Header.Set("Content-Type", "application/vnd.git-lfs+json")
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}

	response, err := c.http.Do(request)
	if err != nil {
		// The transport error is not wrapped: it can carry the URL, which is a
		// request secret.
		return nil, fmt.Errorf("lfs: source batch request failed")
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode == http.StatusTooManyRequests {
		// The source is rate limiting. This is the same signal the history phase
		// treats as a stall, not a failure (SPEC-0011 AC8).
		return nil, errSourceRateLimited
	}
	if response.StatusCode/100 != 2 {
		return nil, fmt.Errorf("lfs: source batch returned status %d", response.StatusCode)
	}
	var batch lfsBatchResponse
	if err := json.NewDecoder(io.LimitReader(response.Body, 32<<20)).Decode(&batch); err != nil {
		return nil, fmt.Errorf("lfs: source batch response is not readable")
	}
	return &batch, nil
}

// fetchObject streams one object from the href the batch response named.
func (c *sourceLFSClient) fetchObject(ctx context.Context, href string, headers map[string]string) (io.ReadCloser, error) {
	if err := c.pace(ctx); err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, href, nil)
	if err != nil {
		return nil, fmt.Errorf("lfs: object href is not usable")
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return nil, fmt.Errorf("lfs: object fetch failed")
	}
	if response.StatusCode == http.StatusTooManyRequests {
		_ = response.Body.Close()
		return nil, errSourceRateLimited
	}
	if response.StatusCode/100 != 2 {
		_ = response.Body.Close()
		return nil, fmt.Errorf("lfs: object fetch returned status %d", response.StatusCode)
	}
	return response.Body, nil
}
