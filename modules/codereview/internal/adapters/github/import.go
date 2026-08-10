// Package github imports pull-request history from a GitHub source as
// ATTESTED_IMPORT records (SPEC-0011, ADR-0029, T-0018).
//
// What it does and does not claim, stated plainly: this package fetches what
// the GitHub API returns and stores it verbatim, with a provenance block that
// says "the source asserted this" — never "we witnessed this". Imported
// approvals never satisfy a merge policy, imported actors stay opaque foreign
// handles, and no imported record ever reaches the audit log. The import
// operation itself is the only first-party audit event (emitted by the import
// service, not here).
package github

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gitfrok/backend/modules/codereview/api"
	"github.com/gitfrok/backend/modules/codereview/internal/app"
)

// Client fetches GitHub pull-request history. The base URL is injected so a
// self-hosted GitHub instance works and tests never touch the network.
type Client struct {
	base    string
	http    *http.Client
	records api.ImportedRecordStore
	pacer   app.Pacer
}

// New wires the importer. records is where imported history is stored.
func New(records api.ImportedRecordStore, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{base: "https://api.github.com", http: httpClient, records: records, pacer: app.NoPacer{}}
}

// WithPacer paces this importer's source calls. Import work asks before every
// fetch, so it yields throughput to the interactive traffic it shares a plane
// with (SPEC-0011 AC21).
func (c *Client) WithPacer(pacer app.Pacer) *Client {
	if pacer != nil {
		c.pacer = pacer
	}
	return c
}

// fetchState is one import's own accounting: the response bytes read so far. A
// Client serves many imports, so the count cannot live on it.
type fetchState struct {
	read int64
}

// source is the parsed owner/repo from a source URL.
type source struct {
	owner, repo string
}

// parseSource extracts owner/repo from a GitHub URL: https://github.com/owner/repo[.git]
// or the scp-like ssh form [user@]host:owner/repo[.git].
func parseSource(raw string) (source, bool) {
	if raw == "" {
		return source{}, false
	}
	path := raw
	if !strings.Contains(raw, "://") {
		// scp-like ssh shorthand: [user@]host:owner/repo. The host:path split
		// is the first colon; everything after is the path.
		colon := strings.Index(raw, ":")
		if colon < 0 {
			return source{}, false
		}
		path = raw[colon+1:]
	} else {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			return source{}, false
		}
		path = u.Path
	}
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) < 2 {
		return source{}, false
	}
	owner, repo := parts[0], parts[1]
	if owner == "" || repo == "" || strings.ContainsAny(owner+repo, " \t\r\n") {
		return source{}, false
	}
	repo = strings.TrimSuffix(repo, ".git")
	return source{owner: owner, repo: repo}, true
}

// ImportHistory implements the Code Review history port. It fetches the source
// pull requests and their reviews, stores them as ATTESTED_IMPORT records, and
// returns per-type counts for the manifest digest (AC16).
func (c *Client) ImportHistory(ctx context.Context, command app.ImportHistoryCommand) (app.HistoryResult, error) {
	src, ok := parseSource(command.SourceURL)
	if !ok {
		return app.HistoryResult{}, fmt.Errorf("github import: cannot parse source %q", command.SourceURL)
	}

	// st is this import's own accounting, threaded through every fetch.
	st := &fetchState{}
	prs, err := c.listPullRequests(ctx, st, src, command.SourceToken)
	if err != nil {
		return app.HistoryResult{}, err
	}

	counts := map[string]int64{"merge_requests": int64(len(prs))}
	records := make([]api.ImportedMergeRequest, 0, len(prs))
	for _, pr := range prs {
		record, err := c.buildRecord(ctx, st, src, command, pr)
		if err != nil {
			return app.HistoryResult{}, err
		}
		records = append(records, record)
		counts["comments"] += int64(len(record.Threads))
		counts["approvals"] += int64(len(record.Approvals))
	}

	if err := c.records.PutImport(ctx, command.ImportID, records); err != nil {
		return app.HistoryResult{}, err
	}
	return app.HistoryResult{Counts: counts, SourceBytesRead: st.read}, nil
}

// buildRecord shapes one pull request plus its reviews into an imported MR.
func (c *Client) buildRecord(ctx context.Context, st *fetchState, src source, command app.ImportHistoryCommand, pr pullRequest) (api.ImportedMergeRequest, error) {
	digest, err := payloadDigest(pr)
	if err != nil {
		return api.ImportedMergeRequest{}, err
	}
	provenance := api.Provenance{
		Class:          api.AttestImported,
		ImportID:       command.ImportID,
		SourceSystem:   "github",
		SourceInstance: command.SourceInstance,
		SourceRef:      strconv.FormatInt(pr.Number, 10),
		DeclaredActor:  pr.User.Login,
		DeclaredAt:     pr.CreatedAt,
		PayloadDigest:  digest,
	}

	reviews, err := c.listReviews(ctx, st, src, pr.Number, command.SourceToken)
	if err != nil {
		return api.ImportedMergeRequest{}, err
	}
	threads := make([]api.ImportedThread, 0, len(reviews))
	approvals := make([]api.ImportedApproval, 0)
	for _, review := range reviews {
		if strings.EqualFold(review.State, "approved") {
			approvalDigest, err := payloadDigest(review)
			if err != nil {
				return api.ImportedMergeRequest{}, err
			}
			approvalProvenance := provenance
			approvalProvenance.PayloadDigest = approvalDigest
			approvalProvenance.DeclaredActor = review.User.Login
			approvalProvenance.DeclaredAt = review.SubmittedAt
			approvals = append(approvals, api.ImportedApproval{
				ApprovalID:     fmt.Sprintf("%d", review.ID),
				MergeRequestID: fmt.Sprintf("%d", pr.Number),
				DeclaredActor:  review.User.Login,
				DeclaredAt:     review.SubmittedAt,
				Provenance:     approvalProvenance,
			})
		}
		if review.Body != "" {
			// A review summary carries no diff position, so it attaches to the
			// merge request itself rather than claiming a file it never named
			// (AC5). Its digest covers the review's own payload.
			reviewDigest, err := payloadDigest(review)
			if err != nil {
				return api.ImportedMergeRequest{}, err
			}
			reviewProvenance := provenance
			reviewProvenance.PayloadDigest = reviewDigest
			reviewProvenance.DeclaredActor = review.User.Login
			reviewProvenance.DeclaredAt = review.SubmittedAt
			threads = append(threads, api.ImportedThread{
				ThreadID:       fmt.Sprintf("review-%d", review.ID),
				MergeRequestID: fmt.Sprintf("%d", pr.Number),
				Path:           review.Path,
				Anchor:         api.DeclaredAnchor(review.Path),
				Comments: []api.ImportedComment{{
					CommentID:     fmt.Sprintf("review-%d", review.ID),
					DeclaredActor: review.User.Login,
					Body:          review.Body,
					DeclaredAt:    review.SubmittedAt,
					Provenance:    reviewProvenance,
				}},
				Provenance: reviewProvenance,
			})
		}
	}

	// Line comments are a separate GitHub surface from reviews. Each keeps the
	// position the source declared; one whose line no longer resolves degrades
	// to the file, and is never dropped (AC5).
	comments, err := c.listReviewComments(ctx, st, src, pr.Number, command.SourceToken)
	if err != nil {
		return api.ImportedMergeRequest{}, err
	}
	for _, comment := range comments {
		commentDigest, err := payloadDigest(comment)
		if err != nil {
			return api.ImportedMergeRequest{}, err
		}
		commentProvenance := provenance
		commentProvenance.PayloadDigest = commentDigest
		commentProvenance.DeclaredActor = comment.User.Login
		commentProvenance.DeclaredAt = comment.CreatedAt
		threads = append(threads, api.ImportedThread{
			ThreadID:       fmt.Sprintf("comment-%d", comment.ID),
			MergeRequestID: fmt.Sprintf("%d", pr.Number),
			Path:           comment.Path,
			Anchor:         api.DeclaredAnchor(comment.Path),
			Comments: []api.ImportedComment{{
				CommentID:     fmt.Sprintf("comment-%d", comment.ID),
				DeclaredActor: comment.User.Login,
				Body:          comment.Body,
				DeclaredAt:    comment.CreatedAt,
				Provenance:    commentProvenance,
			}},
			Provenance: commentProvenance,
		})
	}

	return api.ImportedMergeRequest{
		MergeRequestID: fmt.Sprintf("%d", pr.Number),
		SourceRef:      pr.Head.Ref,
		TargetRef:      pr.Base.Ref,
		Title:          pr.Title,
		Description:    pr.Body,
		State:          pr.State,
		CreatorID:      pr.User.Login,
		Threads:        threads,
		Approvals:      approvals,
		Provenance:     provenance,
	}, nil
}

// listPullRequests fetches every PR (open + closed) for the source repository,
// page by page. A repository with more history than one page holds must not
// import as a silently truncated set: the import would report its partial counts
// as if they were the whole backlog.
func (c *Client) listPullRequests(ctx context.Context, st *fetchState, src source, token string) ([]pullRequest, error) {
	var all []pullRequest
	for _, state := range []string{"open", "closed"} {
		batch, err := fetchPages[pullRequest](ctx, c, st, token, func(page int) string {
			return fmt.Sprintf("%s/repos/%s/%s/pulls?state=%s&per_page=%d&page=%d&sort=created&direction=asc",
				c.base, src.owner, src.repo, state, pageSize, page)
		})
		if err != nil {
			return nil, err
		}
		all = append(all, batch...)
	}
	return all, nil
}

// pageSize is the per-page ceiling the GitHub API honours.
const pageSize = 100

// maxPages bounds a paging loop so a source that keeps returning full pages
// cannot spin forever. Reaching it is an error, never a quiet truncation.
const maxPages = 1000

// fetchPages walks a paged GitHub collection until a short page ends it.
func fetchPages[T any](ctx context.Context, c *Client, st *fetchState, token string, pageURL func(page int) string) ([]T, error) {
	var all []T
	for page := 1; page <= maxPages; page++ {
		var batch []T
		if err := c.getJSON(ctx, st, pageURL(page), token, &batch); err != nil {
			return nil, err
		}
		all = append(all, batch...)
		if len(batch) < pageSize {
			return all, nil
		}
	}
	return nil, fmt.Errorf("github import: source has more than %d pages", maxPages)
}

// listReviews fetches the reviews for one pull request.
func (c *Client) listReviews(ctx context.Context, st *fetchState, src source, number int64, token string) ([]pullReview, error) {
	return fetchPages[pullReview](ctx, c, st, token, func(page int) string {
		return fmt.Sprintf("%s/repos/%s/%s/pulls/%d/reviews?per_page=%d&page=%d", c.base, src.owner, src.repo, number, pageSize, page)
	})
}

// listReviewComments fetches the line comments for one pull request.
func (c *Client) listReviewComments(ctx context.Context, st *fetchState, src source, number int64, token string) ([]reviewComment, error) {
	return fetchPages[reviewComment](ctx, c, st, token, func(page int) string {
		return fmt.Sprintf("%s/repos/%s/%s/pulls/%d/comments?per_page=%d&page=%d", c.base, src.owner, src.repo, number, pageSize, page)
	})
}

// getJSON performs one authenticated GET and decodes the JSON body.
func (c *Client) getJSON(ctx context.Context, st *fetchState, path, token string, into any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	// The token is request-only: it never becomes a log line, an event, or an
	// audit record (SPEC-0011 AC22).
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	request.Header.Set("Accept", "application/vnd.github+json")

	// Every fetch waits its turn before it runs (AC21).
	if err := c.pacer.Wait(ctx); err != nil {
		return err
	}

	response, err := c.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		// Rate limiting (HTTP 403/429) means a stalled import, not a failed one
		// (AC8); the caller's state machine records STALLED.
		if response.StatusCode == http.StatusForbidden || response.StatusCode == http.StatusTooManyRequests {
			return app.ErrImportStalled
		}
		// The body is not read into an error: it can echo the URL's owner/repo
		// but never a token, and a coarse error is all a caller needs.
		return fmt.Errorf("github import: status %d", response.StatusCode)
	}
	// The response body is hashed as received for the payload digest — the
	// reproducible handle (AC16). Decode from the same bytes.
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}
	// What the source's responses weighed on the wire. It is ingress, reported
	// for observability — the bytes a tenant is charged for are the ones storage
	// says it wrote (AC21).
	st.read += int64(len(body))
	if err := json.Unmarshal(body, into); err != nil {
		return err
	}
	return nil
}

// payloadDigest is a SHA-256 over the canonical JSON of a fetched object, so a
// post-import mutation is detectable against the manifest (AC16).
func payloadDigest(v any) (string, error) {
	canonical, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

// pullRequest is the subset of the GitHub PR API shape this importer needs.
type pullRequest struct {
	Number    int64     `json:"number"`
	Title     string    `json:"title"`
	Body      string    `json:"body"`
	State     string    `json:"state"`
	User      ghUser    `json:"user"`
	CreatedAt time.Time `json:"created_at"`
	Head      ghRef     `json:"head"`
	Base      ghRef     `json:"base"`
}

// pullReview is the subset of the GitHub review API shape.
type pullReview struct {
	ID          int64     `json:"id"`
	State       string    `json:"state"`
	Body        string    `json:"body"`
	Path        string    `json:"path"`
	User        ghUser    `json:"user"`
	SubmittedAt time.Time `json:"submitted_at"`
}

// reviewComment is the subset of the GitHub review-comment API shape this
// importer needs. line is absent (0) once the source considers the comment
// outdated, which is what degrades its anchor to the file (AC5).
type reviewComment struct {
	ID        int64     `json:"id"`
	Body      string    `json:"body"`
	Path      string    `json:"path"`
	Line      int64     `json:"line"`
	User      ghUser    `json:"user"`
	CreatedAt time.Time `json:"created_at"`
}

type ghUser struct {
	Login string `json:"login"`
}

type ghRef struct {
	Ref string `json:"ref"`
}
