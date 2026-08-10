// Package gitlab imports merge-request history from a GitLab source as
// ATTESTED_IMPORT records (SPEC-0011, ADR-0029, T-0018).
//
// It mirrors the GitHub adapter: what the GitLab API returns is stored
// verbatim with a provenance block that says "the source asserted this" —
// never "we witnessed this". Imported approvals never satisfy a merge policy,
// imported actors stay opaque foreign handles, and no imported record ever
// reaches the audit log.
package gitlab

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

// Client fetches GitLab merge-request history. The base is the API root
// (https://gitlab.com/api/v4, or a self-hosted instance's), injected so tests
// never touch the network.
type Client struct {
	base    string
	http    *http.Client
	records api.ImportedRecordStore
}

// New wires the importer. records is where imported history is stored.
func New(records api.ImportedRecordStore, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{base: "https://gitlab.com/api/v4", http: httpClient, records: records}
}

// source is the parsed namespace/project from a source URL.
type source struct {
	namespace, project string
}

// parseSource extracts namespace/project from a GitLab URL:
// https://gitlab.com/group/subgroup/project[.git].
func parseSource(raw string) (source, bool) {
	if raw == "" {
		return source{}, false
	}
	path := raw
	if !strings.Contains(raw, "://") {
		// scp-like ssh shorthand: [user@]host:group/project.
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
	// GitLab allows nested groups: everything but the last segment is the
	// namespace.
	namespace := strings.Join(parts[:len(parts)-1], "/")
	project := strings.TrimSuffix(parts[len(parts)-1], ".git")
	if namespace == "" || project == "" || strings.ContainsAny(namespace+project, " \t\r\n") {
		return source{}, false
	}
	return source{namespace: namespace, project: project}, true
}

// ImportHistory implements the Code Review history port. It fetches the source
// merge requests and their approvals and notes, stores them as ATTESTED_IMPORT
// records, and returns per-type counts for the manifest digest (AC16).
func (c *Client) ImportHistory(ctx context.Context, command app.ImportHistoryCommand) (map[string]int64, error) {
	src, ok := parseSource(command.SourceURL)
	if !ok {
		return nil, fmt.Errorf("gitlab import: cannot parse source %q", command.SourceURL)
	}

	mrs, err := c.listMergeRequests(ctx, src, command.SourceToken)
	if err != nil {
		return nil, err
	}

	counts := map[string]int64{"merge_requests": int64(len(mrs))}
	records := make([]api.ImportedMergeRequest, 0, len(mrs))
	for _, mr := range mrs {
		record, err := c.buildRecord(ctx, src, command, mr)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
		counts["comments"] += int64(len(record.Threads))
		counts["approvals"] += int64(len(record.Approvals))
	}

	if err := c.records.PutImport(ctx, command.ImportID, records); err != nil {
		return nil, err
	}
	return counts, nil
}

// buildRecord shapes one merge request plus its approvals and notes into an
// imported MR.
func (c *Client) buildRecord(ctx context.Context, src source, command app.ImportHistoryCommand, mr mergeRequest) (api.ImportedMergeRequest, error) {
	digest, err := payloadDigest(mr)
	if err != nil {
		return api.ImportedMergeRequest{}, err
	}
	provenance := api.Provenance{
		Class:          api.AttestImported,
		ImportID:       command.ImportID,
		SourceSystem:   "gitlab",
		SourceInstance: command.SourceInstance,
		SourceRef:      strconv.FormatInt(mr.IID, 10),
		DeclaredActor:  mr.Author.Username,
		DeclaredAt:     mr.CreatedAt,
		PayloadDigest:  digest,
	}

	// GitLab merge-request approvals (may be absent for an unapproved MR).
	approvals, err := c.listApprovals(ctx, src, mr.IID, command.SourceToken)
	if err != nil {
		return api.ImportedMergeRequest{}, err
	}
	importedApprovals := make([]api.ImportedApproval, 0, len(approvals))
	for _, a := range approvals {
		// Each record's digest covers that record's own payload, so tampering
		// with one is detectable against it rather than against its parent.
		approvalDigest, err := payloadDigest(a)
		if err != nil {
			return api.ImportedMergeRequest{}, err
		}
		approvalProvenance := provenance
		approvalProvenance.PayloadDigest = approvalDigest
		approvalProvenance.DeclaredActor = a.User.Username
		// GitLab's approvals response carries no per-approval timestamp. The
		// source declared none, so none is recorded: substituting the merge
		// request's own updated_at would put a value this system invented into an
		// immutable provenance block (ADR-0029).
		approvalProvenance.DeclaredAt = time.Time{}
		importedApprovals = append(importedApprovals, api.ImportedApproval{
			ApprovalID:     strconv.FormatInt(a.ID, 10),
			MergeRequestID: strconv.FormatInt(mr.IID, 10),
			DeclaredActor:  a.User.Username,
			Provenance:     approvalProvenance,
		})
	}

	// GitLab notes are the review threads/comments.
	notes, err := c.listNotes(ctx, src, mr.IID, command.SourceToken)
	if err != nil {
		return api.ImportedMergeRequest{}, err
	}
	threads := make([]api.ImportedThread, 0, len(notes))
	for _, note := range notes {
		// A note the source placed in a file anchors to that file; one it placed
		// nowhere attaches to the merge request. Neither is dropped, and neither
		// claims a diff position this import has not resolved (AC5).
		noteDigest, err := payloadDigest(note)
		if err != nil {
			return api.ImportedMergeRequest{}, err
		}
		noteProvenance := provenance
		noteProvenance.PayloadDigest = noteDigest
		noteProvenance.DeclaredActor = note.Author.Username
		noteProvenance.DeclaredAt = note.CreatedAt
		threads = append(threads, api.ImportedThread{
			ThreadID:       "note-" + strconv.FormatInt(note.ID, 10),
			MergeRequestID: strconv.FormatInt(mr.IID, 10),
			Path:           note.Position.NewPath,
			Anchor:         api.DeclaredAnchor(note.Position.NewPath),
			Comments: []api.ImportedComment{{
				CommentID:     "note-" + strconv.FormatInt(note.ID, 10),
				DeclaredActor: note.Author.Username,
				Body:          note.Body,
				DeclaredAt:    note.CreatedAt,
				Provenance:    noteProvenance,
			}},
			Provenance: noteProvenance,
		})
	}

	return api.ImportedMergeRequest{
		MergeRequestID: strconv.FormatInt(mr.IID, 10),
		SourceRef:      mr.SourceBranch,
		TargetRef:      mr.TargetBranch,
		Title:          mr.Title,
		Description:    mr.Description,
		State:          mr.State,
		CreatorID:      mr.Author.Username,
		Threads:        threads,
		Approvals:      importedApprovals,
		Provenance:     provenance,
	}, nil
}

// listMergeRequests fetches every MR (any state) for the source project, page by
// page. A source with more history than one page holds must not import as a
// silently truncated set: an import that stops early would report its partial
// counts as if they were the whole backlog.
func (c *Client) listMergeRequests(ctx context.Context, src source, token string) ([]mergeRequest, error) {
	project := url.PathEscape(src.namespace + "/" + src.project)
	return fetchPages[mergeRequest](ctx, c, token, func(page int) string {
		return fmt.Sprintf("%s/projects/%s/merge_requests?state=all&scope=all&per_page=%d&page=%d&order_by=created_at&sort=asc",
			c.base, project, pageSize, page)
	})
}

// listApprovals fetches the approvals for one MR.
func (c *Client) listApprovals(ctx context.Context, src source, iid int64, token string) ([]approval, error) {
	project := url.PathEscape(src.namespace + "/" + src.project)
	path := fmt.Sprintf("%s/projects/%s/merge_requests/%d/approvals", c.base, project, iid)
	var result struct {
		ApprovedBy []approval `json:"approved_by"`
	}
	if err := c.getJSON(ctx, path, token, &result); err != nil {
		return nil, err
	}
	return result.ApprovedBy, nil
}

// listNotes fetches every note (comment) for one MR, page by page.
func (c *Client) listNotes(ctx context.Context, src source, iid int64, token string) ([]note, error) {
	project := url.PathEscape(src.namespace + "/" + src.project)
	return fetchPages[note](ctx, c, token, func(page int) string {
		return fmt.Sprintf("%s/projects/%s/merge_requests/%d/notes?per_page=%d&page=%d&sort=asc",
			c.base, project, iid, pageSize, page)
	})
}

// pageSize is the per-page ceiling GitLab honours.
const pageSize = 100

// maxPages bounds a paging loop so a source that keeps returning full pages
// cannot spin forever. Reaching it is an error, never a quiet truncation.
const maxPages = 1000

// fetchPages walks a paged GitLab collection until a short page ends it.
func fetchPages[T any](ctx context.Context, c *Client, token string, pageURL func(page int) string) ([]T, error) {
	var all []T
	for page := 1; page <= maxPages; page++ {
		var batch []T
		if err := c.getJSON(ctx, pageURL(page), token, &batch); err != nil {
			return nil, err
		}
		all = append(all, batch...)
		if len(batch) < pageSize {
			return all, nil
		}
	}
	return nil, fmt.Errorf("gitlab import: source has more than %d pages", maxPages)
}

// getJSON performs one authenticated GET and decodes the JSON body.
func (c *Client) getJSON(ctx context.Context, path, token string, into any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	// The token is request-only: it never becomes a log line, an event, or an
	// audit record (SPEC-0011 AC22).
	if token != "" {
		request.Header.Set("PRIVATE-TOKEN", token)
	}

	response, err := c.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		// Rate limiting (HTTP 429/403) means a stalled import, not a failed one
		// (AC8).
		if response.StatusCode == http.StatusForbidden || response.StatusCode == http.StatusTooManyRequests {
			return app.ErrImportStalled
		}
		return fmt.Errorf("gitlab import: status %d", response.StatusCode)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}
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

// mergeRequest is the subset of the GitLab MR API shape this importer needs.
type mergeRequest struct {
	IID          int64     `json:"iid"`
	Title        string    `json:"title"`
	Description  string    `json:"description"`
	State        string    `json:"state"`
	Author       glUser    `json:"author"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	SourceBranch string    `json:"source_branch"`
	TargetBranch string    `json:"target_branch"`
}

// approval is the GitLab approval shape (nested under approved_by).
type approval struct {
	ID   int64  `json:"user_id"`
	User glUser `json:"user"`
}

// note is the GitLab note shape.
type note struct {
	ID        int64     `json:"id"`
	Body      string    `json:"body"`
	Author    glUser    `json:"author"`
	CreatedAt time.Time `json:"created_at"`
	Position  position  `json:"position"`
}

// position is the diff position GitLab declares for a diff note. A note that
// is not on a diff has no position, and an outdated one has no new_line — both
// degrade the anchor rather than dropping the note (AC5).
type position struct {
	NewPath string `json:"new_path"`
	NewLine int64  `json:"new_line"`
}

type glUser struct {
	Username string `json:"username"`
}
