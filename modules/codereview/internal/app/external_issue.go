package app

import (
	"context"
	"strings"
	"time"

	"github.com/gitfrok/backend/modules/codereview/api"
	"github.com/gitfrok/backend/platform/audit"
)

// Referencing an issue that lives somewhere else (SPEC-0059, PR-28's accepted scope,
// ADR-0074).
//
// Two use cases, and what they do NOT do is the design. There is no HTTP client
// here, no port that could acquire one, and no path on which this product asks a
// customer's tracker anything. A reference is stored exactly as given, and the
// tracker being down changes nothing about this product's behaviour.
//
// The action is `merge_request.external_issue.link`, its own entry in the role table
// rather than a reuse of `merge_request.open`: a write authorized as something it is
// not is a lie in the one place this product's authorization is legible.

const actionLinkExternalIssue = "merge_request.external_issue.link"

// LinkExternalIssue references an issue from a merge request.
//
// Linking the same (tracker, issue key) twice is the same fact stated twice: it is
// accepted, changes nothing, and writes no second audit record. The URL is not part
// of that identity, so a second link with a different URL for the same issue does
// not replace the first — the first reference is the one that was recorded, and
// silently repointing it would rewrite what a reader already saw.
func (s *Service) LinkExternalIssue(ctx context.Context, req api.LinkExternalIssueRequest) (api.MergeRequest, error) {
	mr, err := s.Get(ctx, req.Context, req.MergeRequestID)
	if err != nil {
		return api.MergeRequest{}, api.ErrDenied
	}
	candidate := api.ExternalIssue{
		Tracker:  strings.TrimSpace(req.Tracker),
		IssueKey: strings.TrimSpace(req.IssueKey),
		URL:      strings.TrimSpace(req.URL),
		LinkedBy: req.ActorID,
	}
	// Validated before the PDP is asked: a malformed reference is not an
	// authorization question, and asking one would record a decision about a
	// request that was never coherent.
	if err := candidate.Validate(); err != nil {
		return api.MergeRequest{}, err
	}
	if !s.allowed(ctx, req.Context, actionLinkExternalIssue, "merge_request", mr.ID, map[string]string{
		"state": string(mr.State),
	}) {
		return api.MergeRequest{}, api.ErrDenied
	}
	for _, existing := range mr.ExternalIssues {
		if existing.SameAs(candidate) {
			return mr, nil
		}
	}
	if len(mr.ExternalIssues) >= api.MaxExternalIssues {
		return api.MergeRequest{}, api.ErrTooManyExternalIssues
	}

	now := s.now().UTC()
	candidate.LinkedAt = now
	mr.ExternalIssues = append(mr.ExternalIssues, candidate)
	mr.Version, mr.UpdatedAt = mr.Version+1, now
	if err := s.store.Save(ctx, mr); err != nil {
		return api.MergeRequest{}, api.ErrDenied
	}
	if err := s.announceExternalIssue(ctx, mr, req.Context, candidate, now, true); err != nil {
		return api.MergeRequest{}, err
	}
	return mr, nil
}

// UnlinkExternalIssue removes a reference by its identity.
//
// Removing one that is not there is accepted and changes nothing, for the reason
// linking twice is: the caller asked for a state, and that state already holds. It
// writes no audit record either — nothing happened.
func (s *Service) UnlinkExternalIssue(ctx context.Context, req api.UnlinkExternalIssueRequest) (api.MergeRequest, error) {
	mr, err := s.Get(ctx, req.Context, req.MergeRequestID)
	if err != nil {
		return api.MergeRequest{}, api.ErrDenied
	}
	target := api.ExternalIssue{Tracker: strings.TrimSpace(req.Tracker), IssueKey: strings.TrimSpace(req.IssueKey)}
	if target.Tracker == "" || target.IssueKey == "" {
		return api.MergeRequest{}, api.ErrInvalidExternalIssue
	}
	if !s.allowed(ctx, req.Context, actionLinkExternalIssue, "merge_request", mr.ID, map[string]string{
		"state": string(mr.State),
	}) {
		return api.MergeRequest{}, api.ErrDenied
	}

	kept := make([]api.ExternalIssue, 0, len(mr.ExternalIssues))
	var removed api.ExternalIssue
	found := false
	for _, existing := range mr.ExternalIssues {
		if !found && existing.SameAs(target) {
			removed, found = existing, true
			continue
		}
		kept = append(kept, existing)
	}
	if !found {
		return mr, nil
	}

	now := s.now().UTC()
	mr.ExternalIssues = kept
	mr.Version, mr.UpdatedAt = mr.Version+1, now
	if err := s.store.Save(ctx, mr); err != nil {
		return api.MergeRequest{}, api.ErrDenied
	}
	if err := s.announceExternalIssue(ctx, mr, req.Context, removed, now, false); err != nil {
		return api.MergeRequest{}, err
	}
	return mr, nil
}

// announceExternalIssue publishes what happened: the merge request changed, and the
// act is on the audit trail.
//
// MergeRequestUpdated is the existing event for a change to a merge request, and
// there is no new domain event because nothing new happened to the world — a
// reference is inert, and a consumer that reacted to it would be reacting to
// something this product does not claim to know.
//
// The audit record carries the tracker and the issue key and NOT the URL. The key is
// the identifier the trail needs; a URL is customer-supplied text, and ADR-0074
// decision 2 keeps issue content out of control records. Keeping the identifier and
// dropping the text is what that decision looks like when there is anything to drop.
func (s *Service) announceExternalIssue(
	ctx context.Context,
	mr api.MergeRequest,
	principal api.Context,
	reference api.ExternalIssue,
	now time.Time,
	linked bool,
) error {
	if err := s.bus.Publish(ctx, api.MergeRequestUpdated{
		EventID: s.newID(), MergeRequestID: mr.ID, TenantID: mr.TenantID, RepositoryID: mr.RepositoryID,
		ActorID: principal.ActorID, HeadRevision: mr.HeadRevision,
		SourceRef: mr.SourceRef, TargetRef: mr.TargetRef, OccurredAt: now,
	}); err != nil {
		return err
	}
	return s.bus.Publish(ctx, audit.MergeRequestExternalIssue{
		TenantID: mr.TenantID, ActorID: principal.ActorID, RepositoryID: mr.RepositoryID,
		MergeRequestID: mr.ID, Tracker: reference.Tracker, IssueKey: reference.IssueKey,
		Linked: linked, RequestID: principal.RequestID, OccurredAt: now,
	})
}
