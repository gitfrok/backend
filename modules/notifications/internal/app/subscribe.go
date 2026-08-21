package app

import (
	"context"

	codereviewapi "github.com/gitfrok/backend/modules/codereview/api"
	"github.com/gitfrok/backend/modules/notifications/api"
	securityapi "github.com/gitfrok/backend/modules/security/api"
	"github.com/gitfrok/backend/platform/bus"
)

// Subscribe wires the context's handlers onto the bus. Registration happens
// at composition time in cmd/, so a missed subscription is a wiring failure,
// not a runtime silence. The coverage table below is the test surface that
// keeps this honest: every event named here has a recipient rule, and every
// rule is asserted reachable by test (ADR-0086's named risk).
func Subscribe(b bus.Bus, s *Service) {
	bus.SubscribeTyped(b, s.OnMergeRequestOpened)
	bus.SubscribeTyped(b, s.OnMergeRequestReady)
	bus.SubscribeTyped(b, s.OnReviewSubmitted)
	bus.SubscribeTyped(b, s.OnMergeRequestMerged)
	bus.SubscribeTyped(b, s.OnFindingsAttributed)
}

// CoverageRule is one row of the coverage table: whether the event notifies
// anyone, and who.
type CoverageRule struct {
	Notifies   bool
	Recipients string
}

// coverageTable accounts for EVERY known producer event type. A rule with
// Notifies=false is a decision, not an omission; a known event missing from
// this table fails the test rather than notifying nobody silently (ADR-0086's
// named risk).
var coverageTable = map[string]CoverageRule{
	codereviewapi.EventMergeRequestOpened:      {true, "the target's reviewers-to-be (review-capable members) minus the actor"},
	codereviewapi.EventMergeRequestReady:       {true, "same recipients as opened — the review-requested fact (SPEC-0063 AC1)"},
	codereviewapi.EventReviewSubmitted:         {true, "the MR's author, never the reviewer"},
	codereviewapi.EventMergeRequestMerged:      {true, "the author and every reviewer whose approval counted at the gate"},
	securityapi.EventFindingsAttributed:        {true, "the MR's author, once per attribution batch"},
	codereviewapi.EventMergeRequestUpdated:     {false, "a head move or retarget is addressed to no one; findings re-attribution carries its own notification"},
	codereviewapi.EventBranchProtectionChanged: {false, "a protection rule is addressed to no one; Repository/Git projects it"},
	securityapi.EventScanIngested:              {false, "a scan is addressed to no one; its findings reach people through attribution (SPEC-0028)"},
}

// Coverage returns the table for tests; the map's keys are the routing keys.
func Coverage() map[string]CoverageRule { return coverageTable }

// onMergeRequestOpened learns the MR's author into the projection and notifies
// the target's reviewers-to-be minus the actor (SPEC-0063 AC1).
func (s *Service) OnMergeRequestOpened(ctx context.Context, e codereviewapi.MergeRequestOpened) error {
	if err := s.putCreator(ctx, e.TenantID, e.RepositoryID, e.MergeRequestID, e.CreatorID); err != nil {
		return err
	}
	recipients, err := s.reviewCapable(ctx, e.TenantID, e.CreatorID)
	if err != nil {
		return err
	}
	rows := make([]Row, 0, len(recipients))
	for _, r := range recipients {
		rows = append(rows, Row{
			EventID: e.EventID + ":" + r, TenantID: e.TenantID, RecipientID: r,
			Kind:         api.KindMergeRequestReadyForReview,
			RepositoryID: e.RepositoryID, MergeRequestID: e.MergeRequestID,
			ActorID: e.CreatorID, OccurredAt: e.OccurredAt,
		})
	}
	return s.append(ctx, rows)
}

// onMergeRequestReady notifies exactly as an open would have (SPEC-0063 AC1):
// marking ready IS the review request. The row's EventID derives from the
// ready event, so a draft that was somehow announced twice still makes one row.
func (s *Service) OnMergeRequestReady(ctx context.Context, e codereviewapi.MergeRequestReady) error {
	if err := s.putCreator(ctx, e.TenantID, e.RepositoryID, e.MergeRequestID, s.creatorOf(ctx, e.TenantID, e.RepositoryID, e.MergeRequestID)); err != nil {
		return err
	}
	recipients, err := s.reviewCapable(ctx, e.TenantID, e.ActorID)
	if err != nil {
		return err
	}
	rows := make([]Row, 0, len(recipients))
	for _, r := range recipients {
		rows = append(rows, Row{
			EventID: e.EventID + ":" + r, TenantID: e.TenantID, RecipientID: r,
			Kind:         api.KindMergeRequestReadyForReview,
			RepositoryID: e.RepositoryID, MergeRequestID: e.MergeRequestID,
			ActorID: e.ActorID, HeadRevision: e.HeadRevision, OccurredAt: e.OccurredAt,
		})
	}
	return s.append(ctx, rows)
}

// onReviewSubmitted notifies the author and never the reviewer (AC2). A
// self-review notifies nobody: minus removes the actor from the set.
func (s *Service) OnReviewSubmitted(ctx context.Context, e codereviewapi.ReviewSubmitted) error {
	if e.CreatorID == "" || e.CreatorID == e.ActorID {
		return nil
	}
	return s.append(ctx, []Row{{
		EventID: e.EventID + ":" + e.CreatorID, TenantID: e.TenantID, RecipientID: e.CreatorID,
		Kind:         api.KindReviewSubmitted,
		RepositoryID: e.RepositoryID, MergeRequestID: e.MergeRequestID,
		ActorID: e.ActorID, HeadRevision: e.HeadRevision, OccurredAt: e.OccurredAt,
	}})
}

// onMergeRequestMerged notifies the author and everyone whose approval counted
// at the gate (AC2) — the actors captured when the gate decided, published on
// the event, not whoever approved by the time it fired.
func (s *Service) OnMergeRequestMerged(ctx context.Context, e codereviewapi.MergeRequestMerged) error {
	recipients := minus(append([]string{e.CreatorID}, e.CountedApprovalActors...), e.ActorID)
	rows := make([]Row, 0, len(recipients))
	for _, r := range recipients {
		rows = append(rows, Row{
			EventID: e.EventID + ":" + r, TenantID: e.TenantID, RecipientID: r,
			Kind:         api.KindMergeRequestMerged,
			RepositoryID: e.RepositoryID, MergeRequestID: e.MergeRequestID,
			ActorID: e.ActorID, HeadRevision: e.HeadRevision, OccurredAt: e.OccurredAt,
		})
	}
	return s.append(ctx, rows)
}

// onFindingsAttributed notifies the MR's author once per batch (AC3): the
// attribution event fires once per (MR, head, base) triple, so one notification
// per event is once per batch — never once per finding.
func (s *Service) OnFindingsAttributed(ctx context.Context, e securityapi.FindingsAttributed) error {
	creator, err := s.creators.Creator(ctx, e.TenantID, e.RepositoryID, e.MergeRequestID)
	if err != nil || creator == "" {
		// An unknown author is a projection gap, not a notify-everyone case:
		// skip quietly, the next opened/ready repairs the projection.
		return err
	}
	return s.append(ctx, []Row{{
		EventID: e.EventID + ":" + creator, TenantID: e.TenantID, RecipientID: creator,
		Kind:         api.KindFindingsAttributed,
		RepositoryID: e.RepositoryID, MergeRequestID: e.MergeRequestID,
		HeadRevision: e.HeadRevision, OccurredAt: e.OccurredAt,
	}})
}

// putCreator tolerates an absent projection store (dev compositions without
// durability): the derivation paths that need it already guard on nil.
func (s *Service) putCreator(ctx context.Context, tenantID, repositoryID, mergeRequestID, creatorID string) error {
	if s.creators == nil || creatorID == "" {
		return nil
	}
	return s.creators.PutCreator(ctx, tenantID, repositoryID, mergeRequestID, creatorID)
}

func (s *Service) creatorOf(ctx context.Context, tenantID, repositoryID, mergeRequestID string) string {
	if s.creators == nil {
		return ""
	}
	creator, err := s.creators.Creator(ctx, tenantID, repositoryID, mergeRequestID)
	if err != nil {
		return ""
	}
	return creator
}

// reviewCapable resolves reviewers-to-be: the tenant's review-capable
// principals minus the acting actor. No directory means no recipients — an
// honest empty set rather than a guess.
func (s *Service) reviewCapable(ctx context.Context, tenantID string, exclude ...string) ([]string, error) {
	if s.directory == nil {
		return nil, nil
	}
	actors, err := s.directory.ReviewCapableActors(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	return minus(actors, exclude...), nil
}
