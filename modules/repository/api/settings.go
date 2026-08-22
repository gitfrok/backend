package api

import (
	"context"
	"errors"
	"time"
)

// The Repository context's settings surface (SPEC-0057, PR-30, ADR-0076).
//
// ADR-0076 accepted name, description and archival only. What is absent here is the decision, not an
// omission: there is no visibility field, no member or role, and no branch-protection or approval
// setting, because none of those is a property of a repository — "public" is a different
// authorization model, per-repository membership is one the PDP would have to learn everywhere
// repo.read is asked, and PR-10 puts branch protection and approval requirements in
// governance/policies as policy rather than as toggles.
//
// Archival is a LABEL and this file is where that is enforceable rather than remembered: nothing in
// this surface returns a ReadOnlyState, and nothing about an archived repository narrows a read.
// Making an archived repository refuse writes would need a third member in readonly.go's
// two-member cause vocabulary, which is a decision about the git write path (SPEC-0057's archival
// rule).

// SettingsView is one repository's changeable properties as a caller receives them.
//
// ArchivedAt is the zero time when the repository is not archived; there is no paired boolean,
// because a flag and an instant can disagree and "archived, but we do not know when" is not a state
// anyone can act on.
//
// SettingsUpdatedBy is an actor ID and not a display name. Resolving it to a person is the Identity
// context's job, and this context does not ask it (ADR-0022).
type SettingsView struct {
	TenantID          string
	RepoID            string
	Name              string
	Description       string
	ArchivedAt        time.Time
	SettingsUpdatedAt time.Time
	SettingsUpdatedBy string
	// MergeStrategy is the landing policy's strategy: empty is the absence of
	// an explicit choice, and merges land exactly as they always did
	// (SPEC-0065 AC1). The vocabulary is the domain's: "merge_commit",
	// "squash", "rebase".
	MergeStrategy string
	// TrunkBased constrains landing shape — merge commits refused,
	// fast-forward preferred, rebase the fallback — never who may land or
	// whether (ADR-0088 decision 3).
	TrunkBased bool
}

// Archived reports whether the repository carries the archived label.
func (v SettingsView) Archived() bool { return !v.ArchivedAt.IsZero() }

// SettingsQuery reads one repository's settings for one verified caller.
type SettingsQuery struct {
	TenantID   string
	RepoID     string
	ActorID    string
	ActorRoles []string
}

// SettingsUpdate is a write of the settings a repository has — not a patch.
//
// Both fields travel on every call. A partial-update convention would need a way to say "leave this
// one alone", and the first thing such a convention attracts is a field that was not in the accepted
// increment.
type SettingsUpdate struct {
	TenantID    string
	RepoID      string
	ActorID     string
	ActorRoles  []string
	Name        string
	Description string
}

// ArchiveRequest states the archived state wanted, not the transition. Asking for the state a
// repository is already in is the same fact stated twice: it is accepted, and it writes no second
// audit record (SPEC-0057 AC3).
type ArchiveRequest struct {
	TenantID   string
	RepoID     string
	ActorID    string
	ActorRoles []string
	Archived   bool
}

// LandingRequest states the landing policy whole (SPEC-0065, ADR-0088):
// strategy and trunk mode together on every call, for the same reason a
// settings update is a write of the settings rather than a patch.
type LandingRequest struct {
	TenantID   string
	RepoID     string
	ActorID    string
	ActorRoles []string
	// Strategy is one of the domain's landing vocabulary values, or empty to
	// clear an explicit choice back to unset.
	Strategy   string
	TrunkBased bool
}

// Settings is the context's settings port: one read, two writes, and nothing that could express a
// visibility, a member or a policy.
type Settings interface {
	GetSettings(ctx context.Context, q SettingsQuery) (SettingsView, error)
	// UpdateSettings changes the name and the description.
	UpdateSettings(ctx context.Context, u SettingsUpdate) (SettingsView, error)
	// SetArchived sets or clears the archived label. It changes no authorization or read outcome.
	SetArchived(ctx context.Context, a ArchiveRequest) (SettingsView, error)
	// SetLanding states the landing policy whole (SPEC-0065, ADR-0088). It
	// changes what a reviewed merge produces; it can never change who may land
	// or whether — that is why it is a setting at all.
	SetLanding(ctx context.Context, l LandingRequest) (SettingsView, error)
}

// Administrator answers whether one verified caller may administer one repository.
//
// It is a second port beside Authorizer rather than a method on it, for the reason Authorizer exists
// at all: this module is a leaf at fan-out zero, so it asks abstractions it owns and the composition
// root adapts the PDP onto them (invariant 14, ADR-0025). Widening Authorizer would also have made
// every existing implementation answer a question it was not written for — and the wrong default for
// "may administer" is the one that says yes.
//
// The question it maps to is `repo.admin`, which the policy bundle already grants to `owner` and to
// nobody else. This surface therefore adds no action to the vocabulary and no role to the model,
// which is ADR-0076 decision 1 holding at the PDP rather than only in the UI.
type Administrator interface {
	MayAdminister(ctx context.Context, tenantID, actorID string, roles []string, repoID string) (bool, error)
}

// The audit actions this surface appends. They are declared here, in the context that emits them,
// because the Audit context's Action type is deliberately open — a module audits something that
// package has never heard of (SPEC-0003).
const (
	// ActionSettingsUpdated records a name or description change.
	ActionSettingsUpdated = "repository.settings.updated"
	// ActionArchivalChanged records an archive or unarchive act. It is a separate action from a
	// settings change because it is a separate question in an investigation: "who renamed this"
	// and "who archived this" are not asked together.
	ActionArchivalChanged = "repository.archival.changed"
	// ActionLandingChanged records a landing-policy change (SPEC-0065). A
	// separate action for the same reason archival is: "who changed what a
	// merge produces here" is its own question, and the answer is evidence
	// when history shape surprises someone.
	ActionLandingChanged = "repository.landing.changed"
)

// WitnessEntry is one settings act as this context states it.
//
// It carries no sequence number and no hash: the writer assigns those, because a producer able to
// state its own position in the chain could also lie about it (ADR-0007). Provenance is not a field
// either — every record from this surface is a first-party fact observed by our own service, and the
// adapter that fills this port states that once rather than letting each call assert it.
type WitnessEntry struct {
	TenantID string
	Action   string
	ActorID  string
	// Resource is the repository the act was about.
	Resource string
	// Denied marks a refusal. A refused settings change that reached the PDP is a record, not a
	// silence: it is the half of the trail an investigation actually wants (SPEC-0057 AC5).
	Denied bool
	// Detail carries what changed, never a diff of prose the caller did not send.
	Detail     map[string]string
	OccurredAt time.Time
}

// Witness is the port through which a settings act reaches the audit trail.
//
// It is declared HERE and filled by the composition root, exactly as Residency declares its own
// witness (SPEC-0040 AC7): importing the Audit context would give this leaf module a dependency and
// invert the module graph for one call.
type Witness interface {
	AppendSettingsRecord(ctx context.Context, e WitnessEntry) error
}

// ErrNoAdministrationPoint reports a Service wired without an Administrator. A settings write is an
// authorization-derived act, so a missing decision point is a composition bug rather than a runtime
// condition — and it refuses loudly instead of allowing the write, because the wrong default here is
// the one that says yes (mirroring ErrNoDecisionPoint).
var ErrNoAdministrationPoint = errors.New("repository: no administrator wired; a settings change cannot be authorized")

// ErrNoWitness reports a Service wired without a Witness.
//
// A settings change that is not audited is not a settings change PR-30 asked for: "each change
// audited" is the requirement's own clause. So an unwitnessed write is refused rather than performed
// silently — the alternative is a product that quietly loses the record it promised.
var ErrNoWitness = errors.New("repository: no audit witness wired; an unaudited settings change is refused")

// ErrSettingsForbidden is the refusal a caller who may not administer a repository receives. It is
// deliberately indistinguishable at the wire from a repository that does not exist: the adapter maps
// every failure onto one coarse denial (SPEC-0057 AC5, SPEC-0001).
var ErrSettingsForbidden = errors.New("repository: settings unavailable")
