// This file carries the reconcile-upgrade lifecycle records (T-0032, SPEC-0039 AC3–AC7,
// ADR-0013/0017/0044): a desired release published, a release refused because its signature
// did not verify, a rollout applied, failed, or rolled back, and a version window set.
// SPEC-0039 governance G6 makes signature verification and rollout outcomes auditable facts;
// the emission points in modules/rollout are what make each act append exactly once.
//
// A signing PRIVATE key never enters this trail; releases are named by OCI ref and digest and
// refusals carry a coarse reason only (ADR-0044).
package audit

import "time"

// Rollout lifecycle actions (SPEC-0039 G6). The dotted vocabulary lives in the audit
// contract's comment; adding one is additive by construction.
const (
	// ActionRolloutDesiredPublished records the control plane publishing a signed desired
	// release and opening a rollout toward it (AC4).
	ActionRolloutDesiredPublished = "rollout.desired.published"
	// ActionRolloutReleaseRefused records a release refused BEFORE anything was applied:
	// unsigned, mis-signed, or malformed (AC3). The running version is untouched.
	ActionRolloutReleaseRefused = "rollout.release.refused"
	// ActionRolloutApplied records a rollout converging to the desired release (AC6).
	ActionRolloutApplied = "rollout.applied"
	// ActionRolloutFailed records a rollout that could not converge, with a reason (AC5).
	ActionRolloutFailed = "rollout.failed"
	// ActionRolloutRolledBack records a failed upgrade reverted to the prior release (AC5).
	ActionRolloutRolledBack = "rollout.rolled_back"
	// ActionRolloutWindowSet records a customer version pin or deferral (AC7).
	ActionRolloutWindowSet = "rollout.window.set"
)

// RolloutDesiredPublished records one desired signed release published for a data plane and
// the rollout it opened. It names the release by ref and digest — never a signing key.
type RolloutDesiredPublished struct {
	TenantID    string
	DataPlaneID string
	Generation  int64
	OCIRef      string
	Digest      string
	Version     string
	OccurredAt  time.Time
}

func (RolloutDesiredPublished) EventName() string { return EventAudit }
func (RolloutDesiredPublished) Action() string    { return ActionRolloutDesiredPublished }
func (e RolloutDesiredPublished) Tenant() string  { return e.TenantID }

// RolloutReleaseRefused records one release the signature gate refused before applying (AC3).
// Reason is the coarse refusal (unsigned / mis-signed / malformed); the running version is
// left untouched and the audit trail is the evidence it was.
type RolloutReleaseRefused struct {
	TenantID    string
	DataPlaneID string
	OCIRef      string
	Digest      string
	Reason      string
	OccurredAt  time.Time
}

func (RolloutReleaseRefused) EventName() string { return EventAudit }
func (RolloutReleaseRefused) Action() string    { return ActionRolloutReleaseRefused }
func (e RolloutReleaseRefused) Tenant() string  { return e.TenantID }

// RolloutApplied records one rollout converging to its desired release (AC6).
type RolloutApplied struct {
	TenantID    string
	DataPlaneID string
	Generation  int64
	Version     string
	OccurredAt  time.Time
}

func (RolloutApplied) EventName() string { return EventAudit }
func (RolloutApplied) Action() string    { return ActionRolloutApplied }
func (e RolloutApplied) Tenant() string  { return e.TenantID }

// RolloutFailed records one rollout that could not converge; Reason says why (AC5).
type RolloutFailed struct {
	TenantID    string
	DataPlaneID string
	Generation  int64
	Version     string
	Reason      string
	OccurredAt  time.Time
}

func (RolloutFailed) EventName() string { return EventAudit }
func (RolloutFailed) Action() string    { return ActionRolloutFailed }
func (e RolloutFailed) Tenant() string  { return e.TenantID }

// RolloutRolledBack records one failed upgrade reverted to the prior signed release (AC5).
type RolloutRolledBack struct {
	TenantID    string
	DataPlaneID string
	Generation  int64
	FromVersion string
	ToVersion   string
	Reason      string
	OccurredAt  time.Time
}

func (RolloutRolledBack) EventName() string { return EventAudit }
func (RolloutRolledBack) Action() string    { return ActionRolloutRolledBack }
func (e RolloutRolledBack) Tenant() string  { return e.TenantID }

// RolloutWindowSet records one customer version pin or deferral within the supported window
// (AC7). SupportedUntil is recorded so the expiry is a fact, not an implication.
type RolloutWindowSet struct {
	TenantID       string
	DataPlaneID    string
	PinnedVersion  string
	DeferredUntil  time.Time
	SupportedUntil time.Time
	OccurredAt     time.Time
}

func (RolloutWindowSet) EventName() string { return EventAudit }
func (RolloutWindowSet) Action() string    { return ActionRolloutWindowSet }
func (e RolloutWindowSet) Tenant() string  { return e.TenantID }
