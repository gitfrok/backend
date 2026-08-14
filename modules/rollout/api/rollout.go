// Package api is the Rollout context's in-process surface (T-0032, SPEC-0039 AC3–AC7,
// ADR-0013/0017/0044).
//
// The context owns reconcile-based upgrades for a cluster the control plane cannot reach:
// it publishes a desired release as a SIGNED reference, verifies that signature before
// anything is applied (AC3), drives an idempotent reconcile toward it (AC4), rolls a failed
// upgrade back to the prior release and says why (AC5), reports the rollout's phase per data
// plane and treats a silent data plane as stale rather than upgraded (AC6), and honors a
// customer's version pin or deferral within a supported window whose expiry stays visible
// (AC7).
//
// The security statement is ADR-0017 §Security restated: the control plane cannot push
// arbitrary code. The only thing it may express as a desired state is a release reference it
// has signed with a key the data plane pins, and the signature check below is the gate that
// makes that true. Nothing here imports infrastructure (invariant 20); the store and the
// signing primitives live under internal/ and translate shapes only.
//
// SECRECY, stated once for every type in this package: a signing PRIVATE key never appears
// here. Only public verification keys (the trust bundle) and signatures traverse this surface;
// a private key lives solely in the publishing CI's protected environment (ADR-0044).
package api

import (
	"context"
	"errors"
	"time"
)

// RolloutPhase is the operator-visible lifecycle of one reconcile-based rollout, mirrored on
// the agent wire's RolloutPhase (SPEC-0039 AC6). The phases are exhaustive and pairwise
// distinguishable; a rollout that has not converged never reads as applied.
type RolloutPhase string

const (
	// PhaseIdle: no rollout is in flight for the data plane's current generation.
	PhaseIdle RolloutPhase = "IDLE"
	// PhaseInProgress: the desired state is being reconciled toward; the data plane has not
	// yet reported convergence.
	PhaseInProgress RolloutPhase = "IN_PROGRESS"
	// PhaseApplied: the desired state converged and the data plane reported it healthy.
	PhaseApplied RolloutPhase = "APPLIED"
	// PhaseFailed: convergence failed; Message says why. Never left silent (AC5).
	PhaseFailed RolloutPhase = "FAILED"
	// PhaseRolledBack: a failed upgrade was reverted to the prior signed release.
	PhaseRolledBack RolloutPhase = "ROLLED_BACK"
)

// Terminal reports whether the phase is a resting state — no further report will change it
// unless a new desired generation is published.
func (p RolloutPhase) Terminal() bool {
	return p == PhaseApplied || p == PhaseRolledBack
}

// SignedRelease is one releasable image as it crosses this surface (ADR-0044). The signature
// is an ECDSA signature over the release's canonical identity (OCIRef@Digest) by a key in the
// trust bundle; the private key that produced it never appears here.
type SignedRelease struct {
	// OCIRef is the image reference, e.g. registry/gitsaas/git-rpc.
	OCIRef string
	// Digest is the immutable content digest, sha256:…, the release is pinned to.
	Digest string
	// Signature is the ECDSA (DER) signature over CanonicalIdentity. Empty means UNSIGNED —
	// always refused (AC3).
	Signature []byte
}

// CanonicalIdentity is the exact byte string the signature covers: "<ociRef>@<digest>".
// Pinning verification to one canonical form is what makes a tampered ref or digest fail the
// signature check rather than slip past it (AC3).
func (r SignedRelease) CanonicalIdentity() []byte {
	return []byte(r.OCIRef + "@" + r.Digest)
}

// Release couples one signed release to the component and version it realizes, the shape the
// desired state and the applier both speak.
type Release struct {
	// Component names the data-plane part this release realizes, e.g. "git-rpc".
	Component string
	// Version is the semantic version the control plane publishes as desired.
	Version string
	// Signed carries the reference and the signature that gates it.
	Signed SignedRelease
}

// ActualReport is one data-plane reconciliation report as the control plane ingests it — the
// in-process mirror of the wire's ActualStateReport, including the AC5/AC6 rollout fields.
type ActualReport struct {
	// AppliedGeneration is the desired-state generation the data plane last applied.
	AppliedGeneration int64
	// ActualVersion is the version the data plane reports running.
	ActualVersion string
	// Healthy is whether the applied state passed its health gate.
	Healthy bool
	// Message is coarse prose from the data plane; it carries the reason a reconcile failed
	// (AC5) and never a secret or a signing key.
	Message string
}

// Rollout is the operator-visible record of one upgrade attempt for one data plane (AC6):
// desired vs actual version, the phase, the reason, and when the data plane last reported.
type Rollout struct {
	ID             string
	TenantID       string
	DataPlaneID    string
	Generation     int64
	DesiredVersion string
	ActualVersion  string
	Phase          RolloutPhase
	Message        string
	// Desired is the signed release this rollout reconciles toward; the applier receives it.
	Desired Release
	// Prior is the release a rollback restores; nil for a first-ever rollout. It is captured
	// when the rollout opens from whatever release was applied before it (AC5).
	Prior          *Release
	StartedAt      time.Time
	UpdatedAt      time.Time
	LastReportedAt time.Time // zero until the data plane reports at least once
}

// ReportedSince reports whether the data plane has sent any report since this rollout began.
// A rollout with no report since it started is the stale case AC6 refuses to call upgraded.
func (r Rollout) ReportedSinceStart() bool { return !r.LastReportedAt.IsZero() }

// RolloutStatus is the AC6 derivation: the phase a rollout reads as at now. A non-terminal
// rollout the data plane has not reported on within staleAfter reads STALE — never applied.
// Staleness is a fault an operator must see, not a shade of progress (SPEC-0039 AC6).
type RolloutStatus struct {
	Phase RolloutPhase
	Stale bool
}

// VersionWindow is one data plane's AC7 pin/defer state. A customer may pin a version or
// defer an upgrade within the supported window; the window's expiry is a field, never an
// implication, so it is visible before it is reached.
type VersionWindow struct {
	// PinnedVersion, when non-empty, is the version the customer holds. A desired release of
	// any other version is held, not forced, while the pin stands.
	PinnedVersion string
	// DeferredUntil, when non-zero, holds upgrades until this instant passes.
	DeferredUntil time.Time
	// SupportedUntil is when this data plane's version window expires. It MUST be surfaced to
	// the operator: an upgrade is not silently forced once support lapses, but neither may the
	// lapse sneak up unseen (AC7).
	SupportedUntil time.Time
}

// Holds reports whether the window holds a desired version at now: the version is pinned to
// something else, or the data plane is inside a deferral. A zero window holds nothing.
func (w VersionWindow) Holds(desiredVersion string, now time.Time) bool {
	if w.PinnedVersion != "" && w.PinnedVersion != desiredVersion {
		return true
	}
	return !w.DeferredUntil.IsZero() && now.Before(w.DeferredUntil)
}

// Expired reports whether the supported window has lapsed at now. Expiry does not by itself
// force an upgrade; it makes the hold untenable and MUST already be visible (AC7).
func (w VersionWindow) Expired(now time.Time) bool {
	return !w.SupportedUntil.IsZero() && !now.Before(w.SupportedUntil)
}

// The coarse refusal vocabulary a release verification produces (AC3). Each names a distinct
// cause so the audit trail and the operator can tell an unsigned release from a mis-signed one.
var (
	// ErrReleaseUnsigned: the release carries no signature. Always refused; the running
	// version is untouched.
	ErrReleaseUnsigned = errors.New("rollout: release is unsigned")
	// ErrReleaseMisSigned: a signature is present but does not verify against the trust
	// bundle, or covers a different identity. Always refused.
	ErrReleaseMisSigned = errors.New("rollout: release signature does not verify")
	// ErrReleaseMalformed: the release is missing the identity a signature would pin (no OCI
	// ref or no digest). Nothing verifiable, so nothing applicable.
	ErrReleaseMalformed = errors.New("rollout: release is malformed")
	// ErrNotFound: no rollout/window record exists for the caller's tenant and data plane.
	ErrNotFound = errors.New("rollout: no such record")
	// ErrWindowExpired: an upgrade was requested past the supported window without an explicit
	// force. Upgrades are not silently forced on a running cluster (AC7).
	ErrWindowExpired = errors.New("rollout: version window has expired")
)

// ReleaseVerifier decides whether one signed release may be applied. The concrete ECDSA
// verifier lives under internal/; a composition supplies whatever trust bundle its
// environment pins (ADR-0044). Verification is offline and never dials anything.
type ReleaseVerifier interface {
	// Verify returns nil only when rel carries a signature that checks out against the trust
	// bundle over rel.CanonicalIdentity. It returns one of the ErrRelease* refusals otherwise;
	// a refusal leaves the running version untouched (AC3).
	Verify(rel SignedRelease) error
}

// Applier is the seam a data plane presents for one reconcile: apply exactly one signed
// release and report the outcome. The control plane NEVER dials it (ADR-0011, SPEC-0039
// AC4); in production the agent pulls the desired release over its own outbound stream and
// applies it in-cluster. The reconcile harness and tests supply a local implementation, so a
// rollout→failure→rollback can be exercised without any inbound path.
type Applier interface {
	// Apply applies rel and returns an error describing why it could not, if it could not.
	Apply(ctx context.Context, rel Release) error
}

// Config is the per-environment rollout configuration (invariant 13). No production value is
// compiled in; cmd/ supplies every field and tests inject clocks and short windows.
type Config struct {
	// StaleAfter is how long a non-terminal rollout may go without a data-plane report before
	// it reads stale rather than in-progress (AC6).
	StaleAfter time.Duration
	// Now is the clock every staleness and window decision reads. Injected so tests can age a
	// rollout without waiting.
	Now func() time.Time
}

// Engine is the context's surface: publish a desired release, reconcile toward it, ingest the
// data plane's reports, and read back the rollout and the version window. Every method that
// changes state appends the audit record for that act (SPEC-0039 governance G6).
type Engine interface {
	// PublishDesired records the control plane's desired release for a data plane and opens an
	// in-progress rollout toward it. The release is verified FIRST (AC3): an unsigned or
	// mis-signed release is refused, audited, and leaves the running version and any existing
	// rollout untouched. Publishing the same generation twice is idempotent — no second rollout
	// (AC4). A release held by the data plane's version window is recorded but not applied
	// until the hold lifts (AC7).
	PublishDesired(ctx context.Context, tenantID, dataPlaneID string, generation int64, desired Release) (Rollout, error)

	// Reconcile drives one reconcile of an open rollout against the data plane's applier seam:
	// apply the desired release, and on failure roll back to the prior signed release and
	// report the reason (AC5). It never opens an inbound path; the applier is local to the
	// reconcile harness.
	Reconcile(ctx context.Context, tenantID, dataPlaneID string, applier Applier) (Rollout, error)

	// ReportActual ingests one data-plane report and advances the rollout's phase and actual
	// version (AC6). A report is the only thing that can move a rollout toward applied.
	ReportActual(ctx context.Context, tenantID, dataPlaneID string, report ActualReport) (Rollout, error)

	// Rollout returns the current rollout view for a data plane with its AC6 status derived at
	// read time. A missing record yields ErrNotFound.
	Rollout(ctx context.Context, tenantID, dataPlaneID string) (Rollout, RolloutStatus, error)

	// SetWindow records the data plane's AC7 pin/defer window.
	SetWindow(ctx context.Context, tenantID, dataPlaneID string, w VersionWindow) error

	// Window returns the data plane's AC7 window; a data plane with no explicit window gets an
	// empty one that holds nothing.
	Window(ctx context.Context, tenantID, dataPlaneID string) (VersionWindow, error)
}
