// Package app is the Rollout context's application layer: the reconcile-upgrade engine that
// publishes a signed desired release, drives an idempotent reconcile toward it, rolls a failed
// upgrade back and says why, ingests the data plane's reports, and honors a version window.
// It composes the domain with ports — verifier, store, bus — and never touches infrastructure
// itself (invariant 16). Every state-changing act appends the audit record for it (G6).
package app

import (
	"context"
	"errors"
	"time"

	"github.com/gitfrok/backend/modules/rollout/api"
	"github.com/gitfrok/backend/modules/rollout/internal/domain"
	platformaudit "github.com/gitfrok/backend/platform/audit"
	"github.com/gitfrok/backend/platform/bus"
	"github.com/gitfrok/backend/platform/ids"
)

// RolloutStore is the persistence port for rollout records and version windows.
type RolloutStore interface {
	PutRollout(ctx context.Context, r api.Rollout) error
	Rollout(ctx context.Context, tenantID, dataPlaneID string) (api.Rollout, bool, error)
	PutWindow(ctx context.Context, tenantID, dataPlaneID string, w api.VersionWindow) error
	Window(ctx context.Context, tenantID, dataPlaneID string) (api.VersionWindow, bool, error)
}

// Service is the composed engine. One instance owns the whole api.Engine surface.
type Service struct {
	verifier api.ReleaseVerifier
	store    RolloutStore
	events   bus.Bus
	cfg      api.Config
	logf     func(format string, args ...any)
}

// Compile-time proof that the service carries the whole surface.
var _ api.Engine = (*Service)(nil)

// New wires the service. A nil verifier, store or bus is refused: an engine without a
// signature verifier would apply unsigned releases, which is precisely the failure AC3 exists
// to make impossible.
func New(verifier api.ReleaseVerifier, store RolloutStore, events bus.Bus, cfg api.Config, logf func(format string, args ...any)) *Service {
	if verifier == nil {
		panic("rollout: no release verifier — every desired release must pass the signature gate (AC3)")
	}
	if store == nil || events == nil {
		panic("rollout: store and bus are both required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Service{verifier: verifier, store: store, events: events, cfg: cfg, logf: logf}
}

// PublishDesired records the desired release and opens an in-progress rollout toward it (AC4).
// The signature is verified BEFORE any state changes (AC3): a refusal leaves the running
// version and any existing rollout untouched and is audited. Publishing the same generation
// twice is idempotent — it returns the existing rollout and opens no second one.
func (s *Service) PublishDesired(ctx context.Context, tenantID, dataPlaneID string, generation int64, desired api.Release) (api.Rollout, error) {
	now := s.cfg.Now()

	// AC3 first: verify the release before anything is recorded or applied.
	if err := s.verifier.Verify(desired.Signed); err != nil {
		perr := s.publish(ctx, platformaudit.RolloutReleaseRefused{
			TenantID: tenantID, DataPlaneID: dataPlaneID,
			OCIRef: desired.Signed.OCIRef, Digest: desired.Signed.Digest,
			Reason: refusalReason(err), OccurredAt: now,
		})
		if perr != nil {
			return api.Rollout{}, perr
		}
		s.logf("rollout: refused release for %s/%s: %v", tenantID, dataPlaneID, err)
		return api.Rollout{}, err
	}

	// AC4 idempotency: the same generation already published is not a second rollout.
	existing, ok, err := s.store.Rollout(ctx, tenantID, dataPlaneID)
	if err != nil {
		return api.Rollout{}, err
	}
	if ok && existing.Generation == generation {
		return existing, nil
	}

	r := api.Rollout{
		ID:             ids.NewULID(),
		TenantID:       tenantID,
		DataPlaneID:    dataPlaneID,
		Generation:     generation,
		DesiredVersion: desired.Version,
		Phase:          api.PhaseInProgress,
		Desired:        desired,
		Prior:          runningRelease(ok, existing),
		StartedAt:      now,
		UpdatedAt:      now,
	}
	if err := s.store.PutRollout(ctx, r); err != nil {
		return api.Rollout{}, err
	}
	if err := s.publish(ctx, platformaudit.RolloutDesiredPublished{
		TenantID: tenantID, DataPlaneID: dataPlaneID, Generation: generation,
		OCIRef: desired.Signed.OCIRef, Digest: desired.Signed.Digest,
		Version: desired.Version, OccurredAt: now,
	}); err != nil {
		return api.Rollout{}, err
	}
	return r, nil
}

// Reconcile drives one reconcile of an open rollout against the data plane's applier seam
// (AC4). It applies the desired release, and a failure rolls the upgrade back to the prior
// signed release and records the reason (AC5). The applier is local to the reconcile harness:
// no inbound path is opened (SPEC-0039 AC4). A terminal rollout, or one held by the version
// window, is left untouched (AC4 idempotency, AC7).
func (s *Service) Reconcile(ctx context.Context, tenantID, dataPlaneID string, applier api.Applier) (api.Rollout, error) {
	now := s.cfg.Now()
	r, ok, err := s.store.Rollout(ctx, tenantID, dataPlaneID)
	if err != nil {
		return api.Rollout{}, err
	}
	if !ok {
		return api.Rollout{}, api.ErrNotFound
	}

	// A failed upgrade is rolled back at the first reconcile after the failure (AC5).
	if r.Phase == api.PhaseFailed {
		return s.rollback(ctx, r, applier, r.Message, now)
	}
	// Idempotency: a terminal rollout has nothing to reconcile (AC4).
	if r.Phase.Terminal() {
		return r, nil
	}

	// AC7: honor the customer's pin/deferral. A held version is not forced.
	w, _, werr := s.store.Window(ctx, tenantID, dataPlaneID)
	if werr != nil {
		return api.Rollout{}, werr
	}
	if w.Holds(r.DesiredVersion, now) {
		return r, nil
	}
	if w.Expired(now) {
		// An upgrade is not silently forced past the supported window (AC7).
		return r, api.ErrWindowExpired
	}

	// AC4: apply the desired release through the seam.
	if applyErr := applier.Apply(ctx, r.Desired); applyErr != nil {
		return s.rollback(ctx, r, applier, applyErr.Error(), now)
	}
	// Applied by the seam; the data plane's report is what moves the rollout to APPLIED — only
	// a reported convergence may do that (AC6).
	r.UpdatedAt = now
	if err := s.store.PutRollout(ctx, r); err != nil {
		return api.Rollout{}, err
	}
	return r, nil
}

// ReportActual ingests one data-plane report and advances the rollout (AC6). A report is the
// only thing that may move a rollout to APPLIED; an unhealthy report for the current
// generation marks it FAILED so the next reconcile rolls it back.
func (s *Service) ReportActual(ctx context.Context, tenantID, dataPlaneID string, report api.ActualReport) (api.Rollout, error) {
	now := s.cfg.Now()
	r, ok, err := s.store.Rollout(ctx, tenantID, dataPlaneID)
	if err != nil {
		return api.Rollout{}, err
	}
	if !ok {
		return api.Rollout{}, api.ErrNotFound
	}
	r.LastReportedAt = now
	r.UpdatedAt = now
	if report.ActualVersion != "" {
		r.ActualVersion = report.ActualVersion
	}

	if report.AppliedGeneration == r.Generation {
		switch {
		case report.Healthy && report.ActualVersion == r.DesiredVersion:
			if r.Phase != api.PhaseApplied {
				r.Phase = api.PhaseApplied
				r.Message = report.Message
				if err := s.publish(ctx, platformaudit.RolloutApplied{
					TenantID: tenantID, DataPlaneID: dataPlaneID,
					Generation: r.Generation, Version: r.DesiredVersion, OccurredAt: now,
				}); err != nil {
					return api.Rollout{}, err
				}
			}
		case !report.Healthy:
			if r.Phase == api.PhaseInProgress {
				r.Phase = api.PhaseFailed
				r.Message = report.Message
				if err := s.publish(ctx, platformaudit.RolloutFailed{
					TenantID: tenantID, DataPlaneID: dataPlaneID,
					Generation: r.Generation, Version: r.DesiredVersion,
					Reason: report.Message, OccurredAt: now,
				}); err != nil {
					return api.Rollout{}, err
				}
			}
		}
	}
	if err := s.store.PutRollout(ctx, r); err != nil {
		return api.Rollout{}, err
	}
	return r, nil
}

// Rollout returns the current rollout with its AC6 status derived at read time: a silent data
// plane reads stale, never applied.
func (s *Service) Rollout(ctx context.Context, tenantID, dataPlaneID string) (api.Rollout, api.RolloutStatus, error) {
	r, ok, err := s.store.Rollout(ctx, tenantID, dataPlaneID)
	if err != nil {
		return api.Rollout{}, api.RolloutStatus{}, err
	}
	if !ok {
		return api.Rollout{}, api.RolloutStatus{}, api.ErrNotFound
	}
	return r, domain.DeriveStatus(r, s.cfg.Now(), s.cfg.StaleAfter), nil
}

// SetWindow records the data plane's AC7 pin/defer window and audits the act, including the
// supported-window expiry so it is a visible fact.
func (s *Service) SetWindow(ctx context.Context, tenantID, dataPlaneID string, w api.VersionWindow) error {
	now := s.cfg.Now()
	if err := s.store.PutWindow(ctx, tenantID, dataPlaneID, w); err != nil {
		return err
	}
	return s.publish(ctx, platformaudit.RolloutWindowSet{
		TenantID: tenantID, DataPlaneID: dataPlaneID,
		PinnedVersion: w.PinnedVersion, DeferredUntil: w.DeferredUntil,
		SupportedUntil: w.SupportedUntil, OccurredAt: now,
	})
}

// Window returns the data plane's AC7 window; no explicit window holds nothing.
func (s *Service) Window(ctx context.Context, tenantID, dataPlaneID string) (api.VersionWindow, error) {
	w, _, err := s.store.Window(ctx, tenantID, dataPlaneID)
	return w, err
}

// rollback reverts a failed rollout to its prior signed release and records the reason (AC5).
// It never hides the outcome: a successful rollback reads ROLLED_BACK, a first-ever failed
// rollout with nothing to revert to reads FAILED, and a rollback that itself cannot apply
// reads FAILED with both reasons — the half-applied state AC5 forbids leaving silent.
func (s *Service) rollback(ctx context.Context, r api.Rollout, applier api.Applier, reason string, now time.Time) (api.Rollout, error) {
	fromVersion := r.DesiredVersion

	if r.Prior == nil {
		// Nothing to roll back to: this was the first rollout. Record the failure plainly.
		r.Phase = api.PhaseFailed
		r.Message = reason
		r.UpdatedAt = now
		if err := s.store.PutRollout(ctx, r); err != nil {
			return api.Rollout{}, err
		}
		if err := s.publish(ctx, platformaudit.RolloutFailed{
			TenantID: r.TenantID, DataPlaneID: r.DataPlaneID,
			Generation: r.Generation, Version: fromVersion, Reason: reason, OccurredAt: now,
		}); err != nil {
			return api.Rollout{}, err
		}
		return r, nil
	}

	if rbErr := applier.Apply(ctx, *r.Prior); rbErr != nil {
		// The rollback itself failed: surface BOTH reasons; never leave it half-applied and
		// unsaid (AC5).
		r.Phase = api.PhaseFailed
		r.Message = reason + "; rollback also failed: " + rbErr.Error()
		r.UpdatedAt = now
		if err := s.store.PutRollout(ctx, r); err != nil {
			return api.Rollout{}, err
		}
		if err := s.publish(ctx, platformaudit.RolloutFailed{
			TenantID: r.TenantID, DataPlaneID: r.DataPlaneID,
			Generation: r.Generation, Version: fromVersion, Reason: r.Message, OccurredAt: now,
		}); err != nil {
			return api.Rollout{}, err
		}
		return r, nil
	}

	r.Phase = api.PhaseRolledBack
	r.ActualVersion = r.Prior.Version
	r.Message = reason
	r.UpdatedAt = now
	if err := s.store.PutRollout(ctx, r); err != nil {
		return api.Rollout{}, err
	}
	if err := s.publish(ctx, platformaudit.RolloutRolledBack{
		TenantID: r.TenantID, DataPlaneID: r.DataPlaneID,
		Generation: r.Generation, FromVersion: fromVersion,
		ToVersion: r.Prior.Version, Reason: reason, OccurredAt: now,
	}); err != nil {
		return api.Rollout{}, err
	}
	return r, nil
}

// runningRelease is the release a new rollout captures as its rollback target: whatever was
// applied before it. An applied rollout's current release is its desired; a rolled-back one is
// running its prior.
func runningRelease(found bool, prev api.Rollout) *api.Release {
	if !found {
		return nil
	}
	if prev.Phase == api.PhaseApplied {
		d := prev.Desired
		return &d
	}
	return prev.Prior
}

// refusalReason maps a verification refusal onto the coarse audit vocabulary (AC3, G6).
func refusalReason(err error) string {
	switch {
	case errors.Is(err, api.ErrReleaseUnsigned):
		return "unsigned"
	case errors.Is(err, api.ErrReleaseMisSigned):
		return "mis_signed"
	case errors.Is(err, api.ErrReleaseMalformed):
		return "malformed"
	default:
		return "refused"
	}
}

// publish carries one audit event to the bus. A failure is returned to the caller: an
// unaudited security act is reported, never swallowed (ADR-0007).
func (s *Service) publish(ctx context.Context, e bus.Event) error { return s.events.Publish(ctx, e) }
