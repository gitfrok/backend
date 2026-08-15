package main

import (
	"context"
	"fmt"
	"time"
)

// WorkloadApplier converges the data-plane workload's image onto a digest pin.
// The operator's only actuation is this one field: it never touches git
// data, credentials, or any workload surface but the image the signed release
// names (ADR-0065 decision 1).
type WorkloadApplier interface {
	// CurrentWorkloadImage is the image the workload runs right now. ok is
	// false before the workload exists.
	CurrentWorkloadImage(ctx context.Context) (image string, ok bool, err error)
	// ApplyWorkloadImage sets the workload's container image. The argument is
	// ALWAYS a digest pin (oci_ref@digest) — the reconciler never hands it a
	// mutable tag.
	ApplyWorkloadImage(ctx context.Context, digestPinnedImage string) error
}

// DesiredVersionSource is the CR half of the loop: spec.version is the
// desired release the control plane published over the agent channel. The
// operator never invents a version of its own (SPEC-0039 AC4).
type DesiredVersionSource interface {
	DesiredVersion(ctx context.Context) (string, error)
}

// StatusReport is one rollout report the operator writes back on the CR's
// status subresource (SPEC-0039 AC6): exactly the fields the CRD schema
// names — observedVersion, phase, message, lastHeartbeatTime — and no
// credential material, ever (the CRD gate asserts the same).
type StatusReport struct {
	ObservedVersion   string
	Phase             string
	Message           string
	LastHeartbeatTime time.Time
}

// StatusWriter writes the rollout report onto the DataPlane CR.
type StatusWriter interface {
	WriteStatus(ctx context.Context, report StatusReport) error
}

// Phase is the bounded status vocabulary the CR renders.
const (
	PhaseUpToDate = "UpToDate" // the workload already runs the desired signed release
	PhaseApplied  = "Applied"  // the workload was converged onto the desired release
	PhaseFailed   = "Failed"   // verification or application refused; nothing half-applied
)

// Reconciler is the narrow loop: read the desired version, resolve its signed
// manifest, VERIFY before applying, converge the workload onto the digest
// pin, report. Failures are reported on the CR, never half-applied.
type Reconciler struct {
	Bundle    *ReleaseTrustBundle
	Manifests ManifestSource
	Desired   DesiredVersionSource
	Applier   WorkloadApplier
	Status    StatusWriter
	Component string
	Now       func() time.Time
	Logf      func(format string, args ...any)
	SyncEvery time.Duration
}

// Run loops until the context ends. A reconciliation error is reported on the
// CR and retried on the next tick: the loop itself must not die on one bad
// release.
func (r *Reconciler) Run(ctx context.Context) error {
	ticker := time.NewTicker(r.SyncEvery)
	defer ticker.Stop()
	for {
		if err := r.ReconcileOnce(ctx); err != nil {
			r.Logf("operator-app: reconcile: %v", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// ReconcileOnce is one pass of the loop, exposed for tests and for main's
// first synchronous pass.
func (r *Reconciler) ReconcileOnce(ctx context.Context) error {
	version, err := r.Desired.DesiredVersion(ctx)
	if err != nil {
		return r.fail(ctx, "", fmt.Sprintf("desired version unreadable: %v", err))
	}
	rel, err := r.Manifests.Manifest(ctx, r.Component, version)
	if err != nil {
		return r.fail(ctx, "", fmt.Sprintf("release %s@%s not applicable: %v", r.Component, version, err))
	}
	// VERIFY BEFORE APPLY (SPEC-0039 AC3): an unsigned or mis-signed release
	// is refused here, before the workload is touched.
	if err := r.Bundle.Verify(rel.CanonicalIdentity(), rel.SignatureDER); err != nil {
		return r.fail(ctx, "", err.Error())
	}
	pin := rel.CanonicalIdentity()
	current, ok, err := r.Applier.CurrentWorkloadImage(ctx)
	if err != nil {
		return r.fail(ctx, "", fmt.Sprintf("workload image unreadable: %v", err))
	}
	if ok && current == pin {
		// Idempotent convergence: the desired signed release already runs —
		// no second rollout, only the heartbeat (SPEC-0039 AC4).
		return r.report(ctx, StatusReport{
			ObservedVersion: version, Phase: PhaseUpToDate,
			Message: "workload already runs the signed release " + pin,
		})
	}
	if err := r.Applier.ApplyWorkloadImage(ctx, pin); err != nil {
		return r.fail(ctx, "", fmt.Sprintf("applying %s: %v", pin, err))
	}
	r.Logf("operator-app: converged workload onto %s", pin)
	return r.report(ctx, StatusReport{
		ObservedVersion: version, Phase: PhaseApplied,
		Message: "workload converged onto signed release " + pin,
	})
}

// fail reports a Failed phase. The observed version is NEVER advanced on a
// refusal: the CR reads what is actually running, not what was attempted
// (SPEC-0039 AC6). The report's own write error wins, because a reconciler
// that cannot report is flying blind.
func (r *Reconciler) fail(ctx context.Context, observed, message string) error {
	if err := r.report(ctx, StatusReport{ObservedVersion: observed, Phase: PhaseFailed, Message: message}); err != nil {
		return err
	}
	return fmt.Errorf("%s", message)
}

func (r *Reconciler) report(ctx context.Context, rep StatusReport) error {
	rep.LastHeartbeatTime = r.Now()
	return r.Status.WriteStatus(ctx, rep)
}
