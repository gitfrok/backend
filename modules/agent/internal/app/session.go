package app

import (
	"context"
	"sync"
	"time"

	"github.com/gitfrok/backend/modules/agent/api"
	platformaudit "github.com/gitfrok/backend/platform/audit"
)

// streamSession is the control-plane half of one established stream: the certificate
// rotation state machine and the contact bookkeeping (ADR-0060 §2, SPEC-0038 AC4).
//
// The shape of the machine: one current certificate, at most one pending rotation. The
// next rotation is issued RotationLead before the current expiry; a failed or
// unacknowledged attempt is retried every RotationRetryInterval; if the current
// certificate expires before any attempt is applied, the session lapses and the stream is
// refused — never extended.
type streamSession struct {
	svc *Service
	id  api.Identity

	mu            sync.Mutex
	currentID     string
	currentExpiry time.Time
	pendingID     string
	pendingExpiry time.Time
	nextRetryAt   time.Time // meaningful while pendingID != ""
	retryInterval time.Duration
	lapsed        bool
	done          chan struct{}
	doneOnce      sync.Once
	closed        bool
}

var _ api.StreamSession = (*streamSession)(nil)

func (ss *streamSession) Identity() api.Identity { return ss.id }

// RotationDueAt is when the adapter must next call Rotate: the rotation lead before the
// current expiry, or the next retry while an attempt is outstanding.
func (ss *streamSession) RotationDueAt() time.Time {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if ss.pendingID != "" {
		return ss.nextRetryAt
	}
	return ss.currentExpiry.Add(-ss.svc.cfg.RotationLead)
}

// Rotate issues (or re-issues, on retry) the next certificate and marks it pending the
// agent's ack. One issuance, one pending at a time: the audit record for the rotation act
// is written when the outcome is known (the ack), so an attempt is never double-recorded.
func (ss *streamSession) Rotate(ctx context.Context) (api.IssuedCertificate, error) {
	now := ss.svc.cfg.Now()
	if ss.Lapsed(now) {
		return api.IssuedCertificate{}, api.ErrNotFound // a lapsed session is refused, never re-issued
	}
	cert, err := ss.svc.issuer.Issue(ctx, ss.id, now, ss.svc.cfg.CertLifetime, ss.svc.cfg.ClockSkewLeeway)
	if err != nil {
		return api.IssuedCertificate{}, err
	}
	ss.mu.Lock()
	ss.pendingID = cert.CertificateID
	ss.pendingExpiry = cert.ExpiresAt
	ss.nextRetryAt = now.Add(ss.retryInterval)
	ss.mu.Unlock()
	return cert, nil
}

// AckRotation applies the agent's answer for certificateID. Exactly one audit record per
// applied-or-failed act (SPEC-0038 AC7); acks for unknown or superseded certificates are
// ignored.
func (ss *streamSession) AckRotation(ctx context.Context, certificateID string, applied bool, failureReason string) error {
	ss.mu.Lock()
	if certificateID != ss.pendingID {
		ss.mu.Unlock()
		return nil
	}
	now := ss.svc.cfg.Now()
	if applied {
		ss.currentID = ss.pendingID
		ss.currentExpiry = ss.pendingExpiry
		newExpiry := ss.pendingExpiry
		ss.pendingID = ""
		ss.mu.Unlock()
		if err := ss.svc.registry.SetCertificate(ctx, ss.id.TenantID, ss.id.DataPlaneID, certificateID, newExpiry); err != nil {
			return err
		}
		return ss.svc.publish(ctx, platformaudit.AgentCertificateRotation{
			TenantID: ss.id.TenantID, DataPlaneID: ss.id.DataPlaneID,
			CertificateID: certificateID, Outcome: "ALLOWED", OccurredAt: now,
		})
	}
	// Failed: keep the attempt pending, pace the retry, record the refusal.
	ss.nextRetryAt = now.Add(ss.retryInterval)
	ss.mu.Unlock()
	return ss.svc.publish(ctx, platformaudit.AgentCertificateRotation{
		TenantID: ss.id.TenantID, DataPlaneID: ss.id.DataPlaneID,
		CertificateID: certificateID, Reason: failureReason, Outcome: "DENIED", OccurredAt: now,
	})
}

// Lapsed reports whether the current certificate expired without a successful rotation.
// The first read past the expiry marks the session lapsed permanently: a late ack cannot
// resurrect an expired identity (SPEC-0038 AC4 — refused rather than extended).
func (ss *streamSession) Lapsed(now time.Time) bool {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if ss.lapsed {
		return true
	}
	if !now.Before(ss.currentExpiry) {
		ss.lapsed = true
		return true
	}
	return false
}

// Touch records contact for the staleness window. A touch failure is not returned to the
// stream: last-seen is read-side bookkeeping, and dropping a message over it would trade
// availability for a timestamp.
func (ss *streamSession) Touch(ctx context.Context) {
	_ = ss.svc.registry.MarkSeen(ctx, ss.id.TenantID, ss.id.DataPlaneID, ss.svc.cfg.Now())
}

// Done closes when the control plane ends the stream itself (revocation).
func (ss *streamSession) Done() <-chan struct{} { return ss.done }

// terminate is the CP-initiated end: close Done exactly once.
func (ss *streamSession) terminate() {
	ss.doneOnce.Do(func() { close(ss.done) })
}

// Close unregisters the session. Idempotent.
func (ss *streamSession) Close(_ context.Context) {
	ss.mu.Lock()
	if ss.closed {
		ss.mu.Unlock()
		return
	}
	ss.closed = true
	ss.mu.Unlock()
	ss.svc.removeStream(ss.id)
	ss.terminate()
}
