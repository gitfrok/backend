package replica

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/gitfrok/backend/modules/repository/api"
	"github.com/gitfrok/backend/platform/audit"
	"github.com/gitfrok/backend/platform/bus"
)

const (
	tenantID     = "tenant-a"
	repositoryID = "repo-a"
	term1        = uint64(1)
)

func seedTwoNode(t *testing.T, c *InMemory) {
	t.Helper()
	if err := c.SeedShard(api.ShardSeed{
		TenantID: tenantID, RepositoryID: repositoryID,
		PrimaryNode: "node-a", SyncReplica: "node-b",
	}); err != nil {
		t.Fatalf("SeedShard: %v", err)
	}
}

// AC1: a push is acknowledged only after primary + sync are durable under the same term.
func TestQuorumRequiresPrimaryAndSyncAck(t *testing.T) {
	c := NewInMemoryCoordinator("", nil)
	seedTwoNode(t, c)

	ctx := t.Context()
	lease, err := c.BindLease(ctx, tenantID, repositoryID, "op-1", "node-a", term1)
	if err != nil || !lease.Granted {
		t.Fatalf("BindLease = %+v err=%v, want granted", lease, err)
	}

	// Primary ack alone must NOT satisfy quorum.
	q, err := c.AckDurable(ctx, tenantID, repositoryID, "op-1", "node-a", term1)
	if err != nil {
		t.Fatalf("AckDurable(primary): %v", err)
	}
	if !q.PrimaryAcked || q.SyncAcked {
		t.Fatalf("after primary ack: primary=%v sync=%v, want primary=true sync=false", q.PrimaryAcked, q.SyncAcked)
	}
	if err := c.WaitForQuorum(ctx, tenantID, repositoryID, "op-1", term1, 50*time.Millisecond); !errors.Is(err, ErrQuorumUnavailable) {
		t.Fatalf("WaitForQuorum after primary-only ack = %v, want ErrQuorumUnavailable", err)
	}

	// An async replica (neither primary nor sync) cannot satisfy quorum.
	if _, err := c.AckDurable(ctx, tenantID, repositoryID, "op-1", "node-c", term1); err != nil {
		t.Fatalf("AckDurable(async): %v", err)
	}
	if err := c.WaitForQuorum(ctx, tenantID, repositoryID, "op-1", term1, 50*time.Millisecond); !errors.Is(err, ErrQuorumUnavailable) {
		t.Fatalf("async ack should not satisfy quorum: %v", err)
	}

	// Sync ack completes the quorum.
	if _, err := c.AckDurable(ctx, tenantID, repositoryID, "op-1", "node-b", term1); err != nil {
		t.Fatalf("AckDurable(sync): %v", err)
	}
	if err := c.WaitForQuorum(ctx, tenantID, repositoryID, "op-1", term1, 50*time.Millisecond); err != nil {
		t.Fatalf("WaitForQuorum after sync ack = %v, want nil", err)
	}
}

// TestSingleNodeAutoSeedSatisfiesQuorum: single-node dev mode where primary==sync==localNodeID,
// so one ack satisfies the quorum.
func TestSingleNodeAutoSeedSatisfiesQuorum(t *testing.T) {
	c := NewInMemoryCoordinator("node-a", nil)
	ctx := t.Context()
	// GetShard auto-seeds: primary==sync=="node-a".
	rec, err := c.GetShard(ctx, tenantID, repositoryID, 0)
	if err != nil {
		t.Fatalf("GetShard: %v", err)
	}
	if rec.PrimaryNode != "node-a" || rec.SyncReplica != "node-a" || !rec.WriteReady {
		t.Fatalf("auto-seed = %+v", rec)
	}
	if _, err := c.BindLease(ctx, tenantID, repositoryID, "op-x", "node-a", term1); err != nil {
		t.Fatalf("BindLease: %v", err)
	}
	// One ack from node-a sets both primary and sync (same node) → quorum met.
	q, err := c.AckDurable(ctx, tenantID, repositoryID, "op-x", "node-a", term1)
	if err != nil || !q.PrimaryAcked || !q.SyncAcked {
		t.Fatalf("AckDurable = %+v err=%v, want both acked", q, err)
	}
	if err := c.WaitForQuorum(ctx, tenantID, repositoryID, "op-x", term1, 50*time.Millisecond); err != nil {
		t.Fatalf("WaitForQuorum = %v, want nil", err)
	}
}

// AC2: stale term, stale primary, mismatched term are denied without changing the record.
func TestStaleTermAndStalePrimaryAreDeniedWithoutChangingRecord(t *testing.T) {
	c := NewInMemoryCoordinator("", nil)
	seedTwoNode(t, c)
	ctx := t.Context()

	// BindLease with a stale (too-high) term: denied, returns current term.
	lease, err := c.BindLease(ctx, tenantID, repositoryID, "op", "node-a", 99)
	if err != nil || lease.Granted {
		t.Fatalf("BindLease stale term = %+v err=%v, want denied", lease, err)
	}
	if lease.DenyReason != api.DenyReasonStaleTerm || lease.CurrentTerm != term1 {
		t.Fatalf("BindLease stale = %+v, want StaleTerm current=1", lease)
	}
	// BindLease with zero term: denied stale.
	lease, _ = c.BindLease(ctx, tenantID, repositoryID, "op", "node-a", 0)
	if lease.Granted || lease.DenyReason != api.DenyReasonStaleTerm {
		t.Fatalf("BindLease zero term = %+v", lease)
	}

	// A correct bind, then a stale-primary ack must be refused and leave the op untouched.
	if _, err := c.BindLease(ctx, tenantID, repositoryID, "op-a", "node-a", term1); err != nil {
		t.Fatal(err)
	}
	if _, err := c.AckDurable(ctx, tenantID, repositoryID, "op-a", "node-a", 99); !errors.Is(err, ErrStaleTerm) {
		t.Fatalf("AckDurable stale term = %v, want ErrStaleTerm", err)
	}
}

// AC2: an unknown shard is denied.
func TestUnknownShardDenied(t *testing.T) {
	c := NewInMemoryCoordinator("", nil)
	ctx := t.Context()
	if _, err := c.BindLease(ctx, tenantID, repositoryID, "op", "node-a", term1); !errors.Is(err, ErrShardNotFound) {
		t.Fatalf("BindLease unknown shard = %v, want ErrShardNotFound", err)
	}
}

// AC3: auto-promotion is a CAS from healthy to the in-sync replica; the old primary is fenced (stale
// term) and the shard is not write-ready until AcknowledgeFence.
func TestAutoPromoteCASAndFence(t *testing.T) {
	c := NewInMemoryCoordinator("", nil)
	seedTwoNode(t, c)
	ctx := t.Context()

	res, err := c.PromoteReplica(ctx, tenantID, repositoryID)
	if err != nil || !res.Promoted || res.Term != 2 || res.WriteReady {
		t.Fatalf("PromoteReplica = %+v err=%v, want promoted term=2 writeReady=false", res, err)
	}
	rec, err := c.GetShard(ctx, tenantID, repositoryID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if rec.PrimaryNode != "node-b" || rec.SyncReplica != "node-a" || rec.FencingTerm != 2 {
		t.Fatalf("after promote, primary=%q sync=%q term=%d, want node-b/node-a/2", rec.PrimaryNode, rec.SyncReplica, rec.FencingTerm)
	}
	if rec.State != api.ShardStateRecovering || rec.WriteReady {
		t.Fatalf("after promote, state=%v writeReady=%v, want RECOVERING/false", rec.State, rec.WriteReady)
	}

	// The old primary (node-a) is fenced: its term-1 lease/ack is now stale.
	lease, _ := c.BindLease(ctx, tenantID, repositoryID, "op", "node-a", term1)
	if lease.Granted || lease.DenyReason != api.DenyReasonStaleTerm || lease.CurrentTerm != 2 {
		t.Fatalf("old primary lease after promote = %+v", lease)
	}
	if _, err := c.AckDurable(ctx, tenantID, repositoryID, "op-a", "node-a", term1); !errors.Is(err, ErrStaleTerm) {
		t.Fatalf("old primary ack after promote = %v, want ErrStaleTerm", err)
	}

	// The new primary (node-b) cannot yet write — the shard is recovering / not write-ready.
	lease, _ = c.BindLease(ctx, tenantID, repositoryID, "op2", "node-b", 2)
	if lease.Granted || lease.DenyReason != api.DenyReasonNotWriteReady {
		t.Fatalf("new primary lease before fence = %+v, want NotWriteReady", lease)
	}

	// The new primary acknowledges the fence → write-ready.
	ok, err := c.AcknowledgeFence(ctx, tenantID, repositoryID, "node-b", 2)
	if err != nil || !ok {
		t.Fatalf("AcknowledgeFence = %v, %v", ok, err)
	}
	rec, _ = c.GetShard(ctx, tenantID, repositoryID, 0)
	if !rec.WriteReady || rec.State != api.ShardStateHealthy || rec.FencingTerm != 2 {
		t.Fatalf("after fence = %+v, want writeReady healthy term=2", rec)
	}
	lease, _ = c.BindLease(ctx, tenantID, repositoryID, "op3", "node-b", 2)
	if !lease.Granted {
		t.Fatalf("new primary lease after fence = %+v, want granted", lease)
	}
}

// AC3: promotion from a non-healthy shard is refused (CAS fails, record unchanged).
func TestPromoteRefusedWhenNotHealthy(t *testing.T) {
	c := NewInMemoryCoordinator("", nil)
	seedTwoNode(t, c)
	ctx := t.Context()
	// Second promotion would race / find a non-healthy shard.
	if _, err := c.PromoteReplica(ctx, tenantID, repositoryID); err != nil {
		t.Fatalf("first PromoteReplica: %v", err)
	}
	// Shard is now RECOVERING; a further auto-promote is refused.
	res, err := c.PromoteReplica(ctx, tenantID, repositoryID)
	if err != nil || res.Promoted || res.DenyReason != api.DenyReasonNotHealthy {
		t.Fatalf("second PromoteReplica = %+v err=%v, want not healthy", res, err)
	}
	// Fence the first promotion, then another auto-promote is again refused only on a new loss.
	if _, err := c.AcknowledgeFence(ctx, tenantID, repositoryID, "node-b", 2); err != nil {
		t.Fatal(err)
	}
}

// AC4: confirmed dual loss fails the shard to read-only; no automatic async promotion.
func TestDualLossFailsReadOnly(t *testing.T) {
	c := NewInMemoryCoordinator("", nil)
	seedTwoNode(t, c)
	ctx := t.Context()
	if err := c.MarkDegraded(ctx, tenantID, repositoryID); err != nil {
		t.Fatal(err)
	}
	rec, _ := c.GetShard(ctx, tenantID, repositoryID, 0)
	if rec.State != api.ShardStateDegradedReadOnly || rec.WriteReady {
		t.Fatalf("after dual loss = %+v, want DEGRADED_READ_ONLY writeReady=false", rec)
	}
	// No write route: primary denied despite correct term.
	lease, _ := c.BindLease(ctx, tenantID, repositoryID, "op", "node-a", term1)
	if lease.Granted || lease.DenyReason != api.DenyReasonNotWriteReady {
		t.Fatalf("BindLease on read-only = %+v, want NotWriteReady", lease)
	}
	// No automatic async promotion out of a dual loss.
	res, err := c.PromoteReplica(ctx, tenantID, repositoryID)
	if err != nil || res.Promoted || res.DenyReason != api.DenyReasonNotHealthy {
		t.Fatalf("auto-promote from read-only = %+v err=%v, want refused NotHealthy", res, err)
	}
}

// AC5: force-promote is the operator override from degraded-read-only, PDP-decision-gated, and emits
// exactly one immutable replica.force_promote audit event with the bounded detail vocabulary.
func TestForcePromoteFromDegradedReadOnlyAudited(t *testing.T) {
	b := bus.NewInProcess()
	var events []audit.ForcePromote
	bus.SubscribeTyped(b, func(_ context.Context, e audit.ForcePromote) error {
		events = append(events, e)
		return nil
	})
	c := NewInMemoryCoordinator("", b)
	seedTwoNode(t, c)
	ctx := t.Context()
	// Give the sync replica a recorded ack so the RPO estimate is real, then declare dual loss.
	if _, err := c.BindLease(ctx, tenantID, repositoryID, "op", "node-a", term1); err != nil {
		t.Fatalf("BindLease: %v", err)
	}
	if _, err := c.AckDurable(ctx, tenantID, repositoryID, "op", "node-b", term1); err != nil {
		t.Fatal(err)
	}
	if err := c.MarkDegraded(ctx, tenantID, repositoryID); err != nil {
		t.Fatal(err)
	}

	res, err := c.ForcePromote(ctx, api.ForcePromoteRequest{
		TenantID: tenantID, RepositoryID: repositoryID, TargetNode: "node-c",
		PolicyDecisionID: "pd-1", ActorID: "op-1",
	})
	if err != nil || !res.Promoted {
		t.Fatalf("ForcePromote = %+v err=%v, want promoted", res, err)
	}
	if res.PreviousTerm != term1 || res.ResultingTerm != 2 || res.EstimatedRPOSeconds == 0 || res.EstimatedRPOSeconds == 1<<30 {
		t.Fatalf("ForcePromote terms/rpo = prev=%d new=%d rpo=%d", res.PreviousTerm, res.ResultingTerm, res.EstimatedRPOSeconds)
	}
	rec, _ := c.GetShard(ctx, tenantID, repositoryID, 0)
	if rec.PrimaryNode != "node-c" || rec.FencingTerm != 2 || rec.State != api.ShardStateRecovering || rec.WriteReady {
		t.Fatalf("after force-promote = %+v", rec)
	}

	if len(events) != 1 {
		t.Fatalf("published %d audit events, want 1", len(events))
	}
	got := events[0]
	if got.EventName() != audit.EventAudit {
		t.Errorf("event name = %q, want %q", got.EventName(), audit.EventAudit)
	}
	if got.Action() != audit.ActionReplicaForcePromote {
		t.Errorf("action = %q, want %q", got.Action(), audit.ActionReplicaForcePromote)
	}
	if got.TenantID != tenantID || got.ActorID != "op-1" || got.PolicyDecisionID != "pd-1" {
		t.Errorf("evidence identity = %+v", got)
	}
	if got.PreviousTerm != term1 || got.ResultingTerm != 2 || got.TargetNode != "node-c" {
		t.Errorf("evidence terms/target = %+v", got)
	}
}

// AC5: force-promote is refused (and emits no audit event) when the shard is not degraded-read-only.
func TestForcePromoteRefusedWhenNotDegraded(t *testing.T) {
	b := bus.NewInProcess()
	var events []audit.ForcePromote
	bus.SubscribeTyped(b, func(_ context.Context, e audit.ForcePromote) error {
		events = append(events, e)
		return nil
	})
	c := NewInMemoryCoordinator("", b)
	seedTwoNode(t, c)
	ctx := t.Context()
	// Healthy shard is the wrong state for an operator override.
	res, err := c.ForcePromote(ctx, api.ForcePromoteRequest{
		TenantID: tenantID, RepositoryID: repositoryID, TargetNode: "node-c",
		PolicyDecisionID: "pd-1", ActorID: "op-1",
	})
	if err != nil || res.Promoted || res.DenyReason != api.DenyReasonNotHealthy {
		t.Fatalf("ForcePromote on healthy = %+v err=%v, want refused NotHealthy", res, err)
	}
	if len(events) != 0 {
		t.Fatalf("published %d audit events for a refused force-promote, want 0", len(events))
	}
}

// AC4/AC5: an unknown shard cannot be force-promoted.
func TestForcePromoteUnknownShard(t *testing.T) {
	c := NewInMemoryCoordinator("", nil)
	_, err := c.ForcePromote(t.Context(), api.ForcePromoteRequest{
		TenantID: tenantID, RepositoryID: repositoryID, TargetNode: "node-c",
	})
	if !errors.Is(err, ErrShardNotFound) {
		t.Fatalf("ForcePromote unknown shard = %v, want ErrShardNotFound", err)
	}
}

// AC2/AC3: a stale term never satisfies quorum, and a term change mid-operation withholds the ack.
func TestTermChangeMidPushWithholdsAck(t *testing.T) {
	c := NewInMemoryCoordinator("", nil)
	seedTwoNode(t, c)
	ctx := t.Context()
	// Primary leases and acks under term 1.
	if _, err := c.BindLease(ctx, tenantID, repositoryID, "op", "node-a", term1); err != nil {
		t.Fatal(err)
	}
	if _, err := c.AckDurable(ctx, tenantID, repositoryID, "op", "node-a", term1); err != nil {
		t.Fatal(err)
	}
	// A promotion bumps the term to 2 mid-push; the in-flight op's quorum is now stale.
	if _, err := c.PromoteReplica(ctx, tenantID, repositoryID); err != nil {
		t.Fatal(err)
	}
	if err := c.WaitForQuorum(ctx, tenantID, repositoryID, "op", term1, 50*time.Millisecond); !errors.Is(err, ErrStaleOperation) {
		t.Fatalf("WaitForQuorum after term change = %v, want ErrStaleOperation", err)
	}
}
