// Package replica is the Repository/Git context's in-process replica coordination adapter
// (SPEC-0018, ADR-0042, ADR-0046).
//
// The state machine here implements the durable-ack quorum, the monotonic fencing term, the
// healthy→in-sync-replica CAS promotion with fence acknowledgement, the dual-loss fail-safe, and the
// audited operator force-promote. It is the single-node/dev adapter: it auto-seeds an unknown shard
// as primary==sync==the local node so a standalone storage node can still acknowledge a push.
// Production deployments use a shared durable substrate (Postgres advisory/CAS or etcd) behind the
// same api.Coordinator port — that adapter choice does not alter the term semantics or the quorum
// rule (SPEC-0018 §Data owned / §Open questions).
package replica

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/gitfrok/backend/modules/repository/api"
	"github.com/gitfrok/backend/platform/audit"
	"github.com/gitfrok/backend/platform/bus"
)

// Sentinel errors. A denial is reported through the value types (BindLease.DenyReason, the
// PromotedShard/ForcePromoteResult DenyReason) rather than through these errors for the consensus
// path, so a router can map a coordination refusal to a Git "repository unavailable" without parsing
// strings. These remain for the in-process wiring where a boolean isn't expressible in the port
// shape.
var (
	ErrShardNotFound     = errors.New("replica: shard not found")
	ErrOperationNotFound = errors.New("replica: operation not found")
	ErrQuorumUnavailable = errors.New("replica: sync replica did not acknowledge before timeout")
	ErrStaleTerm         = errors.New("replica: offered term is stale")
	ErrStaleOperation    = errors.New("replica: operation superseded by a term change")
	ErrNotWriteReady     = errors.New("replica: shard is not write-ready")
	ErrAlreadySeeded     = errors.New("replica: shard already seeded")
)

// InMemory is the single-process coordinator. It is concurrency-safe.
type InMemory struct {
	localNodeID string // this storage node's identity; used to auto-seed dev shards
	bus         bus.Bus
	mu          sync.Mutex
	shards      map[string]*shardState
}

// NewInMemoryCoordinator assembles an in-process coordinator. localNodeID is the identity this
// process presents as a replica; an empty localNodeID disables auto-seeding (every shard must be
// seeded explicitly), which is how the production-style contract is exercised in tests.
func NewInMemoryCoordinator(localNodeID string, b bus.Bus) *InMemory {
	return &InMemory{
		localNodeID: localNodeID,
		bus:         b,
		shards:      make(map[string]*shardState),
	}
}

// Satisfies the api.Coordinator port.
var _ api.Coordinator = (*InMemory)(nil)

type opState struct {
	term         uint64
	primaryAcked bool
	syncAcked    bool
	closed       bool
	done         chan struct{}
}

type shardState struct {
	rec         api.ShardRecord
	ops         map[string]*opState // operationID -> ack state, keyed by current term
	lastSyncAck time.Time           // when the in-sync replica last acked (drives RPO estimate)
}

func shardKey(tenantID, repositoryID string) string { return tenantID + "\x00" + repositoryID }

func newShard(tenantID, repositoryID, primary, sync string) *shardState {
	return &shardState{
		rec: api.ShardRecord{
			TenantID:     tenantID,
			RepositoryID: repositoryID,
			PrimaryNode:  primary,
			SyncReplica:  sync,
			FencingTerm:  1,
			State:        api.ShardStateHealthy,
			WriteReady:   true,
		},
		ops: make(map[string]*opState),
	}
}

// SeedShard records initial membership for a shard that has no live record. It is idempotent.
func (c *InMemory) SeedShard(seed api.ShardSeed) error {
	if seed.TenantID == "" || seed.RepositoryID == "" {
		return errors.New("replica: tenant and repository are required to seed")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	key := shardKey(seed.TenantID, seed.RepositoryID)
	if existing, ok := c.shards[key]; ok {
		// Idempotent re-seed only resets to the provided membership when the shard was never written.
		if existing.ops != nil {
			return fmt.Errorf("%w: %s", ErrAlreadySeeded, key)
		}
	}
	c.shards[key] = newShard(seed.TenantID, seed.RepositoryID, seed.PrimaryNode, seed.SyncReplica)
	return nil
}

// MarkDegraded records a confirmed primary-plus-sync loss, failing the shard to read-only
// (ADR-0042 §4). It is an operational input driven by the liveness subsystem; it is not in the
// consensus port because entry into this state is coordinator-internal there.
func (c *InMemory) MarkDegraded(ctx context.Context, tenantID, repositoryID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, ok := c.shards[shardKey(tenantID, repositoryID)]
	if !ok {
		return ErrShardNotFound
	}
	s.rec.State = api.ShardStateDegradedReadOnly
	s.rec.WriteReady = false
	return nil
}

func (c *InMemory) GetShard(_ context.Context, tenantID, repositoryID string, ifTerm uint64) (api.ShardRecord, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, ok := c.shards[shardKey(tenantID, repositoryID)]
	if !ok {
		if c.localNodeID != "" {
			s = newShard(tenantID, repositoryID, c.localNodeID, c.localNodeID)
			c.shards[shardKey(tenantID, repositoryID)] = s
		} else {
			return api.ShardRecord{}, ErrShardNotFound
		}
	}
	rec := s.rec
	if ifTerm != 0 && ifTerm != rec.FencingTerm {
		return rec, ErrStaleTerm
	}
	return rec, nil
}

func (c *InMemory) BindLease(_ context.Context, tenantID, repositoryID, operationID, nodeID string, term uint64) (api.BindLease, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, ok := c.shards[shardKey(tenantID, repositoryID)]
	if !ok {
		if c.localNodeID == "" {
			return api.BindLease{DenyReason: api.DenyReasonUnknownShard}, ErrShardNotFound
		}
		s = newShard(tenantID, repositoryID, c.localNodeID, c.localNodeID)
		c.shards[shardKey(tenantID, repositoryID)] = s
	}
	rec := s.rec
	cur := rec.FencingTerm
	if term != cur {
		return api.BindLease{Granted: false, DenyReason: api.DenyReasonStaleTerm, CurrentTerm: cur}, nil
	}
	if rec.State != api.ShardStateHealthy {
		return api.BindLease{Granted: false, DenyReason: api.DenyReasonNotWriteReady, CurrentTerm: cur}, nil
	}
	if !rec.WriteReady {
		return api.BindLease{Granted: false, DenyReason: api.DenyReasonNotWriteReady, CurrentTerm: cur}, nil
	}
	if nodeID != rec.PrimaryNode {
		return api.BindLease{Granted: false, DenyReason: api.DenyReasonNotPrimary, CurrentTerm: cur}, nil
	}
	s.ops[operationID] = &opState{term: term, done: make(chan struct{})}
	return api.BindLease{Granted: true, Term: term, CurrentTerm: cur}, nil
}

func (c *InMemory) AckDurable(_ context.Context, tenantID, repositoryID, operationID, nodeID string, term uint64) (api.AckQuorum, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, ok := c.shards[shardKey(tenantID, repositoryID)]
	if !ok {
		return api.AckQuorum{}, ErrShardNotFound
	}
	if term != s.rec.FencingTerm {
		return api.AckQuorum{}, ErrStaleTerm
	}
	op, ok := s.ops[operationID]
	if !ok {
		return api.AckQuorum{}, ErrOperationNotFound
	}
	if op.term != term {
		return api.AckQuorum{}, ErrStaleOperation
	}
	if nodeID == s.rec.PrimaryNode {
		op.primaryAcked = true
	}
	if nodeID == s.rec.SyncReplica {
		op.syncAcked = true
		s.lastSyncAck = time.Now()
	}
	// An async replica that is neither primary nor in-sync is ignored: it cannot satisfy the quorum
	// (SPEC-0018 AC1) and a stale primary cannot inject an acknowledgement (ADR-0042 §2).
	quorum := api.AckQuorum{PrimaryAcked: op.primaryAcked, SyncAcked: op.syncAcked}
	if op.primaryAcked && op.syncAcked && !op.closed {
		op.closed = true
		close(op.done)
	}
	return quorum, nil
}

func (c *InMemory) WaitForQuorum(ctx context.Context, tenantID, repositoryID, operationID string, term uint64, timeout time.Duration) error {
	c.mu.Lock()
	s, ok := c.shards[shardKey(tenantID, repositoryID)]
	if !ok {
		c.mu.Unlock()
		return ErrShardNotFound
	}
	if s.rec.FencingTerm != term {
		c.mu.Unlock()
		return ErrStaleOperation
	}
	op, ok := s.ops[operationID]
	if !ok {
		c.mu.Unlock()
		return ErrOperationNotFound
	}
	if op.term != term {
		c.mu.Unlock()
		return ErrStaleOperation
	}
	if op.primaryAcked && op.syncAcked {
		c.mu.Unlock()
		return nil
	}
	done := op.done
	c.mu.Unlock()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
		return nil
	case <-timer.C:
		return ErrQuorumUnavailable
	case <-ctx.Done():
		return ctx.Err()
	}
}

// PromoteReplica is the automated CAS promotion of the in-sync replica on primary loss
// (ADR-0042 §3). It may only succeed from a healthy shard; the new primary is the recorded in-sync
// replica, the term increments, and the shard enters RECOVERING (not write-ready) until the old
// primary fences via AcknowledgeFence. A stale primary's subsequent BindLease/AckDurable with the
// old term is rejected as stale, which is the fence.
func (c *InMemory) PromoteReplica(_ context.Context, tenantID, repositoryID string) (api.PromotedShard, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, ok := c.shards[shardKey(tenantID, repositoryID)]
	if !ok {
		return api.PromotedShard{}, ErrShardNotFound
	}
	if s.rec.State != api.ShardStateHealthy {
		return api.PromotedShard{Promoted: false, DenyReason: api.DenyReasonNotHealthy}, nil
	}
	newTerm := s.rec.FencingTerm + 1
	oldPrimary := s.rec.PrimaryNode
	s.rec.PrimaryNode = s.rec.SyncReplica
	s.rec.SyncReplica = oldPrimary
	s.rec.FencingTerm = newTerm
	s.rec.State = api.ShardStateRecovering
	s.rec.WriteReady = false
	return api.PromotedShard{Promoted: true, Term: newTerm, WriteReady: false}, nil
}

// AcknowledgeFence completes a promotion: the new primary reports the old term fenced and the shard
// flips to healthy and write-ready for the new term (ADR-0042 §3). Stale terms and non-promotions are
// refused without changing the record.
func (c *InMemory) AcknowledgeFence(_ context.Context, tenantID, repositoryID, nodeID string, term uint64) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, ok := c.shards[shardKey(tenantID, repositoryID)]
	if !ok {
		return false, ErrShardNotFound
	}
	if s.rec.FencingTerm != term {
		return false, nil
	}
	if s.rec.State != api.ShardStateRecovering {
		return false, nil
	}
	if nodeID != s.rec.PrimaryNode {
		return false, nil
	}
	s.rec.State = api.ShardStateHealthy
	s.rec.WriteReady = true
	return true, nil
}

// ForcePromote is the operator override from degraded-read-only (ADR-0042 §4, ADR-0046 §3). It
// carries no caller allow assertion: req.PolicyDecisionID is audit context only. It emits exactly
// one replica.force_promote audit event after a successful fence-and-CAS.
func (c *InMemory) ForcePromote(ctx context.Context, req api.ForcePromoteRequest) (api.ForcePromoteResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, ok := c.shards[shardKey(req.TenantID, req.RepositoryID)]
	if !ok {
		return api.ForcePromoteResult{}, ErrShardNotFound
	}
	if s.rec.State != api.ShardStateDegradedReadOnly {
		return api.ForcePromoteResult{Promoted: false, DenyReason: api.DenyReasonNotHealthy}, nil
	}
	previousTerm := s.rec.FencingTerm
	resultingTerm := previousTerm + 1
	s.rec.PrimaryNode = req.TargetNode
	s.rec.SyncReplica = ""
	s.rec.FencingTerm = resultingTerm
	s.rec.State = api.ShardStateRecovering
	s.rec.WriteReady = false

	rpo := estimatedRPO(s.lastSyncAck)
	evidence := api.ForcePromoteEvidence{
		TenantID:            req.TenantID,
		RepositoryID:        req.RepositoryID,
		PreviousTerm:        previousTerm,
		ResultingTerm:       resultingTerm,
		TargetNode:          req.TargetNode,
		EstimatedRPOSeconds: rpo,
		ActorID:             req.ActorID,
		PolicyDecisionID:    req.PolicyDecisionID,
	}
	if c.bus != nil {
		_ = c.bus.Publish(ctx, audit.ForcePromote{
			TenantID:            req.TenantID,
			RepositoryID:        req.RepositoryID,
			PreviousTerm:        previousTerm,
			ResultingTerm:       resultingTerm,
			TargetNode:          req.TargetNode,
			EstimatedRPOSeconds: rpo,
			ActorID:             req.ActorID,
			PolicyDecisionID:    req.PolicyDecisionID,
			OccurredAt:          time.Now(),
		})
	}
	return api.ForcePromoteResult{
		Promoted:            true,
		PreviousTerm:        previousTerm,
		ResultingTerm:       resultingTerm,
		EstimatedRPOSeconds: rpo,
		AuditEvidence:       evidence,
	}, nil
}

// estimatedRPO bounds the recovery-point estimate for a force-promoted async replica. It is the age
// of the last in-sync acknowledgement (rounded up to at least one second as a conservative lower
// bound), or a large sentinel when there never was one — never an implicit zero-data-loss claim.
func estimatedRPO(lastSyncAck time.Time) uint32 {
	if lastSyncAck.IsZero() {
		return 1 << 30
	}
	delta := uint64(time.Since(lastSyncAck) / time.Second)
	if delta < 1 {
		return 1
	}
	if delta > 1<<30 {
		return 1 << 30
	}
	return uint32(delta)
}
