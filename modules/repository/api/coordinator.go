package api

import (
	"context"
	"time"
)

// This file declares the Repository context's in-process port for replica coordination
// (SPEC-0018, ADR-0042). The Git write path depends on this interface only — never on an internal/
// implementation, and never on a coordination substrate. The contract lives in
// governance/contracts/proto/replica/v1/replica.proto; this port is its in-process mirror.
//
// All state carried here is opaque identifier + term + bounded outcome. No filesystem path,
// credential, Git payload, agent-stream field, or caller authorization assertion is representable
// (SPEC-0018 AC6, ADR-0042 §5).

// ShardState is the coarse availability of one repository shard's replica set (ADR-0042 §1).
type ShardState int

const (
	ShardStateUnspecified      ShardState = 0
	ShardStateHealthy          ShardState = 1 // primary + sync replica up; a write-ready primary may serve pushes
	ShardStateDegradedReadOnly ShardState = 2 // confirmed primary + sync loss; no writes, no stale auto-promote
	ShardStateRecovering       ShardState = 3 // post-promotion fence in progress; not yet write-ready
)

// DenyReason is the bounded vocabulary of coordination refusals. It cannot encode a path,
// credential, Git payload, or an authorization result.
type DenyReason int

const (
	DenyReasonUnspecified   DenyReason = 0
	DenyReasonStaleTerm     DenyReason = 1 // offered term is below the current fencing term
	DenyReasonNotPrimary    DenyReason = 2 // caller is not the primary for the current term
	DenyReasonNotWriteReady DenyReason = 3 // fence for the current term is not yet acknowledged
	DenyReasonUnknownShard  DenyReason = 4 // no shard record exists
	DenyReasonNotHealthy    DenyReason = 5 // CAS preconditions not met (state not promotable)
)

// ShardRecord is the read-only coordination view of one repository shard. It is the only
// coordination state a writer consults; writers never read Repository/Git storage via the coordinator.
type ShardRecord struct {
	TenantID          string
	RepositoryID      string
	PrimaryNode       string // opaque node identifier
	SyncReplica       string // opaque in-sync replica identifier
	MembershipVersion uint32 // increments when the replica set changes
	FencingTerm       uint64 // unsigned, monotonic, strictly increasing per shard
	State             ShardState
	WriteReady        bool // true only after the current term's fence is acknowledged
}

// BindLease is the outcome of leasing the write-route for one receive-pack operation.
type BindLease struct {
	Granted     bool
	Term        uint64 // the term the lease is for, when granted
	DenyReason  DenyReason
	CurrentTerm uint64 // current fencing term, for retries (meaningful when !Granted)
}

// AckQuorum reports durable-ack progress for one operation under one term. The router
// acknowledges its Git caller only once both flags are true under the same term (ADR-0016,
// SPEC-0018 AC1).
type AckQuorum struct {
	PrimaryAcked bool
	SyncAcked    bool
}

// PromotedShard is the outcome of an automated promotion.
type PromotedShard struct {
	Promoted   bool
	DenyReason DenyReason // meaningful only when !Promoted; the record is unchanged
	Term       uint64     // new fencing term
	WriteReady bool       // true once the fence for the new term is acknowledged
}

// ForcePromoteRequest is the audited operator override input. It carries no caller-provided
// allow assertion (ADR-0046 §2); the PDP decision ID is audit context only.
type ForcePromoteRequest struct {
	TenantID         string
	RepositoryID     string
	TargetNode       string // operator-selected async replica
	PolicyDecisionID string
	ActorID          string // verified platform-operator principal
}

// ForcePromoteResult is the outcome of a force-promote. The bounded evidence is returned as plain
// data so the caller — or the in-memory adapter on behalf of the coordinator — can emit exactly one
// immutable replica.force_promote audit event (SPEC-0018 AC5).
type ForcePromoteResult struct {
	Promoted            bool
	DenyReason          DenyReason
	PreviousTerm        uint64
	ResultingTerm       uint64
	EstimatedRPOSeconds uint32
	AuditEvidence       ForcePromoteEvidence
}

// ForcePromoteEvidence is the bounded audit vocabulary for replica.force_promote.
type ForcePromoteEvidence struct {
	TenantID            string
	RepositoryID        string
	PreviousTerm        uint64
	ResultingTerm       uint64
	TargetNode          string
	EstimatedRPOSeconds uint32
	ActorID             string
	PolicyDecisionID    string
}

// Coordinator is the per-shard authority over replica membership, the fencing term, the
// durable-ack quorum, and the dual-loss/failover state (SPEC-0018, ADR-0042). It is consulted by the
// Git write path before any Git subprocess starts.
type Coordinator interface {
	// GetShard returns the read-only shard record. ifTerm != 0 is a client staleness guard: a value
	// that does not match the current fencing term is refused as stale.
	GetShard(ctx context.Context, tenantID, repositoryID string, ifTerm uint64) (ShardRecord, error)

	// BindLease leases the write-route for one receive-pack operation. Granted only when the caller
	// is the write-ready primary for the current term; otherwise denied without mutating the record.
	BindLease(ctx context.Context, tenantID, repositoryID, operationID, nodeID string, term uint64) (BindLease, error)

	// AckDurable records a replica's durable acknowledgement. A stale term or a node that is
	// neither the primary nor the in-sync replica is denied without changing the record. Only the
	// primary and the in-sync replica, acking under the same term, satisfy the quorum.
	AckDurable(ctx context.Context, tenantID, repositoryID, operationID, nodeID string, term uint64) (AckQuorum, error)

	// WaitForQuorum blocks until both the primary and the in-sync replica have durably acked the
	// operation under the same term, or until ctx is done / the timeout elapses.
	WaitForQuorum(ctx context.Context, tenantID, repositoryID, operationID string, term uint64, timeout time.Duration) error

	// PromoteReplica is the automated CAS promotion of the in-sync replica on primary loss
	// (ADR-0042 §3). It may only succeed from a healthy shard and increments the term; the shard is
	// not write-ready until the resulting fence is acknowledged.
	PromoteReplica(ctx context.Context, tenantID, repositoryID string) (PromotedShard, error)

	// AcknowledgeFence completes a promotion: the old primary reports it has observed the new
	// fencing term, flipping the shard to write-ready for the new term (ADR-0042 §3).
	AcknowledgeFence(ctx context.Context, tenantID, repositoryID, nodeID string, term uint64) (bool, error)

	// ForcePromote is the operator override from degraded-read-only (ADR-0042 §4, ADR-0046). It
	// carries no caller allow assertion; the PDP decision ID is audit context only.
	ForcePromote(ctx context.Context, req ForcePromoteRequest) (ForcePromoteResult, error)
}

// SeedShard records the initial membership for a shard that has no live record yet. It is a
// one-time bootstrap, not a recovery operation.
type ShardSeed struct {
	TenantID     string
	RepositoryID string
	PrimaryNode  string
	SyncReplica  string
}
