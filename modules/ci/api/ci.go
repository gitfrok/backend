// Package api is the CI/CD context's in-process surface. It deliberately
// exposes jobs and lifecycle commands, never Kubernetes objects, source bytes,
// credentials, or queue records (SPEC-0020).
package api

import (
	"context"
	"errors"
	"time"
)

// ErrDenied is the coarse refusal returned by CI operations. It intentionally
// does not distinguish non-existent state from cross-tenant access (SPEC-0020 AC6).
var ErrDenied = errors.New("ci: job unavailable")

type TriggerKind string

const (
	TriggerRefUpdated TriggerKind = "REF_UPDATED"
	TriggerManual     TriggerKind = "MANUAL"
)

type JobState string

const (
	JobQueued    JobState = "QUEUED"
	JobRunning   JobState = "RUNNING"
	JobSucceeded JobState = "SUCCEEDED"
	JobFailed    JobState = "FAILED"
	JobCancelled JobState = "CANCELLED"
)

// Context holds only the verified identity inputs to the CI PEP.
type Context struct {
	TenantID, RepositoryID, ActorID, RequestID string
	ActorRoles                                 []string
}

// EnqueueRequest identifies immutable source. SourceEventID deduplicates
// RefUpdated delivery; manual requests use RequestID instead.
type EnqueueRequest struct {
	Context
	Ref, CommitSHA, SourceEventID string
	Trigger                       TriggerKind
}

// DelayCauseEnvelopeThrottle is the cause a job carries when it waited in the
// queue while the fair-use claim gate held dispatch at the published cap
// (SPEC-0041 AC5, T-0035): queued jobs are delayed, never dropped, and the
// delay is visible as a cause on the job. It is the only delay cause in this
// vocabulary — nothing else dispatch refuses for, and git is never one of
// them (AC7).
const DelayCauseEnvelopeThrottle = "ENVELOPE_THROTTLE"

// Job is the bounded public lifecycle view. Attempt capabilities, pod names,
// node details, raw output, and source bytes are CI implementation details.
type Job struct {
	ID, AttemptID, TenantID, RepositoryID, ActorID string
	Ref, CommitSHA                                 string
	Trigger                                        TriggerKind
	ActorRoles                                     []string
	State                                          JobState
	QueuedAt                                       time.Time
	StartedAt, FinishedAt                          *time.Time
	ConfigurationDigest, OutcomeSummary            string
	// DelayCause names why this job waited in the queue before dispatch; it
	// is empty when the job dispatched without a throttle delay (SPEC-0041
	// AC5).
	DelayCause string
}

type Jobs interface {
	Enqueue(context.Context, EnqueueRequest) (Job, error)
	Get(context.Context, Context, string) (Job, error)
	Cancel(context.Context, Context, string) (Job, error)
}
