package api

import "time"

const (
	EventJobQueued   = "gitsaas.events.ci.v1.CIJobQueued"
	EventJobStarted  = "gitsaas.events.ci.v1.CIJobStarted"
	EventJobFinished = "gitsaas.events.ci.v1.CIJobFinished"
)

type CIJobQueued struct {
	EventID, JobID, TenantID, RepositoryID string
	Ref, CommitSHA, ConfigurationDigest    string
	OccurredAt                             time.Time
}

func (CIJobQueued) EventName() string { return EventJobQueued }
func (e CIJobQueued) Tenant() string  { return e.TenantID }

type CIJobStarted struct {
	EventID, JobID, AttemptID, TenantID, RepositoryID string
	OccurredAt                                        time.Time
}

func (CIJobStarted) EventName() string { return EventJobStarted }
func (e CIJobStarted) Tenant() string  { return e.TenantID }

type CIJobFinished struct {
	EventID, JobID, AttemptID, TenantID, RepositoryID string
	TerminalState                                     JobState
	OutcomeSummary                                    string
	OccurredAt                                        time.Time
}

func (CIJobFinished) EventName() string { return EventJobFinished }
func (e CIJobFinished) Tenant() string  { return e.TenantID }
