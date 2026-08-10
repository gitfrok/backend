// Package audit carries security-relevant events to whatever will eventually persist them.
//
// SPEC-0001 AC3 requires a cross-tenant write attempt to be *audited*, not merely rejected: a
// rejection tells the attacker they failed, an audit event tells us they tried.
//
// SCOPE, stated plainly because it is easy to over-read what this package does. It emits onto the
// in-process bus (T-0008). It does not persist anything, does not hash-chain, and provides no
// tamper-evidence — that is T-0006 (ADR-0007), which also owns adding `AuditEvent` to
// `governance/contracts/events`. Until that lands there is no subscriber, so today these events are
// published and dropped. That is deliberate: the emission point is the part that must live at the
// place the violation is detected, and retrofitting it later means auditing the code paths again.
package audit

import "time"

// ActionCIDispatch is the `action` value for a CI job accepted for dispatch (SPEC-0020 AC7).
const ActionCIDispatch = "ci.dispatch"

// ActionCITerminal is the `action` value for a CI job reaching a terminal outcome (SPEC-0020 AC7).
const ActionCITerminal = "ci.terminal"

// CIDispatch records that a queued job was claimed and dispatched to a sandbox.
// It carries no source bytes, raw logs, runner capabilities, Kubernetes names, or
// authorization results (SPEC-0020 AC7, G9).
type CIDispatch struct {
	TenantID            string
	ActorID             string
	RepositoryID        string
	JobID               string
	AttemptID           string
	CommitSHA           string
	ConfigurationDigest string
	PolicyDecisionID    string
	OccurredAt          time.Time
}

func (CIDispatch) EventName() string { return EventAudit }
func (e CIDispatch) Action() string  { return ActionCIDispatch }
func (e CIDispatch) Tenant() string  { return e.TenantID }

// CITerminal records a CI job's terminal outcome after sandbox cleanup confirmation.
// It carries no raw log, source, secret, source capability, Kubernetes node detail, or
// authorization result (SPEC-0020 AC7).
type CITerminal struct {
	TenantID       string
	ActorID        string
	RepositoryID   string
	JobID          string
	AttemptID      string
	TerminalState  string
	OutcomeSummary string
	OccuredAt      time.Time
}

func (CITerminal) EventName() string { return EventAudit }
func (e CITerminal) Action() string  { return ActionCITerminal }
func (e CITerminal) Tenant() string  { return e.TenantID }
