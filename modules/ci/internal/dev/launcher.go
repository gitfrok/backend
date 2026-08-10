// Package dev provides non-production adapters for local development: an
// in-memory CI queue/store and a no-op sandbox launcher that records dispatch
// attempts without contacting a cluster. Production uses the K8s adapter
// (modules/ci/internal/runner/k8s).
package dev

import (
	"context"
	"sync"

	"github.com/gitfrok/backend/modules/ci/api"
	"github.com/gitfrok/backend/modules/ci/internal/dispatcher"
)

// Launcher is a dev-only dispatcher.Launcher that records every launch and
// returns a synthetic successful attempt. It never contacts a cluster.
type Launcher struct {
	mu       sync.Mutex
	Launches []DevAttempt
	FailNext bool
}

type DevAttempt struct {
	JobID        string
	AttemptID    string
	CommitSHA    string
	ConfigDigest string
	Config       dispatcher.Config
}

func (l *Launcher) Launch(_ context.Context, job api.Job, cfg dispatcher.Config) (dispatcher.Attempt, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.Launches = append(l.Launches, DevAttempt{JobID: job.ID, AttemptID: job.AttemptID, CommitSHA: job.CommitSHA, ConfigDigest: job.ConfigurationDigest, Config: cfg})
	if l.FailNext {
		l.FailNext = false
		return nil, errLaunch
	}
	return &devAttempt{state: api.JobSucceeded, summary: "dev: ok"}, nil
}

type devAttempt struct {
	state   api.JobState
	summary string
}

func (a *devAttempt) Await(_ context.Context) (api.JobState, string, error) {
	return a.state, a.summary, nil
}

var errLaunch = errStr("dev launcher: simulated failure")

type errStr string

func (e errStr) Error() string { return string(e) }
