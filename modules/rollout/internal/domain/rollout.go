package domain

import (
	"time"

	"github.com/gitfrok/backend/modules/rollout/api"
)

// DeriveStatus is the AC6 derivation: the phase a rollout reads as at now, plus whether a
// silent data plane makes it stale. The rules, in the order they bind:
//
//   - A terminal rollout (applied or rolled back) is what it is; a finished rollout does not
//     go stale, because its outcome was reported and recorded.
//   - A non-terminal rollout needs CONTACT to read as in-progress. Contact is the data plane's
//     most recent report, or — if it has not reported since the rollout began — the rollout's
//     own start. If that contact is older than staleAfter, the rollout reads STALE.
//
// The load-bearing half of AC6 is the one this function shares with the app layer: nothing here
// ever manufactures APPLIED. Only a reported convergence moves a rollout to applied, so a data
// plane that went silent mid-rollout can never be read as "upgraded" — at best it reads
// in-progress while contact is fresh, then stale.
func DeriveStatus(r api.Rollout, now time.Time, staleAfter time.Duration) api.RolloutStatus {
	if r.Phase.Terminal() {
		return api.RolloutStatus{Phase: r.Phase, Stale: false}
	}
	contact := r.StartedAt
	if r.ReportedSinceStart() {
		contact = r.LastReportedAt
	}
	stale := now.After(contact.Add(staleAfter))
	return api.RolloutStatus{Phase: r.Phase, Stale: stale}
}
