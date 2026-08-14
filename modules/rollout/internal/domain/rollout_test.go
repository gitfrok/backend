package domain

import (
	"testing"
	"time"

	"github.com/gitfrok/backend/modules/rollout/api"
)

func TestDeriveStatusTerminalNeverStale(t *testing.T) {
	now := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	for _, phase := range []api.RolloutPhase{api.PhaseApplied, api.PhaseRolledBack} {
		r := api.Rollout{Phase: phase, StartedAt: now.Add(-72 * time.Hour)}
		st := DeriveStatus(r, now, 5*time.Minute)
		if st.Phase != phase || st.Stale {
			t.Fatalf("terminal phase %s must read as itself and never stale, got %+v", phase, st)
		}
	}
}

func TestDeriveStatusSilentRolloutGoesStale(t *testing.T) {
	now := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	staleAfter := 5 * time.Minute

	// A rollout that began but never received a report is in-progress while contact is fresh.
	fresh := api.Rollout{Phase: api.PhaseInProgress, StartedAt: now.Add(-1 * time.Minute)}
	if st := DeriveStatus(fresh, now, staleAfter); st.Stale || st.Phase != api.PhaseInProgress {
		t.Fatalf("a freshly-started rollout reads in-progress, got %+v", st)
	}

	// Once the silence outlasts the window it is stale — never applied, never upgraded.
	silent := api.Rollout{Phase: api.PhaseInProgress, StartedAt: now.Add(-10 * time.Minute)}
	st := DeriveStatus(silent, now, staleAfter)
	if !st.Stale {
		t.Fatal("a rollout silent since it began must read stale")
	}
	if st.Phase == api.PhaseApplied {
		t.Fatal("a silent data plane must NEVER read as upgraded/applied")
	}
}

func TestDeriveStatusReportResetsContact(t *testing.T) {
	now := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	staleAfter := 5 * time.Minute

	// Started long ago but reported recently: contact is the report, so still in-progress.
	r := api.Rollout{
		Phase:          api.PhaseInProgress,
		StartedAt:      now.Add(-1 * time.Hour),
		LastReportedAt: now.Add(-1 * time.Minute),
	}
	if st := DeriveStatus(r, now, staleAfter); st.Stale {
		t.Fatalf("a recent report must keep the rollout in-progress, got %+v", st)
	}

	// The same rollout after the report ages out goes stale again.
	r.LastReportedAt = now.Add(-6 * time.Minute)
	if st := DeriveStatus(r, now, staleAfter); !st.Stale {
		t.Fatal("a rollout whose last report aged out must read stale")
	}
}
