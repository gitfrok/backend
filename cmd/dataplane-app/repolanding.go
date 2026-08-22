package main

import (
	"context"

	"github.com/gitfrok/backend/modules/codereview"
	repoapi "github.com/gitfrok/backend/modules/repository/api"
)

// repoLandingSource adapts the Repository context's settings port onto Code
// Review's landing-policy reader (SPEC-0065 AC7). The strategy is read at
// merge time from the record — a server-side fact, never a caller field — and
// the read runs under the merging actor's own verified context, exactly like
// every other repository read that actor triggers.
type repoLandingSource struct {
	settings repoapi.Settings
}

// LandingFor reports the policy as the record holds it. A repository with no
// explicit strategy AND no trunk mode reports found=false: that is the legacy
// landing by decision (SPEC-0065 AC1), not a default guess. An unreadable
// record is an error, and the merge refuses rather than guessing a shape.
func (s repoLandingSource) LandingFor(ctx context.Context, tenantID, actorID string, roles []string, repoID string) (string, bool, bool, error) {
	view, err := s.settings.GetSettings(ctx, repoapi.SettingsQuery{
		TenantID: tenantID, RepoID: repoID, ActorID: actorID, ActorRoles: roles,
	})
	if err != nil {
		return "", false, false, err
	}
	if view.MergeStrategy == "" && !view.TrunkBased {
		return "", false, false, nil
	}
	return view.MergeStrategy, view.TrunkBased, true, nil
}

var _ codereview.LandingPolicySource = repoLandingSource{}
