package grpc

import (
	"context"
	"time"

	repositoryv1 "github.com/gitfrok/backend/gen/proto/repository/v1"
	"github.com/gitfrok/backend/modules/repository/api"
	"github.com/gitfrok/backend/platform/tenancy"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// SettingsServer is the gRPC adapter for the Settings port (T-0068, SPEC-0057, ADR-0076).
//
// It carries verified identity and shapes only. A caller cannot assert a visibility, a member, a
// role, a branch protection or an approval requirement — not because this adapter drops them, but
// because no message in the contract has a field for one, asserted against the compiled descriptor
// by check-contracts' check 16.
type SettingsServer struct {
	repositoryv1.UnimplementedRepositorySettingsServer
	settings api.Settings
}

// NewSettingsServer builds the adapter over the module's port.
func NewSettingsServer(s api.Settings) *SettingsServer { return &SettingsServer{settings: s} }

// invalidName is the one refusal that is not coarse.
//
// Every other failure on this surface collapses into denial(): whether the repository exists, whether
// the caller may administer it, and whether the store was reachable are all indistinguishable, which
// is what stops the error from being a probe. A rename to nothing is different in kind — it is about
// the field the caller just sent, which the caller already knows, so naming it discloses nothing and
// saves a person from a form that fails for no stated reason.
func invalidName() error {
	return status.Error(codes.InvalidArgument, "repository: a name is required")
}

// GetSettings serves one repository's settings.
func (s *SettingsServer) GetSettings(ctx context.Context, req *repositoryv1.GetSettingsRequest) (*repositoryv1.GetSettingsResponse, error) {
	rc := req.GetContext()
	if !verified(rc) {
		return nil, denial()
	}
	ctx = tenancy.WithTenant(ctx, tenancy.ID(rc.GetTenantId()))
	view, err := s.settings.GetSettings(ctx, api.SettingsQuery{
		TenantID:   rc.GetTenantId(),
		RepoID:     rc.GetRepositoryId(),
		ActorID:    rc.GetActorId(),
		ActorRoles: rc.GetActorRoles(),
	})
	if err != nil {
		return nil, denial()
	}
	return &repositoryv1.GetSettingsResponse{Settings: settingsMessage(view)}, nil
}

// UpdateSettings changes the name and the description.
func (s *SettingsServer) UpdateSettings(ctx context.Context, req *repositoryv1.UpdateSettingsRequest) (*repositoryv1.UpdateSettingsResponse, error) {
	rc := req.GetContext()
	if !verified(rc) {
		return nil, denial()
	}
	if req.GetName() == "" {
		return nil, invalidName()
	}
	ctx = tenancy.WithTenant(ctx, tenancy.ID(rc.GetTenantId()))
	view, err := s.settings.UpdateSettings(ctx, api.SettingsUpdate{
		TenantID:   rc.GetTenantId(),
		RepoID:     rc.GetRepositoryId(),
		ActorID:    rc.GetActorId(),
		ActorRoles: rc.GetActorRoles(),
		Name:       req.GetName(),
		// The actor is the verified caller from the context, never a field: an actor field would
		// be an unauthenticated authorship claim, the same reason ReleaseContext has no
		// publisher (SPEC-0056).
		Description: req.GetDescription(),
	})
	if err != nil {
		return nil, denial()
	}
	return &repositoryv1.UpdateSettingsResponse{Settings: settingsMessage(view)}, nil
}

// SetArchived sets or clears the archived label.
//
// It returns the settings as they now are, including for a caller that asked for the state the
// repository was already in — that call is accepted, writes nothing and is not an error
// (SPEC-0057 AC3).
func (s *SettingsServer) SetArchived(ctx context.Context, req *repositoryv1.SetArchivedRequest) (*repositoryv1.SetArchivedResponse, error) {
	rc := req.GetContext()
	if !verified(rc) {
		return nil, denial()
	}
	ctx = tenancy.WithTenant(ctx, tenancy.ID(rc.GetTenantId()))
	view, err := s.settings.SetArchived(ctx, api.ArchiveRequest{
		TenantID:   rc.GetTenantId(),
		RepoID:     rc.GetRepositoryId(),
		ActorID:    rc.GetActorId(),
		ActorRoles: rc.GetActorRoles(),
		Archived:   req.GetArchived(),
	})
	if err != nil {
		return nil, denial()
	}
	return &repositoryv1.SetArchivedResponse{Settings: settingsMessage(view)}, nil
}

// verified reports whether the read context names a tenant, a repository and an actor. All three come
// from the session; none is optional, because a settings call without one of them is not a call this
// surface can authorize.
func verified(rc *repositoryv1.ReadContext) bool {
	return rc != nil && rc.GetTenantId() != "" && rc.GetRepositoryId() != "" && rc.GetActorId() != ""
}

// settingsMessage shapes the view onto the contract.
//
// Absent instants travel as the empty string rather than as a zero timestamp: a repository that was
// never archived has no archival instant, and rendering one would make every unarchived repository
// claim a date. The consumer distinguishes them by emptiness, which is what the contract's comment
// says it does.
func settingsMessage(v api.SettingsView) *repositoryv1.Settings {
	return &repositoryv1.Settings{
		RepositoryId:      v.RepoID,
		Name:              v.Name,
		Description:       v.Description,
		ArchivedAt:        rfc3339OrEmpty(v.ArchivedAt),
		SettingsUpdatedAt: rfc3339OrEmpty(v.SettingsUpdatedAt),
		SettingsUpdatedBy: v.SettingsUpdatedBy,
		MergeStrategy:     strategyProto(v.MergeStrategy),
		TrunkBased:        v.TrunkBased,
	}
}

// strategyProto maps the domain's landing vocabulary onto the wire enum. The
// empty string is the absence of an explicit choice, so it maps to
// UNSPECIFIED — which is exactly what UNSPECIFIED means on this field.
func strategyProto(strategy string) repositoryv1.MergeStrategy {
	switch strategy {
	case "merge_commit":
		return repositoryv1.MergeStrategy_MERGE_STRATEGY_MERGE_COMMIT
	case "squash":
		return repositoryv1.MergeStrategy_MERGE_STRATEGY_SQUASH
	case "rebase":
		return repositoryv1.MergeStrategy_MERGE_STRATEGY_REBASE
	default:
		return repositoryv1.MergeStrategy_MERGE_STRATEGY_UNSPECIFIED
	}
}

// strategyDomain maps the wire enum back onto the domain vocabulary.
func strategyDomain(strategy repositoryv1.MergeStrategy) string {
	switch strategy {
	case repositoryv1.MergeStrategy_MERGE_STRATEGY_MERGE_COMMIT:
		return "merge_commit"
	case repositoryv1.MergeStrategy_MERGE_STRATEGY_SQUASH:
		return "squash"
	case repositoryv1.MergeStrategy_MERGE_STRATEGY_REBASE:
		return "rebase"
	default:
		return ""
	}
}

// SetLandingPolicy states the landing policy whole (SPEC-0065, ADR-0088).
// An unknown strategy is refused by name — like invalidName, it is about the
// field the caller just sent — and every other failure is the one coarse
// denial.
func (s *SettingsServer) SetLandingPolicy(ctx context.Context, req *repositoryv1.SetLandingPolicyRequest) (*repositoryv1.SetLandingPolicyResponse, error) {
	rc := req.GetContext()
	if !verified(rc) {
		return nil, denial()
	}
	ctx = tenancy.WithTenant(ctx, tenancy.ID(rc.GetTenantId()))
	view, err := s.settings.SetLanding(ctx, api.LandingRequest{
		TenantID:   rc.GetTenantId(),
		RepoID:     rc.GetRepositoryId(),
		ActorID:    rc.GetActorId(),
		ActorRoles: rc.GetActorRoles(),
		Strategy:   strategyDomain(req.GetStrategy()),
		TrunkBased: req.GetTrunkBased(),
	})
	if err != nil {
		return nil, denial()
	}
	return &repositoryv1.SetLandingPolicyResponse{Settings: settingsMessage(view)}, nil
}

// rfc3339OrEmpty renders an instant, or nothing at all when there is no instant to render.
func rfc3339OrEmpty(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
