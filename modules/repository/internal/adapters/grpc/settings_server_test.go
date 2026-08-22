package grpc_test

import (
	"context"
	"errors"
	"testing"
	"time"

	repositoryv1 "github.com/gitfrok/backend/gen/proto/repository/v1"
	"github.com/gitfrok/backend/modules/repository/api"
	repogrpc "github.com/gitfrok/backend/modules/repository/internal/adapters/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// SPEC-0057 AC1/AC5 at the adapter, plus AC11's absence checked from the descriptor side: the shapes
// this surface can express are the accepted increment and nothing else.

type fakeSettings struct {
	view    api.SettingsView
	err     error
	gotQ    api.SettingsQuery
	gotU    api.SettingsUpdate
	gotA    api.ArchiveRequest
	gotL    api.LandingRequest
	archive int
}

func (f *fakeSettings) GetSettings(_ context.Context, q api.SettingsQuery) (api.SettingsView, error) {
	f.gotQ = q
	return f.view, f.err
}

func (f *fakeSettings) UpdateSettings(_ context.Context, u api.SettingsUpdate) (api.SettingsView, error) {
	f.gotU = u
	return f.view, f.err
}

func (f *fakeSettings) SetArchived(_ context.Context, a api.ArchiveRequest) (api.SettingsView, error) {
	f.gotA = a
	f.archive++
	return f.view, f.err
}

func (f *fakeSettings) SetLanding(_ context.Context, l api.LandingRequest) (api.SettingsView, error) {
	f.gotL = l
	return f.view, f.err
}

func readCtx(tenant, repoID, actor string) *repositoryv1.ReadContext {
	return &repositoryv1.ReadContext{
		TenantId: tenant, RepositoryId: repoID, ActorId: actor,
		RequestId: "req-1", ActorRoles: []string{"owner"},
	}
}

func TestGetSettingsForwardsTheVerifiedContext(t *testing.T) {
	at := time.Date(2026, 8, 19, 9, 30, 0, 0, time.UTC)
	settings := &fakeSettings{view: api.SettingsView{
		TenantID: "t-1", RepoID: "alpha", Name: "Alpha", Description: "the cluster",
		ArchivedAt: at, SettingsUpdatedAt: at, SettingsUpdatedBy: "user-9",
	}}
	srv := repogrpc.NewSettingsServer(settings)

	got, err := srv.GetSettings(context.Background(), &repositoryv1.GetSettingsRequest{
		Context: readCtx("t-1", "alpha", "actor-1"),
	})
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	if settings.gotQ.TenantID != "t-1" || settings.gotQ.RepoID != "alpha" || settings.gotQ.ActorID != "actor-1" {
		t.Errorf("the port did not receive the verified context: %+v", settings.gotQ)
	}
	if got.GetSettings().GetName() != "Alpha" || got.GetSettings().GetDescription() != "the cluster" {
		t.Errorf("unexpected response %v", got)
	}
	if got.GetSettings().GetArchivedAt() != at.Format(time.RFC3339) {
		t.Errorf("archived_at not rendered: %q", got.GetSettings().GetArchivedAt())
	}
}

// An absent instant travels as the empty string, not as a zero timestamp: otherwise every repository
// nobody archived would claim a date, and the archived label is what this surface renders.
func TestAbsentInstantsTravelAsEmptyStrings(t *testing.T) {
	settings := &fakeSettings{view: api.SettingsView{TenantID: "t-1", RepoID: "alpha", Name: "Alpha"}}
	srv := repogrpc.NewSettingsServer(settings)

	got, err := srv.GetSettings(context.Background(), &repositoryv1.GetSettingsRequest{
		Context: readCtx("t-1", "alpha", "actor-1"),
	})
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	if a := got.GetSettings().GetArchivedAt(); a != "" {
		t.Errorf("an unarchived repository claims an instant: %q", a)
	}
	if u := got.GetSettings().GetSettingsUpdatedAt(); u != "" {
		t.Errorf("a repository whose settings nobody changed claims an instant: %q", u)
	}
}

// AC5: every failure is the same coarse refusal, so the error cannot be used as a probe.
func TestEveryFailureIsOneCoarseRefusal(t *testing.T) {
	for name, err := range map[string]error{
		"forbidden":  api.ErrSettingsForbidden,
		"no witness": api.ErrNoWitness,
		"no pdp":     api.ErrNoAdministrationPoint,
		"unknown":    errors.New("the store fell over"),
	} {
		srv := repogrpc.NewSettingsServer(&fakeSettings{err: err})
		_, got := srv.GetSettings(context.Background(), &repositoryv1.GetSettingsRequest{
			Context: readCtx("t-1", "alpha", "actor-1"),
		})
		st, ok := status.FromError(got)
		if !ok || st.Code() != codes.PermissionDenied {
			t.Errorf("%s: want PermissionDenied, got %v", name, got)
		}
		if st.Message() != "repository: unavailable" {
			t.Errorf("%s: the refusal names a cause: %q", name, st.Message())
		}
	}
}

// A request that does not name a tenant, a repository and an actor is refused before the port is
// reached: there is nothing to authorize.
func TestAnUnverifiedContextNeverReachesThePort(t *testing.T) {
	settings := &fakeSettings{}
	srv := repogrpc.NewSettingsServer(settings)

	for name, rc := range map[string]*repositoryv1.ReadContext{
		"no context":    nil,
		"no tenant":     readCtx("", "alpha", "actor-1"),
		"no repository": readCtx("t-1", "", "actor-1"),
		"no actor":      readCtx("t-1", "alpha", ""),
	} {
		if _, err := srv.SetArchived(context.Background(), &repositoryv1.SetArchivedRequest{
			Context: rc, Archived: true,
		}); err == nil {
			t.Errorf("%s: must be refused", name)
		}
	}
	if settings.archive != 0 {
		t.Errorf("the port was reached %d times by unverified calls", settings.archive)
	}
}

// AC2 at the adapter: a rename to nothing is the one refusal that is not coarse, because it is about
// the field the caller just sent — which the caller already knows, so naming it discloses nothing.
func TestARenameToNothingIsRefusedByTheField(t *testing.T) {
	settings := &fakeSettings{}
	srv := repogrpc.NewSettingsServer(settings)

	_, err := srv.UpdateSettings(context.Background(), &repositoryv1.UpdateSettingsRequest{
		Context: readCtx("t-1", "alpha", "actor-1"), Name: "",
	})
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.InvalidArgument {
		t.Fatalf("want InvalidArgument, got %v", err)
	}
	if settings.gotU.Name != "" || settings.gotU.RepoID != "" {
		t.Error("the port was reached with a nameless update")
	}
}

// AC3 at the adapter: asking for the state a repository is already in is accepted and returns the
// settings as they are. The adapter does not know or care whether anything changed — that is the
// aggregate's decision, and duplicating it here would be a second place idempotency is decided.
func TestSetArchivedForwardsTheStateWanted(t *testing.T) {
	settings := &fakeSettings{view: api.SettingsView{RepoID: "alpha", Name: "Alpha"}}
	srv := repogrpc.NewSettingsServer(settings)

	if _, err := srv.SetArchived(context.Background(), &repositoryv1.SetArchivedRequest{
		Context: readCtx("t-1", "alpha", "actor-1"), Archived: true,
	}); err != nil {
		t.Fatalf("SetArchived: %v", err)
	}
	if !settings.gotA.Archived || settings.gotA.RepoID != "alpha" {
		t.Errorf("the port did not receive the state wanted: %+v", settings.gotA)
	}
}

// AC11 from the consumer's side: the generated messages carry no field this increment excluded.
//
// check-contracts asserts the same thing against the compiled descriptor in governance, which is the
// gate that fails a contract change. This asserts it here, where the code that would use such a field
// lives — so a hand-edited or stale gen/ tree cannot introduce one either.
func TestTheSettingsMessagesCarryNoExcludedField(t *testing.T) {
	excluded := map[string]bool{
		"visibility": true, "public": true, "private": true,
		"member": true, "members": true, "permissions": true,
		"branch_protection": true, "protected_branch": true,
		"required_approvals": true, "approval_rule": true, "merge_rule": true,
	}
	for _, m := range []proto.Message{
		&repositoryv1.Settings{},
		&repositoryv1.GetSettingsRequest{}, &repositoryv1.GetSettingsResponse{},
		&repositoryv1.UpdateSettingsRequest{}, &repositoryv1.UpdateSettingsResponse{},
		&repositoryv1.SetArchivedRequest{}, &repositoryv1.SetArchivedResponse{},
	} {
		fields := m.ProtoReflect().Descriptor().Fields()
		for i := range fields.Len() {
			name := string(fields.Get(i).Name())
			if excluded[name] {
				t.Errorf("%s carries %q — outside ADR-0076's accepted increment",
					m.ProtoReflect().Descriptor().FullName(), name)
			}
		}
	}
}

// AC12 from the consumer's side: the service has no delete verb.
func TestTheSettingsServiceHasNoDeleteVerb(t *testing.T) {
	sd := repositoryv1.File_proto_repository_v1_repository_proto.Services().ByName("RepositorySettings")
	if sd == nil {
		t.Fatal("RepositorySettings is not in the descriptor")
	}
	methods := sd.Methods()
	for i := range methods.Len() {
		if name := methods.Get(i).Name(); len(name) >= 6 && name[:6] == "Delete" {
			t.Errorf("RepositorySettings carries %q — deletion is ADR-0076's deferred decision", name)
		}
	}
	var _ protoreflect.ServiceDescriptor = sd
}
