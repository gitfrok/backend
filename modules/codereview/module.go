// Package codereview is the Code Review context's composition root (SPEC-0019).
//
// It assembles the merge-request service from its ports and returns the api/
// surface. The ref move at the end of a merge is a port to Repository/Git, which
// is what keeps this context out of Git storage.
package codereview

import (
	"net/http"

	gitv1 "github.com/gitfrok/backend/gen/proto/git/v1"
	"github.com/gitfrok/backend/modules/codereview/api"
	"github.com/gitfrok/backend/modules/codereview/internal/adapters/github"
	"github.com/gitfrok/backend/modules/codereview/internal/adapters/gitwire"
	codereviewgrpc "github.com/gitfrok/backend/modules/codereview/internal/adapters/grpc"
	"github.com/gitfrok/backend/modules/codereview/internal/app"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
	"github.com/gitfrok/backend/platform/bus"
)

// RefMover is Repository/Git's boundary for moving a ref on behalf of an
// authorized merge, aliased so cmd/ can supply one without naming a package
// under this module's internal/ tree.
type RefMover = app.RefMover

// GitImporter is Repository/Git's boundary for the import git phase, aliased
// so cmd/ can supply one without naming a package under this module's
// internal/ tree.
type GitImporter = app.GitImporter

// HistoryImporter imports review history as ATTESTED_IMPORT records, aliased
// so cmd/ can supply one.
type HistoryImporter = app.HistoryImporter

// New builds the Code Review context on the dev/in-memory store and subscribes it
// to ref updates, so each open merge request's view of its target ref stays
// current without this context reading Git state.
func New(refs RefMover, pdp policyapi.DecisionPoint, events bus.Bus) api.MergeRequests {
	service := app.New(app.NewMemoryStore(), refs, pdp, events)
	service.SubscribeRefUpdates(events)
	return service
}

// NewGRPCServer wraps the in-process merge-request surface in its gRPC adapter,
// ready to register on the plane binary's gRPC server.
func NewGRPCServer(requests api.MergeRequests) *codereviewgrpc.Server {
	return codereviewgrpc.NewServer(requests)
}

// NewRefMover builds the ref-move port on the published GitStorage contract. It
// is the only way this context reaches Git.
func NewRefMover(client gitv1.GitStorageClient) RefMover {
	return gitwire.NewRefMover(client)
}

// NewGitImporter builds the import git-phase port on the published GitStorage
// contract.
func NewGitImporter(client gitv1.GitStorageClient) GitImporter {
	return gitwire.NewGitImporter(client)
}

// NewGithubHistoryImporter builds the history-phase port on the GitHub API,
// storing imported records in the in-memory record store. httpClient may be
// nil for the default client.
func NewGithubHistoryImporter(httpClient *http.Client) HistoryImporter {
	return github.New(app.NewMemoryRecordStore(), httpClient)
}

// NewImportService builds the import service on the dev in-memory stores.
// history may be nil when the history phase is not wired; the git phase is
// required.
func NewImportService(git GitImporter, history HistoryImporter, pdp policyapi.DecisionPoint, events bus.Bus) api.ImportService {
	return app.NewImportService(app.NewMemoryImportStore(), app.NewMemoryRecordStore(), git, history, pdp, events)
}

// NewImportGRPCServer wraps the in-process import surface in its gRPC adapter.
func NewImportGRPCServer(imports api.ImportService) *codereviewgrpc.ImportServer {
	return codereviewgrpc.NewImportServer(imports)
}
