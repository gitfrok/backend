// Package codereview is the Code Review context's composition root (SPEC-0019).
//
// It assembles the merge-request service from its ports and returns the api/
// surface. The ref move at the end of a merge is a port to Repository/Git, which
// is what keeps this context out of Git storage.
package codereview

import (
	"net/http"
	"time"

	gitv1 "github.com/gitfrok/backend/gen/proto/git/v1"
	"github.com/gitfrok/backend/modules/codereview/api"
	"github.com/gitfrok/backend/modules/codereview/internal/adapters/github"
	"github.com/gitfrok/backend/modules/codereview/internal/adapters/gitlab"
	"github.com/gitfrok/backend/modules/codereview/internal/adapters/gitwire"
	codereviewgrpc "github.com/gitfrok/backend/modules/codereview/internal/adapters/grpc"
	crpg "github.com/gitfrok/backend/modules/codereview/internal/adapters/postgres"
	"github.com/gitfrok/backend/modules/codereview/internal/app"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
	"github.com/gitfrok/backend/platform/bus"
	"github.com/gitfrok/backend/platform/db"
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

// ImportRefsCommand, RefUpdate and ImportHistoryCommand are the import ports'
// argument types, aliased for the same reason.
type (
	ImportRefsCommand    = app.ImportRefsCommand
	RefUpdate            = app.RefUpdate
	ImportHistoryCommand = app.ImportHistoryCommand
	HistoryResult        = app.HistoryResult
	GitResult            = app.GitResult
)

// StorageMeter is where imported bytes are attributed against a tenant's
// fair-use storage dimension (SPEC-0011 AC9/AC21), aliased so a composition root
// can supply one. No plane wires one yet: fair-use metering is its own unbuilt
// requirement (PRD PR-23), and this module measures rather than accounts.
type StorageMeter = app.StorageMeter

// Pacer throttles import work (SPEC-0011 AC21), aliased so cmd/ can supply one.
type Pacer = app.Pacer

// NewImportPacer returns the import throttle: one step of import work per
// interval. A non-positive interval paces nothing, which is what an environment
// that has not configured pacing gets.
func NewImportPacer(interval time.Duration) Pacer {
	return app.NewIntervalPacer(interval)
}

// New builds the Code Review context on the dev/in-memory store and subscribes it
// to ref updates, so each open merge request's view of its target ref stays
// current without this context reading Git state.
func New(refs RefMover, pdp policyapi.DecisionPoint, events bus.Bus) api.MergeRequests {
	service := app.New(app.NewMemoryStore(), refs, pdp, events)
	service.SubscribeRefUpdates(events)
	return service
}

// NewPostgres assembles the Code Review context on the durable store (T-0078, SPEC-0061, ADR-0080).
// This is the constructor a plane binary calls when it has a pool.
//
// The difference from New is not a detail. On the in-memory store, every merge request, review,
// branch-protection rule and external issue reference empties when the process does — and what
// empties is who approved what, at which revision, against which rule. The audit trail keeps the
// approval act (SPEC-0019 AC6); the merge request that gives it meaning did not survive a deploy.
func NewPostgres(pool *db.Pool, refs RefMover, pdp policyapi.DecisionPoint, events bus.Bus) api.MergeRequests {
	service := app.New(crpg.New(pool), refs, pdp, events)
	service.SubscribeRefUpdates(events)
	return service
}

// AttachFindingsFacts wires the findings-facts provider the security merge
// gate assembles its input from (T-0025, SPEC-0029, SPEC-0030). It is a
// post-construction step because the provider exists only once the
// composition root has composed Security/Findings alongside Code Review,
// while this context is composed before it; a merge surface with no provider
// leaves the security gate disengaged rather than engaged on nothing. It
// reports false when the surface has no merge gate to attach to.
func AttachFindingsFacts(requests api.MergeRequests, provider api.FindingsFactsProvider) bool {
	type factsSink interface {
		SetFindingsFacts(api.FindingsFactsProvider)
	}
	sink, ok := requests.(factsSink)
	if !ok {
		return false
	}
	sink.SetFindingsFacts(provider)
	return true
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

// NewImportRecordStore returns the imported-record store. One store is shared
// by the history importers that write records and the import service that
// revokes them: a revoke that tombstoned a different store would leave the
// imported history readable (SPEC-0011 AC17).
func NewImportRecordStore() api.ImportedRecordStore {
	return app.NewMemoryRecordStore()
}

// NewGithubHistoryImporter builds the history-phase port on the GitHub API,
// storing imported records in the given store. httpClient may be nil for the
// default client.
func NewGithubHistoryImporter(records api.ImportedRecordStore, httpClient *http.Client, pacer Pacer) HistoryImporter {
	return github.New(records, httpClient).WithPacer(pacer)
}

// NewGitlabHistoryImporter builds the history-phase port on the GitLab API,
// storing imported records in the given store.
func NewGitlabHistoryImporter(records api.ImportedRecordStore, httpClient *http.Client, pacer Pacer) HistoryImporter {
	return gitlab.New(records, httpClient).WithPacer(pacer)
}

// NewSourceHistoryImporter returns a HistoryImporter that selects the source
// adapter by the import's source_system ("github" or "gitlab"). Unknown
// systems are refused rather than silently imported by the wrong adapter.
// pacer paces both adapters' source calls, so a plane's import throughput is one
// budget rather than one per source system.
func NewSourceHistoryImporter(records api.ImportedRecordStore, httpClient *http.Client, pacer Pacer) HistoryImporter {
	return app.NewSourceHistoryImporter(map[string]app.HistoryImporter{
		"github": github.New(records, httpClient).WithPacer(pacer),
		"gitlab": gitlab.New(records, httpClient).WithPacer(pacer),
	})
}

// NewImportService builds the import service on the dev in-memory import store.
// records must be the same store the history importer writes to. history may be
// nil when the history phase is not wired; the git phase is required.
func NewImportService(records api.ImportedRecordStore, git GitImporter, history HistoryImporter, pdp policyapi.DecisionPoint, events bus.Bus, pacer Pacer) api.ImportService {
	return app.NewImportService(app.NewMemoryImportStore(), records, git, history, pdp, events).WithPacer(pacer)
}

// NewImportGRPCServer wraps the in-process import surface in its gRPC adapter.
func NewImportGRPCServer(imports api.ImportService) *codereviewgrpc.ImportServer {
	return codereviewgrpc.NewImportServer(imports)
}
