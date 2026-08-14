package gitwire

import (
	"context"
	"fmt"
	"slices"

	gitv1 "github.com/gitfrok/backend/gen/proto/git/v1"
	"github.com/gitfrok/backend/modules/codereview/internal/app"
)

// GitImporter implements the Code Review import port against a GitStorage
// client (SPEC-0011 AC1-AC3). Storage asks its own PDP and runs the fetch
// through the ordinary durability path; this adapter only forwards the verified
// principal and the source identity.
type GitImporter struct {
	client gitv1.GitStorageClient
}

// NewGitImporter wires the adapter onto the GitStorage client.
func NewGitImporter(client gitv1.GitStorageClient) *GitImporter {
	return &GitImporter{client: client}
}

// ImportRefs forwards the fetch. The source token travels only inside this
// call; it is never stored, logged, or copied into an event (SPEC-0011 AC22).
// The imported byte count comes back from storage, which measured what it
// wrote; this adapter does not compute or adjust it (SPEC-0011 AC9/AC21).
func (m *GitImporter) ImportRefs(ctx context.Context, command app.ImportRefsCommand) (app.GitResult, error) {
	response, err := m.client.ImportRefs(ctx, &gitv1.ImportRefsRequest{
		Context: &gitv1.OperationContext{
			TenantId:     command.TenantID,
			RepositoryId: command.RepositoryID,
			ActorId:      command.ActorID,
			RequestId:    command.RequestID,
			ActorRoles:   slices.Clone(command.ActorRoles),
		},
		SourceUrl:   command.SourceURL,
		SourceToken: command.SourceToken,
	})
	if err != nil {
		return app.GitResult{}, fmt.Errorf("codereview: import refs: %w", err)
	}
	updates := make([]app.RefUpdate, 0, len(response.GetRefs()))
	for _, ref := range response.GetRefs() {
		updates = append(updates, app.RefUpdate{Ref: ref.GetRef(), Revision: ref.GetRevision()})
	}
	return app.GitResult{Refs: updates, ImportedBytes: response.GetImportedBytes()}, nil
}

var _ app.GitImporter = (*GitImporter)(nil)
