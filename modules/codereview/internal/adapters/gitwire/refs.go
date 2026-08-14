// Package gitwire carries Code Review's authorized ref move to Repository/Git
// over the published GitStorage contract (SPEC-0019, SPEC-0015).
//
// It is the whole of Code Review's access to Git: one call, on one contract, to
// move one ref. There is no storage path, no repository handle resolution, and no
// Git object handling on this side of the boundary.
package gitwire

import (
	"context"
	"fmt"
	"slices"

	gitv1 "github.com/gitfrok/backend/gen/proto/git/v1"
	"github.com/gitfrok/backend/modules/codereview/internal/app"
)

// RefMover implements the Code Review port against a GitStorage client.
type RefMover struct {
	client gitv1.GitStorageClient
}

func NewRefMover(client gitv1.GitStorageClient) *RefMover {
	return &RefMover{client: client}
}

// MoveRef forwards the move with the verified principal attached. Storage asks
// its own PDP with it, so this call carries no allow flag, no approval count, and
// no protection result — none of which the contract can even express.
func (m *RefMover) MoveRef(ctx context.Context, command app.MergeRefCommand) error {
	_, err := m.client.MergeRef(ctx, &gitv1.MergeRefRequest{
		Context: &gitv1.RefUpdateContext{
			TenantId:     command.TenantID,
			RepositoryId: command.RepositoryID,
			ActorId:      command.ActorID,
			RequestId:    command.RequestID,
			ActorRoles:   slices.Clone(command.ActorRoles),
		},
		TargetRef:               command.TargetRef,
		Revision:                command.Revision,
		ExpectedCurrentRevision: command.ExpectedCurrentRevision,
	})
	if err != nil {
		return fmt.Errorf("codereview: move %s: %w", command.TargetRef, err)
	}
	return nil
}

var _ app.RefMover = (*RefMover)(nil)
