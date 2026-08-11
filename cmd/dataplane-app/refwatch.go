package main

import (
	"context"
	"fmt"
	"os"
	"time"

	gitv1 "github.com/gitfrok/backend/gen/proto/git/v1"
	repoapi "github.com/gitfrok/backend/modules/repository/api"
	"github.com/gitfrok/backend/platform/bus"
)

// watchRefUpdates mirrors git-storaged's RefUpdated announcements onto this
// plane's bus (SPEC-0015). In the monolith composition the receive-pack door
// and the repository/codesearch/CI consumers share one process and one bus; in
// this split deployment git-storaged applies refs, so the dataplane subscribes
// to the wire stream and republishes each notification as the same in-process
// event its consumers already listen for. The subscription is best-effort
// while connected: updates applied while the stream is down are not replayed,
// so callers re-resolve against storage rather than relying on every update.
func watchRefUpdates(ctx context.Context, client gitv1.GitStorageClient, b bus.Bus) {
	if client == nil || b == nil {
		return
	}
	go func() {
		for ctx.Err() == nil {
			stream, err := client.SubscribeRefUpdates(ctx, &gitv1.SubscribeRefUpdatesRequest{})
			if err != nil {
				fmt.Fprintf(os.Stderr, "dataplane: ref watch subscribe: %v\n", err)
				select {
				case <-time.After(time.Second):
				case <-ctx.Done():
					return
				}
				continue
			}
			fmt.Fprintf(os.Stderr, "dataplane: ref watch connected\n")
			for {
				n, err := stream.Recv()
				if err != nil {
					fmt.Fprintf(os.Stderr, "dataplane: ref watch stream ended: %v\n", err)
					break
				}
				fmt.Fprintf(os.Stderr, "dataplane: ref watch %s %s %s -> %s\n", n.GetTenantId(), n.GetRepositoryId(), n.GetRef(), n.GetNewSha())
				if err := b.Publish(ctx, repoapi.RefUpdated{
					EventID:    n.GetEventId(),
					TenantID:   n.GetTenantId(),
					RepoID:     n.GetRepositoryId(),
					Ref:        n.GetRef(),
					OldSha:     n.GetOldSha(),
					NewSha:     n.GetNewSha(),
					ActorID:    n.GetActorId(),
					ActorRoles: n.GetActorRoles(),
					OccurredAt: n.GetOccurredAt().AsTime(),
				}); err != nil {
					fmt.Fprintf(os.Stderr, "dataplane: republish RefUpdated: %v\n", err)
				}
			}
		}
	}()
}
