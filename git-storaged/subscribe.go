package main

import (
	"context"
	"slices"

	gitv1 "github.com/gitfrok/backend/gen/proto/git/v1"
	repoapi "github.com/gitfrok/backend/modules/repository/api"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// refSubscriber is one active SubscribeRefUpdates stream. Updates are dropped,
// never blocked on: the node applies a ref update whether or not a subscriber
// is connected (SPEC-0015), and a slow consumer must not stall a push ack.
type refSubscriber struct {
	tenantID string
	repoID   string
	ch       chan repoapi.RefUpdated
}

// forwardRefUpdate fans a locally-applied RefUpdated out to every matching
// subscription. It runs synchronously on the bus during Publish, so it only
// enqueues; delivery happens on the subscriber's stream goroutine.
func (s *Server) forwardRefUpdate(_ context.Context, e repoapi.RefUpdated) error {
	s.refMu.Lock()
	matches := make([]*refSubscriber, 0, len(s.refSubs))
	for _, sub := range s.refSubs {
		if (sub.tenantID == "" || sub.tenantID == e.TenantID) &&
			(sub.repoID == "" || sub.repoID == e.RepoID) {
			matches = append(matches, sub)
		}
	}
	s.refMu.Unlock()

	for _, sub := range matches {
		select {
		case sub.ch <- e:
		default:
			// Slow consumer: drop rather than hold up the push acknowledgment.
		}
	}
	return nil
}

// SubscribeRefUpdates is the wire counterpart of the in-process RefUpdated
// event for consumers in another process (the dataplane): every ref update
// this node applies is delivered as one notification. Subscription is a
// wire event channel, not an acknowledgement protocol — the node keeps
// applying updates whether or not anyone listens (SPEC-0015).
func (s *Server) SubscribeRefUpdates(req *gitv1.SubscribeRefUpdatesRequest, stream gitv1.GitStorage_SubscribeRefUpdatesServer) error {
	if req == nil {
		return status.Error(codes.InvalidArgument, "subscribe request is required")
	}
	sub := &refSubscriber{
		tenantID: req.GetTenantId(),
		repoID:   req.GetRepositoryId(),
		ch:       make(chan repoapi.RefUpdated, 64),
	}
	s.refMu.Lock()
	s.refSubs = append(s.refSubs, sub)
	s.refMu.Unlock()
	defer func() {
		s.refMu.Lock()
		for i, other := range s.refSubs {
			if other == sub {
				s.refSubs = append(s.refSubs[:i], s.refSubs[i+1:]...)
				break
			}
		}
		s.refMu.Unlock()
	}()

	for {
		select {
		case <-stream.Context().Done():
			return nil
		case e := <-sub.ch:
			if err := stream.Send(&gitv1.RefUpdateNotification{
				EventId:      e.EventID,
				TenantId:     e.TenantID,
				RepositoryId: e.RepoID,
				Ref:          e.Ref,
				OldSha:       e.OldSha,
				NewSha:       e.NewSha,
				ActorId:      e.ActorID,
				ActorRoles:   slices.Clone(e.ActorRoles),
				OccurredAt:   timestamppb.New(e.OccurredAt),
			}); err != nil {
				return err
			}
		}
	}
}
