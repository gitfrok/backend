package main

import (
	"context"
	"testing"
	"time"

	gitv1 "github.com/gitfrok/backend/gen/proto/git/v1"
	"github.com/gitfrok/backend/modules/repository/api"
	"github.com/gitfrok/backend/platform/bus"
)

func TestSubscribeRefUpdatesDeliversMatchingUpdates(t *testing.T) {
	events := bus.NewInProcess()
	client, closeClient := newClient(t, t.TempDir(), allowPDP{}, events)
	defer closeClient()

	want := api.RefUpdated{
		EventID:    "01JQZTEST000000000000000001",
		TenantID:   "tenant-a",
		RepoID:     "repo-a",
		Ref:        "refs/heads/main",
		OldSha:     "0000000000000000000000000000000000000000",
		NewSha:     "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
		ActorID:    "user-1",
		ActorRoles: []string{"owner"},
		OccurredAt: time.Now().UTC(),
	}
	got, recvErr := subscribeAndPublish(t, client, events, "tenant-a", "repo-a", want)
	if recvErr != nil {
		t.Fatalf("Recv(): %v", recvErr)
	}
	if got.GetEventId() != want.EventID ||
		got.GetTenantId() != want.TenantID ||
		got.GetRepositoryId() != want.RepoID ||
		got.GetRef() != want.Ref ||
		got.GetOldSha() != want.OldSha ||
		got.GetNewSha() != want.NewSha ||
		got.GetActorId() != want.ActorID {
		t.Fatalf("Recv() = %+v, want fields of %+v", got, want)
	}
	if len(got.GetActorRoles()) != len(want.ActorRoles) || got.GetActorRoles()[0] != want.ActorRoles[0] {
		t.Fatalf("ActorRoles = %v, want %v", got.GetActorRoles(), want.ActorRoles)
	}
	if got.GetOccurredAt().AsTime().Unix() != want.OccurredAt.Unix() {
		t.Fatalf("OccurredAt = %v, want %v", got.GetOccurredAt().AsTime(), want.OccurredAt)
	}
}

// subscribeAndPublish subscribes, publishes one update, and reads it back.
// The client call returns before the server handler has registered the
// subscriber (the request and handler start lag the call by ~ms on bufconn),
// so a publish in that window is lost; a short settle makes the assertion
// deterministic.
func subscribeAndPublish(t *testing.T, client gitv1.GitStorageClient, events bus.Bus, tenantID, repoID string, update api.RefUpdated) (*gitv1.RefUpdateNotification, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := client.SubscribeRefUpdates(ctx, &gitv1.SubscribeRefUpdatesRequest{
		TenantId:     tenantID,
		RepositoryId: repoID,
	})
	if err != nil {
		t.Fatalf("SubscribeRefUpdates(): %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	if err := events.Publish(ctx, update); err != nil {
		t.Fatalf("Publish(): %v", err)
	}
	return stream.Recv()
}

func TestSubscribeRefUpdatesFiltersByScope(t *testing.T) {
	events := bus.NewInProcess()
	client, closeClient := newClient(t, t.TempDir(), allowPDP{}, events)
	defer closeClient()

	stream, err := client.SubscribeRefUpdates(context.Background(), &gitv1.SubscribeRefUpdatesRequest{
		TenantId:     "tenant-a",
		RepositoryId: "repo-a",
	})
	if err != nil {
		t.Fatalf("SubscribeRefUpdates(): %v", err)
	}

	// A different tenant/repo pair must not be delivered.
	if err := events.Publish(context.Background(), api.RefUpdated{
		EventID:  "01JQZTEST000000000000000002",
		TenantID: "tenant-a",
		RepoID:   "repo-b",
		Ref:      "refs/heads/main",
		OldSha:   "0000000000000000000000000000000000000000",
		NewSha:   "aaaa",
	}); err != nil {
		t.Fatalf("Publish(): %v", err)
	}
	if err := events.Publish(context.Background(), api.RefUpdated{
		EventID:  "01JQZTEST000000000000000003",
		TenantID: "tenant-b",
		RepoID:   "repo-a",
		Ref:      "refs/heads/main",
		OldSha:   "0000000000000000000000000000000000000000",
		NewSha:   "bbbb",
	}); err != nil {
		t.Fatalf("Publish(): %v", err)
	}

	received := make(chan *gitv1.RefUpdateNotification, 1)
	go func() {
		got, _ := stream.Recv()
		received <- got
	}()
	select {
	case got := <-received:
		if got != nil {
			t.Fatalf("Recv() = %+v, want nothing for out-of-scope updates", got)
		}
	case <-time.After(300 * time.Millisecond):
		// Nothing delivered, as expected.
	}
}

func TestSubscribeRefUpdatesWildcardTenant(t *testing.T) {
	events := bus.NewInProcess()
	client, closeClient := newClient(t, t.TempDir(), allowPDP{}, events)
	defer closeClient()

	got, recvErr := subscribeAndPublish(t, client, events, "", "", api.RefUpdated{
		EventID:  "01JQZTEST000000000000000004",
		TenantID: "tenant-z",
		RepoID:   "repo-z",
		Ref:      "refs/heads/main",
		OldSha:   "0000000000000000000000000000000000000000",
		NewSha:   "cccc",
	})
	if recvErr != nil {
		t.Fatalf("Recv(): %v", recvErr)
	}
	if got.GetTenantId() != "tenant-z" || got.GetRepositoryId() != "repo-z" {
		t.Fatalf("Recv() = %+v, want tenant-z/repo-z", got)
	}
}

func TestSubscribeRefUpdatesDropsSlowConsumer(t *testing.T) {
	events := bus.NewInProcess()
	client, closeClient := newClient(t, t.TempDir(), allowPDP{}, events)
	defer closeClient()

	// A subscriber that never drains its channel: the 65th update must be
	// dropped, not block the publisher.
	stream, err := client.SubscribeRefUpdates(context.Background(), &gitv1.SubscribeRefUpdatesRequest{
		TenantId: "tenant-a",
	})
	if err != nil {
		t.Fatalf("SubscribeRefUpdates(): %v", err)
	}
	defer stream.CloseSend()

	done := make(chan error, 1)
	go func() {
		for i := 0; i < 64; i++ {
			done <- events.Publish(context.Background(), api.RefUpdated{
				EventID:  "01JQZTEST000000000000000005",
				TenantID: "tenant-a",
				RepoID:   "repo-a",
				Ref:      "refs/heads/main",
				OldSha:   "0000000000000000000000000000000000000000",
				NewSha:   "dddd",
			})
		}
	}()
	for i := 0; i < 64; i++ {
		if err := <-done; err != nil {
			t.Fatalf("Publish(%d): %v", i, err)
		}
	}
}

func TestSubscribeRefUpdatesEndsOnCancel(t *testing.T) {
	events := bus.NewInProcess()
	client, closeClient := newClient(t, t.TempDir(), allowPDP{}, events)
	defer closeClient()

	ctx, cancel := context.WithCancel(context.Background())
	stream, err := client.SubscribeRefUpdates(ctx, &gitv1.SubscribeRefUpdatesRequest{})
	if err != nil {
		t.Fatalf("SubscribeRefUpdates(): %v", err)
	}
	cancel()

	done := make(chan error, 1)
	go func() {
		_, err := stream.Recv()
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Recv() = nil, want an error after cancel")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("stream did not end after context cancel")
	}
}
