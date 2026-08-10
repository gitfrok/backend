package protection

import (
	"context"
	"testing"
	"time"

	codereviewapi "github.com/gitfrok/backend/modules/codereview/api"
	"github.com/gitfrok/backend/platform/bus"
)

func changed(tenant, repo, ref string, required int32) codereviewapi.BranchProtectionChanged {
	return codereviewapi.BranchProtectionChanged{
		EventID: "event-1", TenantID: tenant, RepositoryID: repo, TargetRef: ref,
		RequiredApprovals: required, OccurredAt: time.Now().UTC(),
	}
}

// The projection is fed only by the event. Nothing here reads Code Review state.
func TestProtectionArrivesOnlyFromTheEvent(t *testing.T) {
	events := bus.NewInProcess()
	projection := New()
	projection.Subscribe(events)

	if projection.Protected("tenant-a", "repo-a", "refs/heads/main") {
		t.Fatal("a ref was protected before any event arrived")
	}
	if err := events.Publish(context.Background(), changed("tenant-a", "repo-a", "refs/heads/main", 1)); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if !projection.Protected("tenant-a", "repo-a", "refs/heads/main") {
		t.Fatal("the ref is not protected after BranchProtectionChanged")
	}
}

// A rule in one tenant is not a rule in another, and it does not apply to another
// repository or another ref.
func TestProtectionIsScopedToItsTenantRepositoryAndRef(t *testing.T) {
	events := bus.NewInProcess()
	projection := New()
	projection.Subscribe(events)
	if err := events.Publish(context.Background(), changed("tenant-a", "repo-a", "refs/heads/main", 1)); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	for _, probe := range []struct{ tenant, repo, ref string }{
		{"tenant-b", "repo-a", "refs/heads/main"},
		{"tenant-a", "repo-b", "refs/heads/main"},
		{"tenant-a", "repo-a", "refs/heads/release"},
	} {
		if projection.Protected(probe.tenant, probe.repo, probe.ref) {
			t.Errorf("%s/%s/%s is protected by another scope's rule", probe.tenant, probe.repo, probe.ref)
		}
	}
}

// Zero required approvals is still a protection rule: the count governs merges,
// the rule's existence governs direct pushes.
func TestZeroRequiredApprovalsStillProtectsTheRef(t *testing.T) {
	events := bus.NewInProcess()
	projection := New()
	projection.Subscribe(events)
	if err := events.Publish(context.Background(), changed("tenant-a", "repo-a", "refs/heads/main", 0)); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if !projection.Protected("tenant-a", "repo-a", "refs/heads/main") {
		t.Fatal("a zero-approval rule left the ref unprotected")
	}
}
