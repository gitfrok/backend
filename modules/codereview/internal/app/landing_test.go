package app

import (
	"context"
	"errors"
	"testing"

	"github.com/gitfrok/backend/modules/codereview/api"
)

// SPEC-0065 AC7 — the landing policy is read server-side from the repository
// record at merge time. The command surface cannot express a strategy: what
// lands is decided between this context's record read and storage's object
// graph, and no caller field sits anywhere in between.

type recordingLander struct {
	command  MergeRefCommand
	strategy string
	trunk    bool
	found    bool
	err      error
	tenant   string
	actor    string
	repo     string
}

func (r *recordingLander) LandingFor(_ context.Context, tenantID, actorID string, _ []string, repoID string) (string, bool, bool, error) {
	r.tenant, r.actor, r.repo = tenantID, actorID, repoID
	if r.err != nil {
		return "", false, false, r.err
	}
	return r.strategy, r.trunk, r.found, nil
}

func TestAMergeForwardsTheRecordedPolicy(t *testing.T) {
	service, _, refs, _ := newService(t)
	lander := &recordingLander{strategy: "squash", trunk: true, found: true}
	service.SetLandingPolicies(lander)

	mr := openOne(t, service, "request-open")
	mr = approveTwo(t, service, mr)
	if _, err := service.Merge(t.Context(), api.MergeRequestCommand{
		Context:         principal("tenant-a", "actor-a", "request-merge", "member"),
		MergeRequestID:  mr.ID,
		ExpectedVersion: mr.Version,
	}); err != nil {
		t.Fatalf("Merge: %v", err)
	}
	if lander.repo != "repo-a" || lander.actor != "actor-a" || lander.tenant != "tenant-a" {
		t.Fatalf("policy read under tenant=%q actor=%q repo=%q", lander.tenant, lander.actor, lander.repo)
	}
	last := refs.commands[len(refs.commands)-1]
	if last.Landing == nil {
		t.Fatal("the ref move carried no landing plan")
	}
	if last.Landing.Strategy != "squash" || !last.Landing.TrunkBased {
		t.Fatalf("plan = %+v, want the recorded policy verbatim", last.Landing)
	}
	if last.Landing.MessageTitle != "Add a thing" {
		t.Fatalf("plan title = %q, want the merge request's own", last.Landing.MessageTitle)
	}
	if last.Landing.MergeRequestReference != mr.ID {
		t.Fatalf("plan reference = %q, want the merge request's opaque ID", last.Landing.MergeRequestReference)
	}
}

// A repository with no explicit policy lands legacy: no plan travels at all.
func TestAnUnsetPolicyLandsLegacyByteForByte(t *testing.T) {
	service, _, refs, _ := newService(t)
	service.SetLandingPolicies(&recordingLander{found: false})

	mr := openOne(t, service, "request-open")
	mr = approveTwo(t, service, mr)
	if _, err := service.Merge(t.Context(), api.MergeRequestCommand{
		Context:         principal("tenant-a", "actor-a", "request-merge", "member"),
		MergeRequestID:  mr.ID,
		ExpectedVersion: mr.Version,
	}); err != nil {
		t.Fatalf("Merge: %v", err)
	}
	last := refs.commands[len(refs.commands)-1]
	if last.Landing != nil {
		t.Fatalf("legacy merge carried %+v, want no landing field at all", last.Landing)
	}
}

// An unreadable record refuses the merge rather than guessing a history shape.
func TestAnUnreadablePolicyRefusesTheMerge(t *testing.T) {
	service, _, refs, _ := newService(t)
	service.SetLandingPolicies(&recordingLander{err: errors.New("settings store down")})

	mr := openOne(t, service, "request-open")
	mr = approveTwo(t, service, mr)
	if _, err := service.Merge(t.Context(), api.MergeRequestCommand{
		Context:         principal("tenant-a", "actor-a", "request-merge", "member"),
		MergeRequestID:  mr.ID,
		ExpectedVersion: mr.Version,
	}); !errors.Is(err, api.ErrDenied) {
		t.Fatalf("Merge = %v, want the coarse denial", err)
	}
	for _, command := range refs.commands {
		if command.Landing != nil {
			t.Fatal("a refused merge moved a ref with a plan anyway")
		}
	}
}

// No reader wired means legacy too — the dev composition.
func TestNoReaderWiredLandsLegacy(t *testing.T) {
	service, _, refs, _ := newService(t)
	mr := openOne(t, service, "request-open")
	mr = approveTwo(t, service, mr)
	if _, err := service.Merge(t.Context(), api.MergeRequestCommand{
		Context:         principal("tenant-a", "actor-a", "request-merge", "member"),
		MergeRequestID:  mr.ID,
		ExpectedVersion: mr.Version,
	}); err != nil {
		t.Fatalf("Merge: %v", err)
	}
	last := refs.commands[len(refs.commands)-1]
	if last.Landing != nil {
		t.Fatalf("unwired merge carried %+v", last.Landing)
	}
}
