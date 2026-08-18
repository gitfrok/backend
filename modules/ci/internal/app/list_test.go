package app_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/gitfrok/backend/modules/ci/api"
	"github.com/gitfrok/backend/modules/ci/internal/app"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
)

// SPEC-0054 AC4, AC5: the listable set is the PDP's, derived per candidate at
// request time, and a caller allowed nothing gets an empty page rather than an
// error — "you may see none" and "there are none" have to be one answer.

type repoPDP struct {
	allowed map[string]bool
	err     error
	asked   []string
}

func (p *repoPDP) Decide(_ context.Context, req policyapi.Request) (policyapi.Decision, error) {
	p.asked = append(p.asked, req.Resource.ID)
	if p.err != nil {
		return policyapi.Decision{}, p.err
	}
	return policyapi.Decision{Allowed: p.allowed[req.Resource.ID]}, nil
}

type listStore struct {
	jobs []api.Job
	err  error
}

func (s *listStore) CreateOrGet(context.Context, string, api.Job) (api.Job, bool, error) {
	return api.Job{}, false, errors.New("not used")
}
func (s *listStore) Get(context.Context, string) (api.Job, error) {
	return api.Job{}, errors.New("not used")
}
func (s *listStore) Save(context.Context, api.Job) error { return errors.New("not used") }

func (s *listStore) Candidates(_ context.Context, tenantID, repositoryID string, after app.ListCursor, limit int) ([]api.Job, error) {
	if s.err != nil {
		return nil, s.err
	}
	var out []api.Job
	for _, job := range s.jobs {
		if job.TenantID != tenantID {
			continue
		}
		if repositoryID != "" && job.RepositoryID != repositoryID {
			continue
		}
		if !after.QueuedAt.IsZero() && !job.QueuedAt.Before(after.QueuedAt) {
			continue
		}
		out = append(out, job)
		if limit > 0 && len(out) == limit {
			break
		}
	}
	return out, nil
}

func job(id, repo string, at time.Time) api.Job {
	return api.Job{ID: id, TenantID: "t-1", RepositoryID: repo, QueuedAt: at, State: api.JobState("QUEUED")}
}

func listService(store app.Store, pdp policyapi.DecisionPoint) *app.Service {
	return app.New(store, nil, nil, pdp, nil)
}

func query() api.ListQuery {
	return api.ListQuery{TenantID: "t-1", ActorID: "actor-1", ActorRoles: []string{"member"}, PageSize: 10}
}

func TestListReturnsOnlyRunsWhoseRepositoryThePDPAllows(t *testing.T) {
	now := time.Now()
	store := &listStore{jobs: []api.Job{
		job("j1", "repo-allowed", now),
		job("j2", "repo-denied", now.Add(-time.Minute)),
		job("j3", "repo-allowed", now.Add(-2*time.Minute)),
	}}
	pdp := &repoPDP{allowed: map[string]bool{"repo-allowed": true}}

	page, err := listService(store, pdp).List(context.Background(), query())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if got := ids(page); fmt.Sprint(got) != fmt.Sprint([]string{"j1", "j3"}) {
		t.Fatalf("listed %v", got)
	}
	// One decision per candidate, at request time.
	if len(pdp.asked) != 3 {
		t.Fatalf("asked about %d repositories, want one per candidate", len(pdp.asked))
	}
}

func TestACallerAllowedNothingGetsAnEmptyPageNotAnError(t *testing.T) {
	store := &listStore{jobs: []api.Job{job("j1", "repo-1", time.Now())}}
	page, err := listService(store, &repoPDP{allowed: map[string]bool{}}).List(context.Background(), query())
	if err != nil {
		t.Fatalf("an empty result must not be an error: %v", err)
	}
	if len(page.Jobs) != 0 || page.NextPageToken != "" {
		t.Fatalf("listed %v", ids(page))
	}
}

func TestAPDPErrorRefusesThatRunWithoutFailingThePage(t *testing.T) {
	store := &listStore{jobs: []api.Job{job("j1", "repo-1", time.Now())}}
	page, err := listService(store, &repoPDP{err: errors.New("pdp down")}).List(context.Background(), query())
	if err != nil {
		t.Fatalf("one unavailable decision must not fail the page: %v", err)
	}
	if len(page.Jobs) != 0 {
		t.Fatal("a PDP error must refuse the run")
	}
}

func TestListRefusesWithoutATenantOrAPDP(t *testing.T) {
	store := &listStore{}
	if _, err := listService(store, &repoPDP{}).List(context.Background(), api.ListQuery{ActorID: "a"}); err == nil {
		t.Fatal("a list without a tenant must be refused")
	}
	if _, err := listService(store, nil).List(context.Background(), query()); err == nil {
		t.Fatal("an unauthorized list must be an error, not an empty page")
	}
}

func TestTheCursorIsBoundToTheTenantThatMintedIt(t *testing.T) {
	now := time.Now()
	store := &listStore{jobs: []api.Job{job("j1", "repo-1", now), job("j2", "repo-1", now.Add(-time.Minute))}}
	pdp := &repoPDP{allowed: map[string]bool{"repo-1": true}}

	q := query()
	q.PageSize = 1
	first, err := listService(store, pdp).List(context.Background(), q)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if first.NextPageToken == "" {
		t.Fatal("a full page with more behind it must offer a cursor")
	}

	stolen := query()
	stolen.TenantID = "t-2"
	stolen.PageToken = first.NextPageToken
	if _, err := listService(store, pdp).List(context.Background(), stolen); err == nil {
		t.Fatal("a cursor from another tenant must be refused")
	}
}

func TestAMalformedCursorIsRefused(t *testing.T) {
	q := query()
	q.PageToken = "not-a-cursor"
	if _, err := listService(&listStore{}, &repoPDP{}).List(context.Background(), q); err == nil {
		t.Fatal("a malformed cursor must be refused, not treated as the beginning")
	}
}

func TestAStoreThatCannotListIsAnErrorNotAnEmptyHistory(t *testing.T) {
	// Returning nothing would read as "no runs", which this service has no
	// basis for saying.
	if _, err := listService(&nonListingStore{}, &repoPDP{}).List(context.Background(), query()); err == nil {
		t.Fatal("a store that cannot enumerate must be an error")
	}
}

type nonListingStore struct{}

func (nonListingStore) CreateOrGet(context.Context, string, api.Job) (api.Job, bool, error) {
	return api.Job{}, false, errors.New("no")
}
func (nonListingStore) Get(context.Context, string) (api.Job, error) {
	return api.Job{}, errors.New("no")
}
func (nonListingStore) Save(context.Context, api.Job) error { return errors.New("no") }

func ids(p api.ListPage) []string {
	out := make([]string, 0, len(p.Jobs))
	for _, j := range p.Jobs {
		out = append(out, j.ID)
	}
	return out
}
