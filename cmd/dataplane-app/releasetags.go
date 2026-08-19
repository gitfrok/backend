package main

import (
	"context"

	repositoryv1 "github.com/gitfrok/backend/gen/proto/repository/v1"
	releaseapi "github.com/gitfrok/backend/modules/release"
)

// releaseTagResolver answers what a tag points at, for the Release context (T-0064, SPEC-0056 AC2).
//
// It lives here rather than in the Release module because that context may not depend on
// Repository/Git (ADR-0022) — the same inversion the repository registry's Authorizer uses. The
// module names the need; the composition root, which knows both contexts, satisfies it.
//
// It reads the tag list rather than asking for one tag, because RepositoryReader has no
// resolve-single-ref RPC and adding one for this would be a contract change for a convenience. The
// list is bounded and a repository's tag count is small; if that stops being true, a targeted RPC
// is the fix and it is a contract change worth making then rather than now.
type releaseTagResolver struct {
	reader repositoryv1.RepositoryReaderClient
}

// ResolveTag returns the commit the tag points at, or empty when there is no such tag.
//
// Empty is not an error: a tag that does not exist is a fact, and the caller refuses the publish on
// it. An error means the question could not be asked, which is a different thing and refuses too.
func (r releaseTagResolver) ResolveTag(ctx context.Context, tenantID, repositoryID, actorID string, actorRoles []string, tag string) (string, error) {
	pageToken := ""
	for {
		response, err := r.reader.ListTags(ctx, &repositoryv1.ListTagsRequest{
			Context: &repositoryv1.ReadContext{
				TenantId: tenantID, RepositoryId: repositoryID, ActorId: actorID,
				ActorRoles: actorRoles,
			},
			PageToken: pageToken,
		})
		if err != nil {
			return "", err
		}
		for _, candidate := range response.GetTags() {
			if candidate.GetName() == tag {
				return candidate.GetCommitId(), nil
			}
		}
		pageToken = response.GetNextPageToken()
		if pageToken == "" {
			return "", nil
		}
	}
}

var _ releaseapi.TagResolver = releaseTagResolver{}
