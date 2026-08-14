// Package gitfrontdoor holds the protocol-neutral authorization boundary for
// Smart-HTTP and SSH. It authenticates a credential before a GitStorage stream
// can be opened and builds the sole context the storage tier receives.
package gitfrontdoor

import (
	"context"
	"errors"
	"regexp"
	"slices"
	"strings"

	gitv1 "github.com/gitfrok/backend/gen/proto/git/v1"
	identityapi "github.com/gitfrok/backend/modules/identity/api"
)

// ErrDenied is deliberately coarse. Transport adapters map every rejected
// credential or handle to their one non-enumerating protocol response.
var ErrDenied = errors.New("git front door: denied")

var opaqueID = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// Router performs identity-to-operation-context translation. It does not
// decide repository authorization: git-storaged remains the PDP enforcement
// point immediately before Git executes (ADR-0041).
type Router struct {
	Authenticator identityapi.Authenticator
}

// RoutePAT resolves token before interpreting any storage operation. The
// tenant portion of handle must equal the authenticated tenant; a client can
// therefore never select another tenant by changing a URL segment.
func (r Router) RoutePAT(ctx context.Context, handle, token, requestID string, transport gitv1.GitTransport) (*gitv1.OperationContext, error) {
	if r.Authenticator == nil {
		return nil, ErrDenied
	}
	principal, ok := r.Authenticator.AuthenticatePAT(ctx, token)
	if !ok {
		return nil, ErrDenied
	}
	return r.route(handle, requestID, principal, transport)
}

// RouteSSH has the same boundary as RoutePAT after the transport has verified
// public-key possession. The configured key ID is public routing metadata, not
// a tenant assertion or authorization result.
func (r Router) RouteSSH(ctx context.Context, handle, publicKey, verifierKeyID, requestID string) (*gitv1.OperationContext, error) {
	if r.Authenticator == nil {
		return nil, ErrDenied
	}
	principal, ok := r.Authenticator.AuthenticateSSHKey(ctx, publicKey, verifierKeyID)
	if !ok {
		return nil, ErrDenied
	}
	return r.route(handle, requestID, principal, gitv1.GitTransport_GIT_TRANSPORT_SSH)
}

func (r Router) route(handle, requestID string, principal identityapi.Principal, transport gitv1.GitTransport) (*gitv1.OperationContext, error) {
	tenantID, repositoryID, err := ParseHandle(handle)
	if err != nil || requestID == "" || principal.TenantID != tenantID || principal.ActorID == "" {
		return nil, ErrDenied
	}
	return &gitv1.OperationContext{
		TenantId:     tenantID,
		RepositoryId: repositoryID,
		ActorId:      principal.ActorID,
		RequestId:    requestID,
		ActorRoles:   slices.Clone(principal.Roles),
		Transport:    transport,
	}, nil
}

// ParseHandle accepts only the opaque external form tenant/repository.git.
// It rejects slash traversal and filesystem paths before they can reach a
// storage boundary; the resulting IDs are not a server-side path.
func ParseHandle(handle string) (tenantID, repositoryID string, err error) {
	parts := strings.Split(handle, "/")
	if len(parts) != 2 || !strings.HasSuffix(parts[1], ".git") {
		return "", "", ErrDenied
	}
	repositoryID = strings.TrimSuffix(parts[1], ".git")
	if !opaqueID.MatchString(parts[0]) || !opaqueID.MatchString(repositoryID) {
		return "", "", ErrDenied
	}
	return parts[0], repositoryID, nil
}
