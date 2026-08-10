package gitfrontdoor

import (
	"context"
	"errors"
	"fmt"
	"time"

	gitv1 "github.com/gitfrok/backend/gen/proto/git/v1"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
	"github.com/gitfrok/backend/platform/objectstore"
)

// ObjectTier implements the batch surface's object port against the SeaweedFS-S3
// tier (SPEC-0023 AC3/AC4, ADR-0020).
//
// It is the enforcement point for LFS: reading and writing a large object are
// their own PDP actions, not implied by `repo.read`/`repo.write`. A large-file
// read is a distinct and expensive permission, and a tenant that wants to grant
// repository access without granting bulk object egress must be able to.
type ObjectTier struct {
	pdp     policyapi.DecisionPoint
	objects presigner
	// downloadTTL and uploadTTL bound how long an unrevokable credential lives.
	downloadTTL time.Duration
	uploadTTL   time.Duration
}

// presigner is the slice of the SeaweedFS-S3 store this adapter needs, so a test
// can supply one without a running SeaweedFS gateway.
type presigner interface {
	Stat(ctx context.Context, key string) (int64, error)
	Presign(method, key string, ttl time.Duration) (string, error)
}

// LFS PDP actions. They are asked about the repository, because that is the thing
// a grant is held on; the object is content within it.
const (
	actionLFSRead  = "repo.lfs.read"
	actionLFSWrite = "repo.lfs.write"
)

// Default credential lifetimes. Short, because a presigned URL cannot be revoked
// mid-transfer: the lifetime *is* the revocation window (SPEC-0023 decision 1).
// Upload is shorter than download — a client that has been told where to put an
// object acts immediately, while a download may queue behind other objects in the
// same batch.
const (
	defaultDownloadTTL = 10 * time.Minute
	defaultUploadTTL   = 5 * time.Minute
)

// NewObjectTier wires the adapter. A nil PDP or store is a configuration error
// rather than an LFS surface that authorizes nothing.
func NewObjectTier(pdp policyapi.DecisionPoint, objects presigner) (*ObjectTier, error) {
	if pdp == nil || objects == nil {
		return nil, errors.New("gitfrontdoor: the LFS object tier needs a PDP and an object store")
	}
	return &ObjectTier{
		pdp: pdp, objects: objects,
		downloadTTL: defaultDownloadTTL, uploadTTL: defaultUploadTTL,
	}, nil
}

// Download authorizes a read and returns a credential for exactly this object.
func (t *ObjectTier) Download(ctx context.Context, operation *gitv1.OperationContext, oid string) (string, int64, time.Duration, error) {
	if !validOID(oid) {
		return "", 0, 0, ErrObjectMissing
	}
	if !t.allowed(ctx, operation, actionLFSRead) {
		// A caller without the LFS grant is refused before the tier is touched, and
		// is told nothing about whether the object exists.
		return "", 0, 0, errors.New("gitfrontdoor: denied")
	}
	key := objectKey(operation.GetTenantId(), oid)
	size, err := t.objects.Stat(ctx, key)
	switch {
	case errors.Is(err, objectstore.ErrNotFound):
		return "", 0, 0, ErrObjectMissing
	case err != nil:
		return "", 0, 0, err
	}
	href, err := t.objects.Presign("GET", key, t.downloadTTL)
	if err != nil {
		return "", 0, 0, err
	}
	return href, size, t.downloadTTL, nil
}

// Upload authorizes a write and returns a credential for exactly this object.
//
// An object already stored returns no upload action and no credential: the tier
// is content-addressed, so the bytes under that OID are already the bytes this
// client would send, and issuing a write credential for them would be an
// opportunity to replace them.
func (t *ObjectTier) Upload(ctx context.Context, operation *gitv1.OperationContext, oid string, size int64) (string, time.Duration, error) {
	if !validOID(oid) || size < 0 {
		return "", 0, errors.New("gitfrontdoor: not an object identifier")
	}
	if !t.allowed(ctx, operation, actionLFSWrite) {
		return "", 0, errors.New("gitfrontdoor: denied")
	}
	key := objectKey(operation.GetTenantId(), oid)
	if _, err := t.objects.Stat(ctx, key); err == nil {
		return "", 0, errors.New("gitfrontdoor: object already stored")
	}
	href, err := t.objects.Presign("PUT", key, t.uploadTTL)
	if err != nil {
		return "", 0, err
	}
	return href, t.uploadTTL, nil
}

func (t *ObjectTier) allowed(ctx context.Context, operation *gitv1.OperationContext, action string) bool {
	if operation == nil || operation.GetTenantId() == "" || operation.GetActorId() == "" {
		return false
	}
	decision, err := t.pdp.Decide(ctx, policyapi.Request{
		TenantID: operation.GetTenantId(),
		Subject: policyapi.Subject{
			ID:       operation.GetActorId(),
			TenantID: operation.GetTenantId(),
			Roles:    append([]string(nil), operation.GetActorRoles()...),
		},
		Action:   action,
		Resource: policyapi.Resource{Type: "repository", ID: operation.GetRepositoryId()},
	})
	return err == nil && decision.Allowed
}

// objectKey mirrors storage's key layout: tenant first, so the same OID in two
// tenants is two objects (SPEC-0023 AC4). It is duplicated rather than shared
// because git-storaged is a separate binary in package main, and the alternative
// is a shared package whose only content is one format string — the layout is
// asserted equal by a test instead.
func objectKey(tenantID, oid string) string {
	return fmt.Sprintf("lfs/%s/%s/%s", tenantID, oid[:2], oid)
}

// validOID accepts only a lowercase hex SHA-256. An OID becomes part of a storage
// key, so a value that could carry a separator or a traversal segment is refused
// rather than escaped.
func validOID(oid string) bool {
	if len(oid) != 64 {
		return false
	}
	for _, r := range oid {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
		default:
			return false
		}
	}
	return true
}
