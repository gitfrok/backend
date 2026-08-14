// Package security is the Security/Findings context (SPEC-0024, SPEC-0025):
// the normalized finding model, scanner ingestion, and tenant-scoped reads.
//
// It wires the ingest service — the one place an ingest meets the PDP,
// computes identities, and emits events and the audit record — over an
// explicit store port. The in-memory store serves dev and tests; the
// Postgres adapter serves a configured plane. Swapping stores is a change
// to the composition line and nothing else.
package security

import (
	"context"
	"fmt"
	"time"

	repositoryv1 "github.com/gitfrok/backend/gen/proto/repository/v1"
	auditapi "github.com/gitfrok/backend/modules/audit/api"
	codereviewapi "github.com/gitfrok/backend/modules/codereview/api"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
	"github.com/gitfrok/backend/modules/security/api"
	securitygrpc "github.com/gitfrok/backend/modules/security/internal/adapters/grpc"
	secpg "github.com/gitfrok/backend/modules/security/internal/adapters/postgres"
	"github.com/gitfrok/backend/modules/security/internal/app"
	platformaudit "github.com/gitfrok/backend/platform/audit"
	"github.com/gitfrok/backend/platform/bus"
	"github.com/gitfrok/backend/platform/db"
	"github.com/gitfrok/backend/platform/ids"
	"github.com/gitfrok/backend/platform/tenancy"
)

// GRPCServer is the module's gRPC door, aliased so cmd/ can hold one
// without naming a package under this module's internal/ tree.
type GRPCServer = securitygrpc.Server

// New builds the context on the in-memory store: dev and tests, and any
// plane without a database URL.
func New(pdp policyapi.DecisionPoint, events bus.Bus) api.Findings {
	return app.New(app.NewMemoryStore(), pdp, events)
}

// NewWithPostgres builds the context on the Postgres adapter: the schema's
// UNIQUE identity dedup, the scan state machine, and RLS tenant isolation
// back the same contract the memory store implements.
func NewWithPostgres(pool *db.Pool, pdp policyapi.DecisionPoint, events bus.Bus) api.Findings {
	return app.New(secpg.New(pool), pdp, events)
}

// NewGRPCServer adapts the Findings port to its gRPC contract.
func NewGRPCServer(findings api.Findings) *GRPCServer {
	return securitygrpc.NewServer(findings)
}

// AttachMergeBaseResolver wires the Repository/Git route attribution
// resolves merge bases through (SPEC-0028). It is a post-construction step
// because the route to Git storage exists only once a plane's doors are
// open, while Security/Findings is composed before them; a Findings surface
// with no resolver leaves attribution honestly UNAVAILABLE. It reports
// false when the surface has no attribution engine to attach to.
func AttachMergeBaseResolver(findings api.Findings, resolver api.MergeBaseResolver) bool {
	type resolverSink interface{ SetMergeBaseResolver(api.MergeBaseResolver) }
	sink, ok := findings.(resolverSink)
	if !ok {
		return false
	}
	sink.SetMergeBaseResolver(resolver)
	return true
}

// AttachAuditWitness wires the trail witness the ingest replay path asks
// whether the ingest's one audit record really landed (SPEC-0025 AC5, wave-2
// N5). Post-construction for the same reason the resolver is: the audit
// trail is composed after the findings service. A Findings surface with no
// witness falls back to the claim marker alone. It reports false when the
// surface has no ingest service to attach to.
func AttachAuditWitness(findings api.Findings, witness app.AuditWitness) bool {
	type witnessSink interface{ SetAuditWitness(app.AuditWitness) }
	sink, ok := findings.(witnessSink)
	if !ok {
		return false
	}
	sink.SetAuditWitness(witness)
	return true
}

// trailAuditWitness answers the replay path's "did the audit record land?"
// from the tenant's audit trail itself (wave-2 N5): the claim marker is
// claimed in the same transaction as the chunk commit, so its presence says
// "committed", not "audited" — the trail is the truth.
type trailAuditWitness struct {
	trail auditapi.TrailReader
}

// NewTrailAuditWitness builds the audit witness over the plane's trail read
// port. The witness performs only the one query the replay guard needs —
// scan-ingest records of one repository since the scan started — never a
// general trail read.
func NewTrailAuditWitness(trail auditapi.TrailReader) app.AuditWitness {
	return trailAuditWitness{trail: trail}
}

func (w trailAuditWitness) IngestAuditRecorded(ctx context.Context, tenantID, repositoryID, scanID, requestID string, since time.Time) (bool, error) {
	// The trail read is tenant-scoped like every trail read (SPEC-0001);
	// the scope comes from the ingest being verified, never broader. The
	// repository filter is deliberately NOT applied: the trail narrows it by
	// a detail key the scan-ingest record does not carry (its repository
	// rides the record's resource), and the (scan_id, request_id) pair
	// identifies the ingest's record uniquely — scan identity is a
	// server-computed hash over the tenant and repository among other
	// descriptor fields, so no other tenant or repository can share it.
	ctx = tenancy.WithTenant(ctx, tenancy.ID(tenantID))
	records, truncated, err := w.trail.Query(ctx, auditapi.TrailQuery{
		From:    since,
		Actions: []auditapi.Action{auditapi.Action(platformaudit.ActionFindingsScanIngested)},
	})
	if err != nil {
		return false, fmt.Errorf("security: witness trail query: %w", err)
	}
	for _, r := range records {
		if r.Detail["scan_id"] == scanID && r.Detail["request_id"] == requestID {
			return true, nil
		}
	}
	if truncated {
		// The matching range holds more records than one read returns, and
		// the record sought — appended at commit — sits at the TAIL, beyond
		// the earliest prefix the read yields. Report "cannot answer": the
		// caller falls back to the claim marker, which at least says
		// "committed".
		return false, fmt.Errorf("security: witness trail read truncated before the record could be located")
	}
	return false, nil
}

// mergeFactsSource is the facts assembler this module's service implements
// (T-0025, SPEC-0029, SPEC-0030). Named here — not on api.Findings — because
// it is not a caller-facing operation: it performs no PDP decision of its
// own, and its only legitimate consumer is the merge decision whose input it
// assembles. The composition root is the only place the two meet.
type mergeFactsSource interface {
	MergeFindingsFacts(ctx context.Context, tenantID, repositoryID, actorID, mergeRequestID string) (codereviewapi.FindingsGateFacts, error)
}

// mergeFactsAdapter presents the assembler on Code Review's port: the port
// speaks the merge decision's vocabulary (FindingsFacts), the assembler
// speaks this context's (MergeFindingsFacts), and the adapter is the whole
// translation.
type mergeFactsAdapter struct{ source mergeFactsSource }

func (a mergeFactsAdapter) FindingsFacts(ctx context.Context, tenantID, repositoryID, actorID, mergeRequestID string) (codereviewapi.FindingsGateFacts, error) {
	return a.source.MergeFindingsFacts(ctx, tenantID, repositoryID, actorID, mergeRequestID)
}

// NewFindingsFactsProvider adapts the Findings surface to Code Review's
// merge-gate findings-facts port (T-0025, SPEC-0029, SPEC-0030): the
// attributed-findings facts a merge decision presents to the reviewed
// security gate, assembled from this context's own attribution and triage
// state. A nil return means the surface has no facts assembler — the
// composition root must treat that as a startup failure, because a merge
// gate wired without its facts provider is a gate silently disengaged.
func NewFindingsFactsProvider(findings api.Findings) codereviewapi.FindingsFactsProvider {
	source, ok := findings.(mergeFactsSource)
	if !ok {
		return nil
	}
	return mergeFactsAdapter{source: source}
}

// grpcMergeBaseResolver adapts repository.v1.RepositoryReader.GetMergeBase
// to the module's port: one PDP-guarded read per resolution, no common
// ancestor rendered as found=false rather than an error — exactly as the
// contract says (T-0024).
type grpcMergeBaseResolver struct {
	reader repositoryv1.RepositoryReaderClient
}

// NewMergeBaseResolver builds the resolver over the plane's RepositoryReader
// route to git-storaged.
func NewMergeBaseResolver(reader repositoryv1.RepositoryReaderClient) api.MergeBaseResolver {
	return grpcMergeBaseResolver{reader: reader}
}

func (r grpcMergeBaseResolver) MergeBase(ctx context.Context, tenantID, repositoryID, actorID, refA, refB string) (string, bool, error) {
	resp, err := r.reader.GetMergeBase(ctx, &repositoryv1.GetMergeBaseRequest{
		Context: &repositoryv1.ReadContext{
			TenantId: tenantID, RepositoryId: repositoryID,
			ActorId: actorID, RequestId: ids.NewULID(),
		},
		RefA: refA, RefB: refB,
	})
	if err != nil {
		return "", false, err
	}
	return resp.GetMergeBase(), resp.GetFound(), nil
}
