// Package audit is the composition root for the Audit context (ADR-0025).
//
// It exists because Go's internal/ rule stops cmd/ from naming an internal type, so without it
// "wire in cmd/" is not expressible. One constructor per adapter choice; cmd/ picks one.
package audit

import (
	auditv1 "github.com/gitfrok/backend/gen/proto/audit/v1"
	"github.com/gitfrok/backend/modules/audit/api"
	codereviewadapter "github.com/gitfrok/backend/modules/audit/internal/adapters/codereview"
	auditgrpc "github.com/gitfrok/backend/modules/audit/internal/adapters/grpc"
	identityadapter "github.com/gitfrok/backend/modules/audit/internal/adapters/identity"
	"github.com/gitfrok/backend/modules/audit/internal/adapters/memory"
	auditpg "github.com/gitfrok/backend/modules/audit/internal/adapters/postgres"
	"github.com/gitfrok/backend/modules/audit/internal/app"
	codereviewapi "github.com/gitfrok/backend/modules/codereview/api"
	identityapi "github.com/gitfrok/backend/modules/identity/api"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
	"github.com/gitfrok/backend/platform/bus"
	"github.com/gitfrok/backend/platform/db"
)

// NewPostgresLog returns the Postgres-backed audit log as its api.Log surface — Append and Verify,
// with no update or delete path to hand out (SPEC-0003 AC1).
func NewPostgresLog(pool *db.Pool) api.Log { return auditpg.New(pool) }

// NewPostgresTrail returns the Postgres-backed trail with its Phase 2 read
// port (T-0026): Append, Verify and date-ranged queries. The read path needs
// no new privilege — the table stays append-only at the grant level.
func NewPostgresTrail(pool *db.Pool) api.TrailStore { return auditpg.New(pool) }

// NewMemoryTrail returns the in-memory trail: the same hash-chained,
// append-only shape for dev planes and tests. It is not durable, exactly like
// every other in-memory adapter; a configured plane composes the Postgres
// trail instead.
func NewMemoryTrail() api.TrailStore { return memory.New() }

// EvidenceService is the composed evidence pack service, aliased so cmd/ can chain its
// builders (WithResidencyWindow) without naming a package under internal/ (ADR-0025).
// It implements api.PackService.
type EvidenceService = app.Service

// NewEvidenceService assembles the evidence pack surface (T-0026, SPEC-0031,
// SPEC-0032): generation and retrieval are PDP decisions with server-derived
// context, themselves audited, and sections assemble through contract
// surfaces and the event-fed projection — never another context's tables.
// attested and access may be nil; see internal/app for the degraded shapes.
// grants is Identity & Access's auditor grant surface (T-0027, SPEC-0033):
// the decision-time facts source auditor pack reads compose fresh on every
// evidence.pack.read decision; nil fails every auditor read closed.
func NewEvidenceService(pdp policyapi.DecisionPoint, events bus.Bus, trail api.TrailStore,
	attested api.AttestedHistorySource, access api.AccessChangesSource,
	grants identityapi.AuditorGrants) *EvidenceService {
	return app.New(pdp, events, trail, attested, access, grants)
}

// NewImportedHistorySource adapts Code Review's import surface to the
// appendix port: attested imported history, labelled as foreign history and
// representable only in the appendix (SPEC-0032 AC2). Composed only on planes
// that have the import surface — a plane without it has no imported history,
// and an empty appendix is then the truthful answer.
func NewImportedHistorySource(imports codereviewapi.ImportService) api.AttestedHistorySource {
	return codereviewadapter.NewImportedHistorySource(imports)
}

// NewAccessChangesSource adapts Identity&Access's auditor grant surface to
// the access-changes port (T-0027, SPEC-0032 assumption, SPEC-0033): the
// grant lifecycle transitions witnessed within a range, citing the immutable
// audit records that witnessed them. Composing it makes the section live;
// a plane that composes none keeps the SPEC-0031 AC10 degraded shape.
func NewAccessChangesSource(grants identityapi.AuditorGrants) api.AccessChangesSource {
	return identityadapter.NewAccessChangesSource(grants)
}

// NewEvidenceGRPCServer exposes the pack surface over contracts/proto/audit/v1
// — Audit's first RPC door. The adapter translates shapes only; assembly,
// filtering and authorization all happen behind api.PackService.
func NewEvidenceGRPCServer(svc api.PackService) auditv1.EvidenceServiceServer {
	return auditgrpc.NewServer(svc)
}
