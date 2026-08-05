// Package db is the tenant-scoped data-access layer.
//
// Every query the application makes goes through InTx, which opens a transaction, pins it to the
// request's tenant with `SET LOCAL app.tenant_id`, and only then hands over a connection. The RLS
// policies in the database read that setting; nothing else grants access.
//
// The two halves are independent on purpose, because SPEC-0001 asks for both (AC1 and AC2):
//
//   - The application refuses to run an unscoped query at all — InTx returns ErrNoTenant before it
//     touches the database.
//   - If application code ever bypasses this package, the database still fails closed:
//     `current_setting('app.tenant_id', true)` is NULL, the policy predicate is NULL, and Postgres
//     reads that as no rows. Defence in depth is the point — one of these being enough is not a
//     reason to have only one (ADR-0003, invariant 1).
//
// SPEC-0001, T-0004.
package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/gitfrok/backend/platform/audit"
	"github.com/gitfrok/backend/platform/bus"
	"github.com/gitfrok/backend/platform/tenancy"
)

// sqlStateInsufficientPrivilege is what Postgres returns when a row-level security policy refuses a
// write ("new row violates row-level security policy"). It is the only signal the application gets
// that a cross-tenant write was *attempted* rather than simply matching nothing.
const sqlStateInsufficientPrivilege = "42501"

// ErrNoTenant is re-exported so callers need not import tenancy to check the denial they will
// actually see from this package.
var ErrNoTenant = tenancy.ErrNoTenant

// Pool is a tenant-scoped handle on Postgres. It wraps pgxpool rather than embedding it: an
// embedded pool would expose Query and Exec directly, and any caller reaching those bypasses the
// scoping this type exists to enforce. Making the unscoped path unreachable beats documenting it.
type Pool struct {
	pool  *pgxpool.Pool
	audit bus.Bus // optional; nil means violations are still rejected, just not audited
	now   func() time.Time
}

// WithAuditBus routes rejected cross-tenant writes to b as audit events (SPEC-0001 AC3).
//
// Optional rather than required so that Open stays usable in tooling that has no bus, and because a
// missing audit sink must never turn a *rejection* into an *acceptance*: isolation is enforced by
// the database, and auditing observes it. Wiring belongs in cmd/ (ADR-0025).
func (p *Pool) WithAuditBus(b bus.Bus) *Pool {
	p.audit = b
	return p
}

// Open connects using dsn. The connection must NOT be a superuser or hold BYPASSRLS: those bypass
// every policy silently, so the isolation tests would pass against a database that enforces nothing.
// Verified at open time rather than trusted, because it is the single assumption everything else
// rests on.
func Open(ctx context.Context, dsn string) (*Pool, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("db: connect: %w", err)
	}

	var super, bypass bool
	err = pool.QueryRow(ctx,
		`SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user`,
	).Scan(&super, &bypass)
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("db: check current_user privileges: %w", err)
	}
	if super || bypass {
		pool.Close()
		return nil, fmt.Errorf(
			"db: refusing to use a role with SUPERUSER=%t BYPASSRLS=%t — RLS would not apply "+
				"and tenant isolation would be unenforced (SPEC-0001, ADR-0003)", super, bypass)
	}
	return &Pool{pool: pool, now: time.Now}, nil
}

// Close releases the pool.
func (p *Pool) Close() {
	if p != nil && p.pool != nil {
		p.pool.Close()
	}
}

// InTx runs fn inside a transaction scoped to the tenant in ctx.
//
// SET LOCAL, not SET: the setting is reverted when the transaction ends, so a pooled connection
// cannot carry one request's tenant into the next request that borrows it. That leak would be
// invisible in tests that use a fresh connection per case, and catastrophic in production.
func (p *Pool) InTx(ctx context.Context, fn func(context.Context, pgx.Tx) error) error {
	tenant, err := tenancy.Require(ctx)
	if err != nil {
		// Deliberately before any database work: an unscoped query must not reach Postgres even to
		// be denied there (SPEC-0001 AC2).
		return err
	}

	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("db: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after a successful Commit

	// SET LOCAL takes no bind parameters, which is why tenancy.Validate restricts the ID to
	// [A-Za-z0-9_-]: quote_literal would also work, but a validated alphabet removes the question.
	if _, err := tx.Exec(ctx, fmt.Sprintf("SET LOCAL app.tenant_id = '%s'", tenant)); err != nil {
		return fmt.Errorf("db: scope tx to tenant %s: %w", tenant, err)
	}

	if err := fn(ctx, tx); err != nil {
		// Audited after the deferred rollback is guaranteed to run, and regardless of whether the
		// bus accepts it: an audit sink that is down must not convert a denied write into a
		// returned success (SPEC-0001 AC3, ADR-0007).
		p.auditIfIsolationViolation(ctx, tenant, err)
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("db: commit: %w", err)
	}
	return nil
}

// auditIfIsolationViolation emits an audit event when err is Postgres refusing a write under an RLS
// policy.
//
// KNOWN LIMIT, and it is inherent rather than an oversight: RLS makes another tenant's rows
// *invisible*, so a cross-tenant UPDATE or DELETE matches nothing and succeeds with zero rows
// affected — there is no error to detect and nothing to audit. Only writes that trip a policy's
// WITH CHECK (an INSERT, or an UPDATE moving a row out of scope) surface as 42501. Auditing the
// silent case would mean the caller declaring intent, which is a change to every call site and is
// not what SPEC-0001 asks for. Recorded in T-0004 rather than left for someone to discover.
func (p *Pool) auditIfIsolationViolation(ctx context.Context, tenant tenancy.ID, err error) {
	if p.audit == nil {
		return
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != sqlStateInsufficientPrivilege {
		return
	}
	_ = p.audit.Publish(ctx, audit.TenantIsolationViolation{
		TenantID:   string(tenant),
		Operation:  pgErr.Routine,
		SQLState:   pgErr.Code,
		Detail:     pgErr.Message,
		OccurredAt: p.now(),
	})
}

// InTxUnscoped runs fn without a tenant scope, for migrations and operator tooling that legitimately
// span tenants.
//
// It exists because the alternative is worse: without a named, greppable escape hatch, whoever needs
// one reaches for the raw pool and the scoped path stops being the only path. Every call site is a
// deliberate exception and should say why. It is NOT a fallback for "no tenant in context" — that is
// a denial (AC2), and this function will not save a caller who forgot to scope.
func (p *Pool) InTxUnscoped(ctx context.Context, reason string, fn func(context.Context, pgx.Tx) error) error {
	if reason == "" {
		return errors.New("db: InTxUnscoped requires a reason — an unexplained cross-tenant query is a bug")
	}
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("db: begin (unscoped: %s): %w", reason, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := fn(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("db: commit (unscoped: %s): %w", reason, err)
	}
	return nil
}
