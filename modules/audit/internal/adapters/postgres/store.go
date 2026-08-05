// Package postgres persists the audit trail.
//
// Append and Verify only. There is no Update, no Delete, and no method that could be extended into
// one without also changing the database grants — which is the point: SPEC-0003 AC1 is a property of
// the store, not a rule the store follows.
package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/gitfrok/backend/modules/audit/api"
	"github.com/gitfrok/backend/modules/audit/internal/domain"
	"github.com/gitfrok/backend/platform/db"
	"github.com/gitfrok/backend/platform/tenancy"
)

// tenantOf reads the scope the surrounding transaction was opened with. InTx has already required
// it, so the empty case is unreachable here; it is handled rather than asserted because a panic in
// the audit path would suppress the very record it was writing.
func tenantOf(ctx context.Context) tenancy.ID {
	id, _ := tenancy.FromContext(ctx)
	return id
}

// Store is the Postgres-backed audit log.
type Store struct {
	pool *db.Pool
}

// New returns a Store over pool. The pool scopes every transaction to a tenant, so the audit trail
// inherits SPEC-0001's isolation without restating it: one tenant's investigators cannot read
// another's incidents.
func New(pool *db.Pool) *Store { return &Store{pool: pool} }

// Append writes one entry and returns it as persisted.
//
// The hash is computed here, from the sequence number the database assigned, and never taken from
// the caller — a producer able to state its own position in the chain could also lie about it.
// Everything happens in one transaction, so a crash cannot leave a record whose predecessor's hash
// was read but whose own row never landed.
func (s *Store) Append(ctx context.Context, e api.Entry) (api.Record, error) {
	var rec api.Record
	err := s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		// Appends are serialised with a transaction-scoped advisory lock keyed on the tenant.
		//
		// The obvious alternative, SELECT ... FOR UPDATE on the chain head, cannot be used here and
		// the reason is instructive: row locking requires the UPDATE privilege, which this table
		// deliberately does not grant (AC1). An append-only table cannot lock its own rows. The
		// advisory lock needs no table privileges at all, and it is the stronger choice anyway —
		// locking the head row would not stop two transactions that both read the head before
		// either inserted, which is exactly the fork it was supposed to prevent.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`,
			"audit.entries:"+string(tenantOf(ctx))); err != nil {
			return fmt.Errorf("audit: serialise append: %w", err)
		}

		// The head of *this tenant's* chain, and its position. Both come from the same scoped read,
		// so the new record's tenant_seq follows the one it chains onto rather than a global counter
		// that other tenants advance.
		var prevHash string
		var prevSeq int64
		err := tx.QueryRow(ctx,
			`SELECT hash, tenant_seq FROM audit.entries ORDER BY tenant_seq DESC LIMIT 1`).
			Scan(&prevHash, &prevSeq)
		if err != nil && err != pgx.ErrNoRows {
			return fmt.Errorf("audit: read chain head: %w", err)
		}
		tenantSeq := prevSeq + 1

		detail, err := json.Marshal(e.Detail)
		if err != nil {
			return fmt.Errorf("audit: encode detail: %w", err)
		}

		// The row is inserted first so the database assigns seq, then the hash is written over it in
		// the same transaction. Two statements rather than one because the hash must cover the
		// assigned sequence number, and BIGSERIAL does not hand it over until the INSERT runs.
		var seq int64
		err = tx.QueryRow(ctx,
			`INSERT INTO audit.entries
			   (tenant_id, tenant_seq, action, actor_id, resource, outcome, detail, occurred_at,
			    prev_hash, hash)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'')
			 RETURNING seq`,
			e.TenantID, tenantSeq, string(e.Action), e.ActorID, e.Resource, string(e.Outcome),
			detail, e.OccurredAt, prevHash).Scan(&seq)
		if err != nil {
			return fmt.Errorf("audit: append: %w", err)
		}

		f := domain.Fields{
			Seq: tenantSeq, TenantID: e.TenantID, Action: string(e.Action), ActorID: e.ActorID,
			Resource: e.Resource, Outcome: string(e.Outcome), Detail: e.Detail, OccurredAt: e.OccurredAt,
		}
		hash := domain.Hash(prevHash, f)

		// UPDATE is not granted to the application role, so this runs through a SECURITY DEFINER
		// helper that may only ever set the hash of a row whose hash is still empty. That keeps
		// "no update path" true for every other column and every already-hashed row.
		if _, err := tx.Exec(ctx, `SELECT audit.set_entry_hash($1, $2)`, seq, hash); err != nil {
			return fmt.Errorf("audit: seal entry %d: %w", seq, err)
		}

		rec = api.Record{
			Seq: tenantSeq, TenantID: e.TenantID, Action: e.Action, ActorID: e.ActorID,
			Resource: e.Resource, Outcome: e.Outcome, Detail: e.Detail, OccurredAt: e.OccurredAt,
			PrevHash: prevHash, Hash: hash,
		}
		return nil
	})
	return rec, err
}

// Verify walks the tenant's chain in order and reports the first fault.
func (s *Store) Verify(ctx context.Context) (api.VerifyResult, error) {
	var res api.VerifyResult
	err := s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT tenant_seq, tenant_id, action, actor_id, resource, outcome, detail, occurred_at,
			        prev_hash, hash
			   FROM audit.entries ORDER BY tenant_seq ASC`)
		if err != nil {
			return fmt.Errorf("audit: read chain: %w", err)
		}
		defer rows.Close()

		var links []domain.Link
		for rows.Next() {
			var l domain.Link
			var detail []byte
			if err := rows.Scan(&l.Fields.Seq, &l.Fields.TenantID, &l.Fields.Action, &l.Fields.ActorID,
				&l.Fields.Resource, &l.Fields.Outcome, &detail, &l.Fields.OccurredAt,
				&l.PrevHash, &l.Hash); err != nil {
				return fmt.Errorf("audit: scan: %w", err)
			}
			if err := json.Unmarshal(detail, &l.Fields.Detail); err != nil {
				return fmt.Errorf("audit: decode detail at seq %d: %w", l.Fields.Seq, err)
			}
			links = append(links, l)
		}
		if err := rows.Err(); err != nil {
			return err
		}

		ok, brokenAt, reason := domain.VerifyChain(links)
		res = api.VerifyResult{
			Checked: int64(len(links)), OK: ok, BrokenAtSeq: brokenAt, Reason: reason,
		}
		return nil
	})
	return res, err
}
