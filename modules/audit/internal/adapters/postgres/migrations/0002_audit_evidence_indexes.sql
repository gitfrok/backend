-- T-0026 / SPEC-0032: read-side indexes for the evidence-pack trail queries.
--
-- Evidence-pack assembly queries the tenant's chain by date range, and the access-changes
-- classification filters by action inside that range. Without help, both walk the whole
-- tenant's rows on every pack request. These two indexes carry those reads.
--
-- This migration is READ-ONLY in the load-bearing sense 0001 establishes: it creates indexes
-- and nothing else. Index creation needs no UPDATE grant, touches no row, and leaves the
-- append-only property of audit.entries — the INSERT/SELECT-only grants, the reject_mutation
-- trigger, and the sealing exception — exactly as 0001 defined it. IF NOT EXISTS keeps the
-- migration re-runnable without touching an existing index.

CREATE INDEX IF NOT EXISTS entries_tenant_occurred_idx
  ON audit.entries (tenant_id, occurred_at);

CREATE INDEX IF NOT EXISTS entries_tenant_action_occurred_idx
  ON audit.entries (tenant_id, action, occurred_at);
