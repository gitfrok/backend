-- T-0027 / SPEC-0033: scoped, read-only, time-boxed auditor grants.
--
-- Two tables: identity.auditor_grants is the grant record (scope and expiry
-- only — no repository permission, no role list, no renewal-on-use), and
-- identity.auditor_grant_transitions is the witnessed lifecycle journal
-- citing the immutable audit records that make the grant lifecycle itself
-- accountability evidence (SPEC-0033 AC4). The UNIQUE (tenant_id, request_id)
-- constraint IS the idempotency rule: replaying an issue request returns the
-- existing grant rather than creating a second one, and the UNIQUE
-- (tenant_id, grant_id, kind) constraint IS the exactly-once transition rule.
--
-- State is deliberately NOT stored: revocation is the revoked_at fact, and
-- expiry is the server's rendering of its own clock at read time — a grant
-- expires without an operator action because no stored state has to move for
-- it to take effect (SPEC-0033 AC3/AC7).
--
-- RLS follows 0001_tenancy_baseline.sql: enabled and forced, one
-- tenant_isolation policy keyed on tenant_id, fail closed when
-- app.tenant_id is unset.

-- rls: tenant-key=tenant_id
CREATE TABLE IF NOT EXISTS identity.auditor_grants (
  grant_id             TEXT PRIMARY KEY,
  tenant_id            TEXT NOT NULL,
  auditor_principal_id TEXT NOT NULL,
  range_from           TIMESTAMPTZ NOT NULL,
  range_to             TIMESTAMPTZ NOT NULL,
  -- Optional repository scope narrowing which packs the grant may name; empty
  -- covers the tenant's repositories. It is NOT a repository permission.
  repository_id        TEXT NOT NULL DEFAULT '',
  pack_ids             TEXT[] NOT NULL,
  expires_at           TIMESTAMPTZ NOT NULL,
  granted_by           TEXT NOT NULL,
  issued_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at           TIMESTAMPTZ,
  -- The idempotency key an issue request replays against. Empty request IDs
  -- are excluded from the uniqueness rule: a request without an ID cannot
  -- replay, only issue.
  request_id           TEXT NOT NULL DEFAULT '',
  CHECK (range_from <= range_to),
  CHECK (cardinality(pack_ids) > 0)
);

CREATE UNIQUE INDEX IF NOT EXISTS auditor_grant_issue_replay
  ON identity.auditor_grants (tenant_id, request_id)
  WHERE request_id <> '';

CREATE INDEX IF NOT EXISTS auditor_grant_principal_lookup
  ON identity.auditor_grants (tenant_id, auditor_principal_id, issued_at);

-- The transition journal's foreign key references the tenant-scoped pair, so
-- the pair must carry a uniqueness constraint of its own.
CREATE UNIQUE INDEX IF NOT EXISTS auditor_grant_tenant_key
  ON identity.auditor_grants (tenant_id, grant_id);

-- rls: tenant-key=tenant_id
-- One row per witnessed lifecycle transition, citing the immutable audit
-- record (chain_seq, record_hash) that witnessed it. Exactly one transition
-- per (tenant, grant, kind): an expiry observed twice is still one expiry.
CREATE TABLE IF NOT EXISTS identity.auditor_grant_transitions (
  tenant_id            TEXT NOT NULL,
  grant_id             TEXT NOT NULL,
  kind                 TEXT NOT NULL CHECK (kind IN ('ISSUED', 'REVOKED', 'EXPIRED')),
  actor_id             TEXT NOT NULL DEFAULT '',
  granted_by           TEXT NOT NULL,
  auditor_principal_id TEXT NOT NULL,
  repository_id        TEXT NOT NULL DEFAULT '',
  decision_id          TEXT NOT NULL DEFAULT '',
  chain_seq            BIGINT NOT NULL,
  record_hash          TEXT NOT NULL,
  occurred_at          TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, grant_id, kind),
  FOREIGN KEY (tenant_id, grant_id)
    REFERENCES identity.auditor_grants (tenant_id, grant_id)
);

CREATE INDEX IF NOT EXISTS auditor_grant_transition_range
  ON identity.auditor_grant_transitions (tenant_id, occurred_at, chain_seq);

ALTER TABLE identity.auditor_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity.auditor_grants FORCE ROW LEVEL SECURITY;
ALTER TABLE identity.auditor_grant_transitions ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity.auditor_grant_transitions FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON identity.auditor_grants;
CREATE POLICY tenant_isolation ON identity.auditor_grants
  FOR ALL
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

DROP POLICY IF EXISTS tenant_isolation ON identity.auditor_grant_transitions;
CREATE POLICY tenant_isolation ON identity.auditor_grant_transitions
  FOR ALL
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

-- Minimal grants: the application role inserts grants and transitions and
-- revokes via UPDATE; it never deletes a lifecycle record.
GRANT USAGE ON SCHEMA identity TO gitfrok_app;
GRANT SELECT, INSERT, UPDATE ON identity.auditor_grants TO gitfrok_app;
GRANT SELECT, INSERT ON identity.auditor_grant_transitions TO gitfrok_app;
REVOKE DELETE, TRUNCATE ON identity.auditor_grants, identity.auditor_grant_transitions FROM gitfrok_app;
