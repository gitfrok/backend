-- T-0037 / SPEC-0042: durable, effective-dated residency declarations and
-- the observed-placement registry the declaration-time contradiction check
-- walks.
--
-- PR-22's declaration state becomes a property of the platform rather than
-- of a process (ADR-0062): a declaration recorded before a control-plane
-- kill-and-restart is exactly what the restarted plane cites, and the
-- evidence pack's residency section is reproducible from durable state.
--
-- declarations is APPEND-ONLY and effective-dated: every declare or replace
-- INSERTs a new row and retains the history — the declaration in force at
-- any instant t is the row with the maximum effective_at <= t. There is no
-- UPDATE path and no DELETE path; the grant set makes that a property of the
-- database, not of the adapter.
--
-- The application role may use these tables only inside platform/db's
-- tenant-scoped transactions. There is NO exemption of any kind in this
-- module (SPEC-0042 AC5): the platform's single pre-tenancy exemption lives
-- in the agent module's token lookups; residency never resolves a tenant,
-- it only ever acts within one. No definer-escalated function, no unscoped
-- query path — a test enumerates both absences.

CREATE SCHEMA IF NOT EXISTS residency;

-- rls: tenant-key=tenant_id
CREATE TABLE IF NOT EXISTS residency.declarations (
  tenant_id    TEXT NOT NULL,
  cloud        TEXT NOT NULL,
  region       TEXT NOT NULL,
  -- The server's instant the declaration was witnessed — the instant it
  -- takes effect. "In force at t" is the maximum effective_at <= t.
  effective_at TIMESTAMPTZ NOT NULL,
  actor_id     TEXT NOT NULL,
  -- The chain position of the immutable audit record witnessing the
  -- declaration: unique per tenant because each declaration is its own
  -- witnessed record, and the natural key this append-only table keeps.
  chain_seq    BIGINT NOT NULL,
  record_hash  TEXT NOT NULL,
  PRIMARY KEY (tenant_id, chain_seq)
);

-- The declaration-history read is a range query over the tenant's effective
-- times; the primary key (tenant_id, chain_seq) cannot serve it.
CREATE INDEX IF NOT EXISTS residency_declarations_tenant_effective
  ON residency.declarations (tenant_id, effective_at);

-- rls: tenant-key=tenant_id
CREATE TABLE IF NOT EXISTS residency.observations (
  tenant_id     TEXT NOT NULL,
  data_plane_id TEXT NOT NULL,
  cloud         TEXT NOT NULL,
  region        TEXT NOT NULL,
  -- The instant the control plane last observed this placement; the port's
  -- shape is the latest placement per data plane, so a re-observation
  -- converges the row rather than appending one.
  observed_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, data_plane_id)
);

ALTER TABLE residency.declarations ENABLE ROW LEVEL SECURITY;
ALTER TABLE residency.declarations FORCE ROW LEVEL SECURITY;
ALTER TABLE residency.observations ENABLE ROW LEVEL SECURITY;
ALTER TABLE residency.observations FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON residency.declarations;
CREATE POLICY tenant_isolation ON residency.declarations
  FOR ALL
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

DROP POLICY IF EXISTS tenant_isolation ON residency.observations;
CREATE POLICY tenant_isolation ON residency.observations
  FOR ALL
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

GRANT USAGE ON SCHEMA residency TO gitfrok_app;
-- declarations: SELECT and INSERT only — history is retained by construction
-- because the role has no UPDATE and no DELETE. observations: the latest
-- placement per data plane converges through INSERT ... ON CONFLICT DO
-- UPDATE, so UPDATE is granted there and nowhere else.
GRANT SELECT, INSERT ON residency.declarations TO gitfrok_app;
GRANT SELECT, INSERT, UPDATE ON residency.observations TO gitfrok_app;
REVOKE UPDATE, DELETE, TRUNCATE ON residency.declarations FROM gitfrok_app;
REVOKE DELETE, TRUNCATE ON residency.observations FROM gitfrok_app;
