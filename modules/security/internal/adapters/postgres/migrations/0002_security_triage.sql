-- T-0023 / SPEC-0026 / SPEC-0027: triage records, triage idempotency, and the
-- repository-level owning-team attribution.
--
-- security.triages is the append-only triage history keyed by the finding's identity: a triage
-- record is a resource of its own, never a field of the finding row (SPEC-0027), and superseding a
-- decision appends a new dense, ascending version rather than mutating the old one (SPEC-0026 AC5).
-- security.triage_requests is the idempotency record per (tenant, finding, request ID)
-- (SPEC-0027 AC1): a redelivery replays the recorded record instead of appending a second one.
-- security.repository_ownership is the v1 owning-team attribution the dashboard facets run under
-- (SPEC-0026); it is fed server-side from Identity & Access, never by reading another context's
-- tables.
--
-- RLS follows 0001_tenancy_baseline.sql: enabled and forced, one tenant_isolation policy keyed on
-- tenant_id, fail closed when app.tenant_id is unset.

-- rls: tenant-key=tenant_id
CREATE TABLE IF NOT EXISTS security.triages (
  tenant_id     TEXT NOT NULL,
  finding_id    TEXT NOT NULL,
  triage_id     TEXT NOT NULL,
  repository_id TEXT NOT NULL,
  state         TEXT NOT NULL CHECK (state IN ('ACCEPT', 'FALSE_POSITIVE', 'FIX', 'DEFER')),
  justification TEXT NOT NULL DEFAULT '',
  -- Dense, ascending versions within the finding's history; the highest is in force.
  version       BIGINT NOT NULL,
  actor_id      TEXT NOT NULL,
  occurred_at   TIMESTAMPTZ NOT NULL,
  recorded_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, finding_id, version)
);

-- rls: tenant-key=tenant_id
CREATE TABLE IF NOT EXISTS security.triage_requests (
  tenant_id   TEXT NOT NULL,
  finding_id  TEXT NOT NULL,
  request_id  TEXT NOT NULL,
  triage_id   TEXT NOT NULL,
  recorded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, finding_id, request_id)
);

-- rls: tenant-key=tenant_id
CREATE TABLE IF NOT EXISTS security.repository_ownership (
  tenant_id     TEXT NOT NULL,
  repository_id TEXT NOT NULL,
  owning_team   TEXT NOT NULL DEFAULT '',
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, repository_id)
);

ALTER TABLE security.triages ENABLE ROW LEVEL SECURITY;
ALTER TABLE security.triages FORCE ROW LEVEL SECURITY;
ALTER TABLE security.triage_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE security.triage_requests FORCE ROW LEVEL SECURITY;
ALTER TABLE security.repository_ownership ENABLE ROW LEVEL SECURITY;
ALTER TABLE security.repository_ownership FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON security.triages;
CREATE POLICY tenant_isolation ON security.triages
  FOR ALL
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

DROP POLICY IF EXISTS tenant_isolation ON security.triage_requests;
CREATE POLICY tenant_isolation ON security.triage_requests
  FOR ALL
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

DROP POLICY IF EXISTS tenant_isolation ON security.repository_ownership;
CREATE POLICY tenant_isolation ON security.repository_ownership
  FOR ALL
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

GRANT USAGE ON SCHEMA security TO gitfrok_app;
GRANT SELECT, INSERT ON security.triages TO gitfrok_app;
GRANT SELECT, INSERT ON security.triage_requests TO gitfrok_app;
GRANT SELECT, INSERT, UPDATE ON security.repository_ownership TO gitfrok_app;
