-- T-0022 / SPEC-0024 / SPEC-0025: the normalized findings model.
--
-- Two tables: security.scans is the batch state machine (INGESTING -> COMPLETE, one-way), and
-- security.findings is the normalized store deduplicated by the SPEC-0024 identity. The UNIQUE
-- (tenant_id, repository_id, identity) constraint IS the dedup rule: a re-reported defect upserts
-- onto its record rather than creating a second one, and the identity is server-computed before
-- it ever reaches this schema (SPEC-0025 AC3) — the database merely makes a duplicate impossible.
--
-- RLS follows 0001_tenancy_baseline.sql: enabled and forced, one tenant_isolation policy keyed on
-- tenant_id, fail closed when app.tenant_id is unset.

CREATE SCHEMA IF NOT EXISTS security;

-- rls: tenant-key=tenant_id
CREATE TABLE IF NOT EXISTS security.scans (
  id            TEXT PRIMARY KEY,
  tenant_id     TEXT NOT NULL,
  repository_id TEXT NOT NULL,
  scanner_class TEXT NOT NULL,
  tool_name     TEXT NOT NULL,
  tool_version  TEXT NOT NULL DEFAULT '',
  revision      TEXT NOT NULL DEFAULT '',
  started_at    TIMESTAMPTZ NOT NULL,
  ended_at      TIMESTAMPTZ NOT NULL,
  -- One-way state machine: INGESTING while chunks accumulate, COMPLETE once the final chunk
  -- lands. Nothing of the scan is readable before COMPLETE; a COMPLETE scan never re-opens.
  state         TEXT NOT NULL DEFAULT 'INGESTING' CHECK (state IN ('INGESTING', 'COMPLETE')),
  -- Chunks received so far; the next chunk must carry exactly this index (contiguity).
  chunk_count   INT NOT NULL DEFAULT 0,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  completed_at  TIMESTAMPTZ
);

-- rls: tenant-key=tenant_id
CREATE TABLE IF NOT EXISTS security.findings (
  id                    TEXT PRIMARY KEY,
  tenant_id             TEXT NOT NULL,
  repository_id         TEXT NOT NULL,
  -- The SPEC-0024 identity, server-computed. This constraint is the dedup rule.
  identity              TEXT NOT NULL,
  scanner_class         TEXT NOT NULL,
  tool_name             TEXT NOT NULL,
  tool_version          TEXT NOT NULL DEFAULT '',
  rule_id               TEXT NOT NULL,
  severity              TEXT NOT NULL,
  artifact_path         TEXT NOT NULL DEFAULT '',
  enclosing_content     TEXT NOT NULL DEFAULT '',
  component             TEXT NOT NULL DEFAULT '',
  component_version     TEXT NOT NULL DEFAULT '',
  lifecycle             TEXT NOT NULL DEFAULT 'OPEN' CHECK (lifecycle IN ('OPEN', 'RESOLVED')),
  first_seen_scan_id    TEXT NOT NULL,
  last_seen_scan_id     TEXT NOT NULL,
  -- The scanner-native payload, byte-for-byte, never interpreted by the domain (SPEC-0025 AC6).
  provenance            BYTEA NOT NULL DEFAULT ''::bytea,
  provenance_media_type TEXT NOT NULL DEFAULT '',
  created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, repository_id, identity)
);

-- rls: tenant-key=tenant_id
-- Idempotency record per (tenant, scan, chunk, request ID) (SPEC-0025 AC1). A redelivery replays
-- outcome_json — the recorded opened/resolved sets — instead of re-applying, and the service emits
-- no event and no second audit record for a replay.
CREATE TABLE IF NOT EXISTS security.scan_chunks (
  tenant_id          TEXT NOT NULL,
  scan_id            TEXT NOT NULL,
  chunk_index        INT NOT NULL,
  request_id         TEXT NOT NULL,
  findings_recorded  INT NOT NULL,
  completed          BOOLEAN NOT NULL DEFAULT false,
  outcome_json       JSONB NOT NULL DEFAULT '{}'::jsonb,
  recorded_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, scan_id, chunk_index, request_id)
);

-- rls: tenant-key=tenant_id
-- Chunk staging: nothing of a batch is visible to a reader until the final chunk lands
-- (SPEC-0025). Chunks accumulate their findings here; the final chunk's transaction applies the
-- whole set to security.findings and clears the stage, atomically.
CREATE TABLE IF NOT EXISTS security.scan_staged_findings (
  tenant_id             TEXT NOT NULL,
  scan_id               TEXT NOT NULL,
  identity              TEXT NOT NULL,
  rule_id               TEXT NOT NULL,
  severity              TEXT NOT NULL,
  artifact_path         TEXT NOT NULL DEFAULT '',
  enclosing_content     TEXT NOT NULL DEFAULT '',
  component             TEXT NOT NULL DEFAULT '',
  component_version     TEXT NOT NULL DEFAULT '',
  provenance            BYTEA NOT NULL DEFAULT ''::bytea,
  provenance_media_type TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (tenant_id, scan_id, identity)
);

ALTER TABLE security.scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE security.scans FORCE ROW LEVEL SECURITY;
ALTER TABLE security.findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE security.findings FORCE ROW LEVEL SECURITY;
ALTER TABLE security.scan_chunks ENABLE ROW LEVEL SECURITY;
ALTER TABLE security.scan_chunks FORCE ROW LEVEL SECURITY;
ALTER TABLE security.scan_staged_findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE security.scan_staged_findings FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON security.scans;
CREATE POLICY tenant_isolation ON security.scans
  FOR ALL
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

DROP POLICY IF EXISTS tenant_isolation ON security.findings;
CREATE POLICY tenant_isolation ON security.findings
  FOR ALL
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

DROP POLICY IF EXISTS tenant_isolation ON security.scan_chunks;
CREATE POLICY tenant_isolation ON security.scan_chunks
  FOR ALL
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

DROP POLICY IF EXISTS tenant_isolation ON security.scan_staged_findings;
CREATE POLICY tenant_isolation ON security.scan_staged_findings
  FOR ALL
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

GRANT USAGE ON SCHEMA security TO gitfrok_app;
GRANT SELECT, INSERT, UPDATE ON security.scans TO gitfrok_app;
GRANT SELECT, INSERT, UPDATE ON security.findings TO gitfrok_app;
GRANT SELECT, INSERT ON security.scan_chunks TO gitfrok_app;
GRANT SELECT, INSERT, DELETE ON security.scan_staged_findings TO gitfrok_app;

CREATE INDEX IF NOT EXISTS findings_list ON security.findings
  (tenant_id, repository_id, scanner_class, severity, lifecycle, id);
