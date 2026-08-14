-- T-0024 / SPEC-0028: the durable per-scan reported set.
--
-- Attribution compares what a merge request's head revision reports against what its merge base
-- reports, by SPEC-0024 identity. That comparison needs each scan's reported set as a durable
-- fact of the scan: security.findings.last_seen_scan_id moves on whenever a later scan
-- re-reports an identity, so it cannot stand in for what an EARLIER scan reported. This table
-- records, at the moment a scan completes, every identity it reported joined to the finding row
-- recorded for it — the same transaction that applies the scan's staged set, so a scan's
-- reported set is as atomic as the scan itself.
--
-- RLS follows 0001_tenancy_baseline.sql: enabled and forced, one tenant_isolation policy keyed on
-- tenant_id, fail closed when app.tenant_id is unset.

-- rls: tenant-key=tenant_id
CREATE TABLE IF NOT EXISTS security.scan_report (
  tenant_id   TEXT NOT NULL,
  scan_id     TEXT NOT NULL,
  identity    TEXT NOT NULL,
  finding_id  TEXT NOT NULL,
  recorded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, scan_id, identity)
);

ALTER TABLE security.scan_report ENABLE ROW LEVEL SECURITY;
ALTER TABLE security.scan_report FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON security.scan_report;
CREATE POLICY tenant_isolation ON security.scan_report
  FOR ALL
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

GRANT SELECT, INSERT ON security.scan_report TO gitfrok_app;
