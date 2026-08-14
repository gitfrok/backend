-- T-0025 / SPEC-0029 / SPEC-0030: the Policy context's decision records.
--
-- Every decision the PDP makes is appended here, immutable, with the provenance it was made
-- under: the deciding bundle revision, the digest over the canonicalized input, and the mode
-- (ENFORCED or DRY_RUN). The PRIMARY KEY (tenant_id, decision_id) IS the append-only rule: a
-- decision ID the plane already recorded cannot be re-appended, and no UPDATE or DELETE grant
-- exists for the app role, so a record can never be rewritten after the fact — a decision that
-- could be edited would be worthless as evidence (G5).
--
-- The subject and context columns preserve the question the decision answered, so a dry-run can
-- replay recorded inputs through a candidate bundle (SPEC-0029 AC2). They are decision inputs,
-- not payloads: small string values only, exactly what the decision request carried.
--
-- RLS follows 0001_tenancy_baseline.sql: enabled and forced, one tenant_isolation policy keyed
-- on tenant_id, fail closed when app.tenant_id is unset.

CREATE SCHEMA IF NOT EXISTS policy;

-- rls: tenant-key=tenant_id
CREATE TABLE IF NOT EXISTS policy.decision_records (
  tenant_id         TEXT NOT NULL,
  decision_id       TEXT NOT NULL,
  policy_revision   TEXT NOT NULL,
  input_digest      TEXT NOT NULL,
  mode              TEXT NOT NULL CHECK (mode IN ('ENFORCED', 'DRY_RUN')),
  actor_id          TEXT NOT NULL DEFAULT '',
  action            TEXT NOT NULL,
  resource_type     TEXT NOT NULL DEFAULT '',
  resource_id       TEXT NOT NULL DEFAULT '',
  allowed           BOOLEAN NOT NULL,
  reason            TEXT NOT NULL DEFAULT '',
  subject_tenant_id TEXT NOT NULL DEFAULT '',
  subject_roles     JSONB NOT NULL DEFAULT '[]',
  context           JSONB NOT NULL DEFAULT '{}',
  decided_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  recorded_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, decision_id)
);

ALTER TABLE policy.decision_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy.decision_records FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON policy.decision_records;
CREATE POLICY tenant_isolation ON policy.decision_records
  FOR ALL
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

GRANT USAGE ON SCHEMA policy TO gitfrok_app;
-- Append and read only: a decision record is immutable evidence, so the app role gets no
-- UPDATE and no DELETE here.
GRANT SELECT, INSERT ON policy.decision_records TO gitfrok_app;

-- Dry-run replay reads history oldest-first within (tenant, action, decided_at) bounds.
CREATE INDEX IF NOT EXISTS decision_records_replay ON policy.decision_records
  (tenant_id, action, decided_at);
