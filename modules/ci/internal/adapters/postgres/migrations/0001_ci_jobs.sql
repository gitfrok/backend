-- T-0059 / SPEC-0054 / ADR-0072: the CI job history, made durable.
--
-- Third instance of the shape ADR-0062 addressed for the agent and residency
-- stores and ADR-0071 for the repository registry: a context whose record of
-- what happened lived in a process. Until now `memoryStore` was the only
-- implementation of CI's Store port, so "what has run" did not survive a
-- restart and could not be asked in the first place — Jobs had Enqueue, Get
-- and Cancel and no List.
--
-- What this table deliberately does NOT hold is job output. api.Job's own
-- comment records raw output as a CI implementation detail, PR-11 destroys the
-- sandbox at job end, and ADR-0072 defers log retention to its own decision
-- covering capture, redaction, retention, access and residency. There is no
-- column here for it and adding one is that decision, not a migration.
--
-- RLS follows 0001_tenancy_baseline.sql: enabled and forced, one
-- tenant_isolation policy keyed on tenant_id, failing closed when
-- app.tenant_id is unset.

CREATE SCHEMA IF NOT EXISTS ci;

-- rls: tenant-key=tenant_id
CREATE TABLE IF NOT EXISTS ci.jobs (
  job_id               TEXT        NOT NULL,
  tenant_id            TEXT        NOT NULL,
  attempt_id           TEXT        NOT NULL DEFAULT '',
  repository_id        TEXT        NOT NULL,
  actor_id             TEXT        NOT NULL DEFAULT '',
  ref                  TEXT        NOT NULL DEFAULT '',
  commit_sha           TEXT        NOT NULL DEFAULT '',
  trigger_kind         TEXT        NOT NULL DEFAULT '',
  actor_roles          TEXT[]      NOT NULL DEFAULT '{}',
  state                TEXT        NOT NULL,
  queued_at            TIMESTAMPTZ NOT NULL,
  started_at           TIMESTAMPTZ,
  finished_at          TIMESTAMPTZ,
  configuration_digest TEXT        NOT NULL DEFAULT '',
  outcome_summary      TEXT        NOT NULL DEFAULT '',
  delay_cause          TEXT        NOT NULL DEFAULT '',
  -- The idempotency key CreateOrGet replays against. It is the database's job
  -- rather than a mutex's: the memory adapter held create-or-get atomic under
  -- a lock, and a unique constraint is the same invariant where more than one
  -- process can enqueue.
  idempotency_key      TEXT        NOT NULL,
  PRIMARY KEY (tenant_id, job_id),
  UNIQUE (tenant_id, idempotency_key),
  CHECK (tenant_id <> ''),
  CHECK (job_id <> '')
);

-- The list walks (tenant_id, queued_at DESC, job_id) — newest first, with the
-- job id breaking ties so the ordering is total and a cursor is a position in
-- it rather than an offset into an answer.
CREATE INDEX IF NOT EXISTS jobs_tenant_queued_idx
  ON ci.jobs (tenant_id, queued_at DESC, job_id DESC);

ALTER TABLE ci.jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE ci.jobs FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON ci.jobs;
CREATE POLICY tenant_isolation ON ci.jobs
  FOR ALL
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

-- Minimal grants: the application role records and advances jobs. It does not
-- delete them — a run that happened is a fact, and nothing in the product
-- removes one.
GRANT USAGE ON SCHEMA ci TO gitfrok_app;
GRANT SELECT, INSERT, UPDATE ON ci.jobs TO gitfrok_app;
REVOKE DELETE, TRUNCATE ON ci.jobs FROM gitfrok_app;
