-- T-0053 / SPEC-0052 / ADR-0071: the repository registry, made durable.
--
-- This is the adapter the Repository context has been owed since T-0004. Its
-- in-memory store's own header says so, and until now the registry recording
-- WHICH repositories exist was a map that emptied on restart, while the
-- repositories themselves are bare git repositories on block volumes
-- (ADR-0033) that do not.
--
-- That survived because no surface read the registry as a list: every one took
-- a repository ID and asked about that one, so an empty registry produced a
-- not-found for a specific request — which SPEC-0001 wants to be
-- indistinguishable from unauthorized anyway. A LIST is different. One that
-- omits a repository asserts it does not exist, to a caller who may be looking
-- straight at its clone URL.
--
-- The registry is the product's truth for existence (ADR-0071 decision 2): a
-- bare repository on disk with no row here is absent from the product's
-- surfaces by consequence, not by defect. Nothing reconciles storage into this
-- table, deliberately — a backfill would make the product assert tenancy,
-- ownership and naming nobody told it (decision 3).
--
-- RLS follows 0001_tenancy_baseline.sql: enabled and forced, one
-- tenant_isolation policy keyed on tenant_id, failing closed when
-- app.tenant_id is unset.

CREATE SCHEMA IF NOT EXISTS repo;

-- rls: tenant-key=tenant_id
CREATE TABLE IF NOT EXISTS repo.repositories (
  tenant_id   TEXT        NOT NULL,
  repo_id     TEXT        NOT NULL,
  name        TEXT        NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  -- The identity is (tenant, repo): a repository ID is unique within a tenant
  -- and says nothing across tenants, so the same ID in two tenants is two
  -- different repositories and neither can observe the other (invariant 1).
  PRIMARY KEY (tenant_id, repo_id),
  CHECK (tenant_id <> ''),
  CHECK (repo_id <> ''),
  CHECK (name <> '')
);

-- The list's only ordering. Paging walks (tenant_id, repo_id) ascending, so a
-- cursor is the last repo_id seen and nothing about position or totals has to
-- be encoded into it — which is what keeps the response free of any field
-- capable of expressing how many repositories the caller may not see
-- (SPEC-0052 AC5).
CREATE INDEX IF NOT EXISTS repositories_tenant_id_repo_id_idx
  ON repo.repositories (tenant_id, repo_id);

ALTER TABLE repo.repositories ENABLE ROW LEVEL SECURITY;
ALTER TABLE repo.repositories FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON repo.repositories;
CREATE POLICY tenant_isolation ON repo.repositories
  FOR ALL
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

-- Minimal grants. The application role registers and reads repositories; it
-- does not delete them. There is no product path that removes a repository
-- (repository settings and archival are Tier C, PR-30), so the grant set says
-- so rather than leaving the capability lying around.
GRANT USAGE ON SCHEMA repo TO gitfrok_app;
GRANT SELECT, INSERT, UPDATE ON repo.repositories TO gitfrok_app;
REVOKE DELETE, TRUNCATE ON repo.repositories FROM gitfrok_app;
