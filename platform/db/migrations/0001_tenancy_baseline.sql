-- T-0004 / SPEC-0001: the tenant registry and the RLS convention every other table follows.
--
-- Lives under platform/ rather than a module because no single bounded context owns the list of
-- tenants; module-owned tables live in modules/<ctx>/internal/adapters/postgres/migrations/.
--
-- NOT YET APPLIED BY ANYTHING. The dev cluster still builds this schema from
-- deploy/dev/postgres.yaml's init SQL, and there is no migration runner (T-0004 did not add one).
-- This file is the convention plus the lint's subject; keeping the two in step is manual until a
-- runner exists. That duplication is a known gap, recorded in the task rather than hidden.

CREATE SCHEMA IF NOT EXISTS tenant;

-- rls: tenant-key=id
-- The registry is the one table whose primary key *is* the tenant, so its policy keys on id rather
-- than a tenant_id column. Declared for the lint instead of special-cased in it: an exemption a
-- reader can see beats one compiled into the checker.
CREATE TABLE IF NOT EXISTS tenant.tenants (
  id         TEXT PRIMARY KEY,
  name       TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE tenant.tenants ENABLE ROW LEVEL SECURITY;
-- FORCE closes the owner exemption: migrations usually run as the owner, and without this the
-- policy would be silently inert for exactly the role most likely to make a mistake.
ALTER TABLE tenant.tenants FORCE ROW LEVEL SECURITY;

-- missing_ok = true: with app.tenant_id unset current_setting() returns NULL, the predicate is
-- NULL, and RLS reads that as no rows — fail closed (SPEC-0001 AC2).
DROP POLICY IF EXISTS tenant_isolation ON tenant.tenants;
CREATE POLICY tenant_isolation ON tenant.tenants
  FOR ALL
  USING (id = current_setting('app.tenant_id', true))
  WITH CHECK (id = current_setting('app.tenant_id', true));
