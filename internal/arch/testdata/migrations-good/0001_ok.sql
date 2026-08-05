CREATE TABLE repo.repositories (
  id        TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  name      TEXT NOT NULL
);
ALTER TABLE repo.repositories ENABLE ROW LEVEL SECURITY;
ALTER TABLE repo.repositories FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON repo.repositories
  FOR ALL USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

-- rls: not-tenant-owned
CREATE TABLE repo.supported_hash_algorithms (
  name TEXT PRIMARY KEY
);
