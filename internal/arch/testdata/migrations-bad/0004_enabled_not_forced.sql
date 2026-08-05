CREATE TABLE repo.owner_exempt (
  id        TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL
);
ALTER TABLE repo.owner_exempt ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON repo.owner_exempt
  FOR ALL USING (tenant_id = current_setting('app.tenant_id', true));
