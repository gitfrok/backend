CREATE TABLE repo.enabled_but_open (
  id        TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL
);
ALTER TABLE repo.enabled_but_open ENABLE ROW LEVEL SECURITY;
ALTER TABLE repo.enabled_but_open FORCE ROW LEVEL SECURITY;
