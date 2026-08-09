-- T-0013 / ADR-0043: tenant-scoped Identity&Access credential state.
--
-- The application role may use these tables only inside platform/db's tenant-scoped
-- transactions. The one exception is resolve_active_credential: a fixed, read-only
-- SECURITY DEFINER resolver for an opaque credential before authentication has
-- established a tenant. It returns only a verified principal tuple.

CREATE SCHEMA IF NOT EXISTS identity;

CREATE TABLE IF NOT EXISTS identity.principals (
  tenant_id   TEXT NOT NULL,
  actor_id    TEXT NOT NULL,
  active      BOOLEAN NOT NULL DEFAULT true,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, actor_id)
);

CREATE TABLE IF NOT EXISTS identity.memberships (
  tenant_id   TEXT NOT NULL,
  actor_id    TEXT NOT NULL,
  role        TEXT NOT NULL,
  active      BOOLEAN NOT NULL DEFAULT true,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, actor_id, role),
  FOREIGN KEY (tenant_id, actor_id) REFERENCES identity.principals (tenant_id, actor_id)
);

CREATE TABLE IF NOT EXISTS identity.credentials (
  id              TEXT PRIMARY KEY,
  tenant_id       TEXT NOT NULL,
  actor_id        TEXT NOT NULL,
  credential_kind TEXT NOT NULL CHECK (credential_kind IN ('PAT', 'SSH')),
  key_id          TEXT NOT NULL,
  verifier        TEXT NOT NULL,
  label           TEXT NOT NULL DEFAULT '',
  scope_labels    TEXT[] NOT NULL DEFAULT '{}',
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at      TIMESTAMPTZ,
  revoked_at      TIMESTAMPTZ,
  FOREIGN KEY (tenant_id, actor_id) REFERENCES identity.principals (tenant_id, actor_id),
  UNIQUE (credential_kind, key_id, verifier)
);

CREATE INDEX IF NOT EXISTS credentials_active_lookup
  ON identity.credentials (credential_kind, key_id, verifier)
  WHERE revoked_at IS NULL;

ALTER TABLE identity.principals ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity.principals FORCE ROW LEVEL SECURITY;
ALTER TABLE identity.memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity.memberships FORCE ROW LEVEL SECURITY;
ALTER TABLE identity.credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity.credentials FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON identity.principals;
CREATE POLICY tenant_isolation ON identity.principals
  FOR ALL
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

DROP POLICY IF EXISTS tenant_isolation ON identity.memberships;
CREATE POLICY tenant_isolation ON identity.memberships
  FOR ALL
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

DROP POLICY IF EXISTS tenant_isolation ON identity.credentials;
CREATE POLICY tenant_isolation ON identity.credentials
  FOR ALL
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

-- The only unauthenticated credential read. The fixed query has no dynamic SQL,
-- accepts no tenant/routing claim and returns no verifier or credential metadata.
CREATE FUNCTION identity.resolve_active_credential(
  p_kind TEXT,
  p_key_id TEXT,
  p_verifier TEXT
)
RETURNS TABLE (tenant_id TEXT, actor_id TEXT, roles TEXT[])
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, identity
AS $$
  SELECT c.tenant_id,
         c.actor_id,
         array_agg(m.role ORDER BY m.role)
    FROM identity.credentials AS c
    JOIN identity.principals AS p
      ON p.tenant_id = c.tenant_id AND p.actor_id = c.actor_id
    JOIN identity.memberships AS m
      ON m.tenant_id = c.tenant_id AND m.actor_id = c.actor_id
   WHERE c.credential_kind = p_kind
     AND c.key_id = p_key_id
     AND c.verifier = p_verifier
     AND c.revoked_at IS NULL
     AND (c.expires_at IS NULL OR c.expires_at > now())
     AND p.active
     AND m.active
   GROUP BY c.tenant_id, c.actor_id
$$;

REVOKE ALL ON FUNCTION identity.resolve_active_credential(TEXT, TEXT, TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.resolve_active_credential(TEXT, TEXT, TEXT) TO gitfrok_app;

GRANT USAGE ON SCHEMA identity TO gitfrok_app;
GRANT SELECT, INSERT, UPDATE ON identity.principals, identity.memberships, identity.credentials TO gitfrok_app;
REVOKE DELETE, TRUNCATE ON identity.principals, identity.memberships, identity.credentials FROM gitfrok_app;
