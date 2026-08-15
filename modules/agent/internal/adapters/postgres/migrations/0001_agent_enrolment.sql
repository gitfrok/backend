-- T-0036 / SPEC-0042: durable enrolment-token store and data-plane registry.
--
-- PR-20's enrolment state becomes a property of the platform rather than of a
-- process (ADR-0062): a spent token stays spent across a control-plane
-- kill-and-restart, a revocation still refuses, and the registry's staleness
-- machine recomputes from durable liveness — never from process uptime.
--
-- The application role may use these tables only inside platform/db's
-- tenant-scoped transactions. The TWO exceptions are named here rather than
-- invented in an adapter (SPEC-0042 AC5): enrolment resolves the tenant FROM
-- the token, so the hash-keyed lookup and claim run before any tenant is
-- known. Each is a fixed, single-purpose SECURITY DEFINER function matching
-- the UNIQUE token-hash column only, returning at most one row; the tenant
-- for everything after is bound from that row, never from the caller. No
-- other path on these tables is exempt, and a test enumerates the exempt set
-- so a new one fails the suite.
--
-- Tokens persist as one-way hashes only — the raw secret is never stored,
-- logged or recoverable (SPEC-0038 AC2, now the store as well as the logs):
-- token_hash BYTEA is the only at-rest form of the credential.

CREATE SCHEMA IF NOT EXISTS agent;

-- rls: tenant-key=tenant_id
CREATE TABLE IF NOT EXISTS agent.enrolment_tokens (
  id            TEXT PRIMARY KEY,
  tenant_id     TEXT NOT NULL,
  issued_by     TEXT NOT NULL,
  -- The token's at-rest identity. UNIQUE makes the exempt lookups return at
  -- most one row by construction; BYTEA carries the 32-byte SHA-256 — never
  -- the raw secret.
  token_hash    BYTEA NOT NULL UNIQUE,
  issued_at     TIMESTAMPTZ NOT NULL,
  expires_at    TIMESTAMPTZ NOT NULL,
  -- Zero while unspent: single-use is durable state, not process memory.
  spent_at      TIMESTAMPTZ,
  -- The data plane the claim minted. Kept when a failed issuance releases the
  -- claim (SPEC-0042 AC6), so any retry re-binds to the SAME identity — one
  -- token never mints two data planes (ADR-0060).
  data_plane_id TEXT NOT NULL DEFAULT '',
  revoked_at    TIMESTAMPTZ
);

-- rls: tenant-key=tenant_id
CREATE TABLE IF NOT EXISTS agent.data_planes (
  tenant_id              TEXT NOT NULL,
  id                     TEXT NOT NULL,
  cloud                  TEXT NOT NULL DEFAULT '',
  region                 TEXT NOT NULL DEFAULT '',
  agent_version          TEXT NOT NULL DEFAULT '',
  k8s_version            TEXT NOT NULL DEFAULT '',
  capabilities           TEXT[] NOT NULL DEFAULT '{}',
  enrolled_at            TIMESTAMPTZ NOT NULL,
  -- Durable liveness: the staleness machine reads this after a restart
  -- exactly as before it (SPEC-0042 AC2).
  last_seen_at           TIMESTAMPTZ NOT NULL,
  current_certificate_id TEXT NOT NULL DEFAULT '',
  certificate_expires_at TIMESTAMPTZ,
  revoked_at             TIMESTAMPTZ,
  PRIMARY KEY (tenant_id, id)
);

ALTER TABLE agent.enrolment_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.enrolment_tokens FORCE ROW LEVEL SECURITY;
ALTER TABLE agent.data_planes ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.data_planes FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON agent.enrolment_tokens;
CREATE POLICY tenant_isolation ON agent.enrolment_tokens
  FOR ALL
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

DROP POLICY IF EXISTS tenant_isolation ON agent.data_planes;
CREATE POLICY tenant_isolation ON agent.data_planes
  FOR ALL
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

-- Exempt path 1 of 2: the pre-tenancy LOOKUP. Read-only, fixed query, matches
-- the UNIQUE token-hash column only and therefore returns at most one row; it
-- yields the tenant the rest of the handshake binds. Clones the shape of
-- identity.resolve_active_credential (ADR-0043). CREATE OR REPLACE (not plain
-- CREATE): the migration is re-applied idempotently and bare CREATE FUNCTION
-- has no IF NOT EXISTS form.
CREATE OR REPLACE FUNCTION agent.lookup_enrolment_token(
  p_token_hash BYTEA
)
RETURNS TABLE (
  id TEXT, tenant_id TEXT, issued_by TEXT, token_hash BYTEA,
  issued_at TIMESTAMPTZ, expires_at TIMESTAMPTZ, spent_at TIMESTAMPTZ,
  data_plane_id TEXT, revoked_at TIMESTAMPTZ
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, agent
AS $$
  SELECT t.id, t.tenant_id, t.issued_by, t.token_hash,
         t.issued_at, t.expires_at, t.spent_at,
         t.data_plane_id, t.revoked_at
    FROM agent.enrolment_tokens AS t
   WHERE t.token_hash = p_token_hash
$$;

-- Exempt path 2 of 2: the pre-tenancy CLAIM. One atomic conditional UPDATE —
-- never a select-then-update — so concurrent presenters cannot both spend the
-- token. Matches the UNIQUE token-hash column only, returns at most one row.
-- A recorded data_plane_id is never overwritten: a claim released after a
-- failed issuance re-binds its retry to the SAME identity (ADR-0060,
-- SPEC-0042 AC6).
CREATE OR REPLACE FUNCTION agent.claim_enrolment_token(
  p_token_hash BYTEA,
  p_data_plane_id TEXT,
  p_now TIMESTAMPTZ
)
RETURNS TABLE (
  id TEXT, tenant_id TEXT, issued_by TEXT, token_hash BYTEA,
  issued_at TIMESTAMPTZ, expires_at TIMESTAMPTZ, spent_at TIMESTAMPTZ,
  data_plane_id TEXT, revoked_at TIMESTAMPTZ
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, agent
AS $$
  UPDATE agent.enrolment_tokens AS t
     SET spent_at = p_now,
         data_plane_id = CASE WHEN t.data_plane_id <> ''
                              THEN t.data_plane_id
                              ELSE p_data_plane_id END
   WHERE t.token_hash = p_token_hash
     AND t.spent_at IS NULL
     AND t.revoked_at IS NULL
     AND t.expires_at > p_now
  RETURNING t.id, t.tenant_id, t.issued_by, t.token_hash,
            t.issued_at, t.expires_at, t.spent_at,
            t.data_plane_id, t.revoked_at
$$;

REVOKE ALL ON FUNCTION agent.lookup_enrolment_token(BYTEA) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION agent.lookup_enrolment_token(BYTEA) TO gitfrok_app;
REVOKE ALL ON FUNCTION agent.claim_enrolment_token(BYTEA, TEXT, TIMESTAMPTZ) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION agent.claim_enrolment_token(BYTEA, TEXT, TIMESTAMPTZ) TO gitfrok_app;

GRANT USAGE ON SCHEMA agent TO gitfrok_app;
GRANT SELECT, INSERT, UPDATE ON agent.enrolment_tokens, agent.data_planes TO gitfrok_app;
REVOKE DELETE, TRUNCATE ON agent.enrolment_tokens, agent.data_planes FROM gitfrok_app;
