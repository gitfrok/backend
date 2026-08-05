-- T-0006 / SPEC-0003: the audit trail.
--
-- AC1 (append-only) and AC4 (a separate store) are both enforced here rather than in Go, because a
-- Go-side rule protects only callers who go through Go. A dedicated schema plus INSERT/SELECT-only
-- grants means even a psql session holding the application's credentials cannot rewrite history.

CREATE SCHEMA IF NOT EXISTS audit;

-- AC4: its own schema, separate from any operational/telemetry store. Observability data is
-- sampled, rotated and dropped; an audit trail is none of those things, and mixing them means the
-- retention policy of the noisiest one wins.
CREATE TABLE IF NOT EXISTS audit.entries (
  -- Physical insertion order across all tenants. Useful for operators; NOT what the chain uses.
  seq         BIGSERIAL PRIMARY KEY,
  tenant_id   TEXT NOT NULL,
  -- The chain's position, counted per tenant.
  --
  -- This has to be per tenant, and the reason is easy to get wrong: reads are RLS-scoped, so a
  -- verifier only ever sees its own tenant's rows. Against a global sequence those rows are
  -- non-contiguous — 7, 19, 24 — and gap detection reports a deletion on every trail that is not
  -- the only writer in the database. The bug is invisible when one tenant writes alone, which is
  -- exactly how it survives testing.
  tenant_seq  BIGINT NOT NULL,
  action      TEXT NOT NULL,
  actor_id    TEXT NOT NULL DEFAULT '',
  resource    TEXT NOT NULL DEFAULT '',
  outcome     TEXT NOT NULL,
  detail      JSONB NOT NULL DEFAULT '{}'::jsonb,
  occurred_at TIMESTAMPTZ NOT NULL,
  prev_hash   TEXT NOT NULL DEFAULT '',
  hash        TEXT NOT NULL,
  -- Two records cannot occupy the same position in one tenant's chain. The append path serialises
  -- on an advisory lock; this makes a fork impossible rather than merely unlikely.
  UNIQUE (tenant_id, tenant_seq)
);

ALTER TABLE audit.entries ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit.entries FORCE ROW LEVEL SECURITY;

-- Tenant isolation applies to the audit trail too (invariant 1): one tenant's investigators must not
-- read another's incidents. SPEC-0001's convention, unchanged.
DROP POLICY IF EXISTS tenant_isolation ON audit.entries;
CREATE POLICY tenant_isolation ON audit.entries
  FOR ALL
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

-- AC1, the part that actually holds: no UPDATE, no DELETE, no TRUNCATE for the application role.
-- Verification needs SELECT; appending needs INSERT and the sequence. Nothing else is granted, so
-- "there is no update/delete path" is a property of the database rather than a convention in code.
GRANT USAGE ON SCHEMA audit TO gitfrok_app;
GRANT INSERT, SELECT ON audit.entries TO gitfrok_app;
GRANT USAGE, SELECT ON SEQUENCE audit.entries_seq_seq TO gitfrok_app;
REVOKE UPDATE, DELETE, TRUNCATE ON audit.entries FROM gitfrok_app;

-- Belt and braces: a rule that rejects UPDATE and DELETE even if a future migration grants them by
-- accident. The grant above is the primary control; this makes a mistake loud instead of silent.
CREATE OR REPLACE FUNCTION audit.reject_mutation() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'audit.entries is append-only (SPEC-0003 AC1, ADR-0007)';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS no_update ON audit.entries;
CREATE TRIGGER no_update BEFORE UPDATE ON audit.entries
  FOR EACH ROW EXECUTE FUNCTION audit.reject_mutation();

DROP TRIGGER IF EXISTS no_delete ON audit.entries;
CREATE TRIGGER no_delete BEFORE DELETE ON audit.entries
  FOR EACH ROW EXECUTE FUNCTION audit.reject_mutation();

-- The one narrow exception to "no UPDATE", and it is deliberately not a general one.
--
-- A record's hash must cover the sequence number, and BIGSERIAL does not assign that until the row
-- is inserted — so the row is written, then sealed, inside one transaction. The application role has
-- no UPDATE grant, so sealing runs through this SECURITY DEFINER function instead.
--
-- Three conditions keep it from becoming an update path: it touches only the `hash` column, only
-- where the hash is still empty (so a sealed record can never be re-sealed), and only within the
-- caller's own tenant. A second call for the same seq changes nothing.
CREATE OR REPLACE FUNCTION audit.set_entry_hash(p_seq BIGINT, p_hash TEXT)
RETURNS void AS $$
BEGIN
  UPDATE audit.entries
     SET hash = p_hash
   WHERE seq = p_seq
     AND hash = ''
     AND tenant_id = current_setting('app.tenant_id', true);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- The reject_mutation trigger above would otherwise block the seal, since it fires on every UPDATE.
-- Re-created here to allow exactly the sealing transition and nothing else: any other UPDATE, and
-- any attempt to change an already-hashed row, still raises.
CREATE OR REPLACE FUNCTION audit.reject_mutation() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'UPDATE'
     AND OLD.hash = ''
     AND NEW.hash <> ''
     AND NEW.seq = OLD.seq
     AND NEW.tenant_seq = OLD.tenant_seq
     AND NEW.tenant_id = OLD.tenant_id
     AND NEW.action = OLD.action
     AND NEW.actor_id = OLD.actor_id
     AND NEW.resource = OLD.resource
     AND NEW.outcome = OLD.outcome
     AND NEW.detail = OLD.detail
     AND NEW.occurred_at = OLD.occurred_at
     AND NEW.prev_hash = OLD.prev_hash THEN
    RETURN NEW;  -- the sealing write, and only that
  END IF;
  RAISE EXCEPTION 'audit.entries is append-only (SPEC-0003 AC1, ADR-0007)';
END;
$$ LANGUAGE plpgsql;

REVOKE ALL ON FUNCTION audit.set_entry_hash(BIGINT, TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit.set_entry_hash(BIGINT, TEXT) TO gitfrok_app;
