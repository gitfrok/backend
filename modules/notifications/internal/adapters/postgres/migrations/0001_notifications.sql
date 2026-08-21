-- T-0080 / SPEC-0063 / ADR-0086: the Notifications context's durable rows.
--
-- One row per (recipient, event), written idempotently by a bus-fed
-- subscriber: at-least-once delivery from the bus, exactly-once rows here.
-- The natural key IS the idempotency key — a replayed event conflicts and
-- changes nothing.
--
-- mr_creators is this context's own tenant-scoped projection of merge-request
-- authors (the security module's pattern): the findings-attributed event does
-- not carry the author, and this context never reads Code Review's tables
-- (invariant 15). The opened/ready events it already receives feed it.
--
-- There is no DELETE path in the grant set; read rows accumulate until
-- retention is decided (SPEC-0063 open question 1, ADR-0080's data-lifecycle
-- class).

CREATE SCHEMA IF NOT EXISTS notifications;

-- rls: tenant-key=tenant_id
CREATE TABLE IF NOT EXISTS notifications.items (
  tenant_id        TEXT NOT NULL,
  recipient_id     TEXT NOT NULL,
  -- The composite of the producing event ID and the recipient. Deterministic,
  -- so a replay lands on the same key; opaque to callers as the row's ID.
  event_id         TEXT NOT NULL,
  kind             TEXT NOT NULL,
  repository_id    TEXT NOT NULL DEFAULT '',
  merge_request_id TEXT NOT NULL DEFAULT '',
  actor_id         TEXT NOT NULL DEFAULT '',
  head_revision    TEXT NOT NULL DEFAULT '',
  occurred_at      TIMESTAMPTZ NOT NULL,
  read_at          TIMESTAMPTZ,
  PRIMARY KEY (tenant_id, recipient_id, event_id)
);

-- The list read is newest-first per recipient; the primary key cannot serve it.
CREATE INDEX IF NOT EXISTS notifications_items_recipient_recent
  ON notifications.items (tenant_id, recipient_id, occurred_at DESC);

-- rls: tenant-key=tenant_id
CREATE TABLE IF NOT EXISTS notifications.mr_creators (
  tenant_id        TEXT NOT NULL,
  repository_id    TEXT NOT NULL,
  merge_request_id TEXT NOT NULL,
  creator_id       TEXT NOT NULL,
  PRIMARY KEY (tenant_id, repository_id, merge_request_id)
);

ALTER TABLE notifications.items ENABLE ROW LEVEL SECURITY;
ALTER TABLE notifications.items FORCE ROW LEVEL SECURITY;
ALTER TABLE notifications.mr_creators ENABLE ROW LEVEL SECURITY;
ALTER TABLE notifications.mr_creators FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON notifications.items;
CREATE POLICY tenant_isolation ON notifications.items
  FOR ALL
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

DROP POLICY IF EXISTS tenant_isolation ON notifications.mr_creators;
CREATE POLICY tenant_isolation ON notifications.mr_creators
  FOR ALL
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

GRANT USAGE ON SCHEMA notifications TO gitfrok_app;
-- items: append-only except read_at — mark-read is the one UPDATE, and no
-- delete or truncate exists for any role here.
GRANT SELECT, INSERT, UPDATE ON notifications.items TO gitfrok_app;
REVOKE DELETE, TRUNCATE ON notifications.items FROM gitfrok_app;
GRANT SELECT, INSERT, UPDATE ON notifications.mr_creators TO gitfrok_app;
REVOKE DELETE, TRUNCATE ON notifications.mr_creators FROM gitfrok_app;
