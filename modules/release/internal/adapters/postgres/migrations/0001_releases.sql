-- T-0064 / SPEC-0056 / ADR-0075: the release record.
--
-- A release is a name for a commit plus prose about it. ADR-0075 accepted the
-- tags-and-notes increment only, so there is NO artifact column here and
-- adding one is that decision rather than a migration — the moment this
-- platform serves a downloadable artifact it is in a customer's supply chain.
--
-- published_commit is the load-bearing column. A tag is a mutable pointer: it
-- can be moved, deleted or recreated against a different commit and git will
-- not remark on it. Recording what the tag pointed at AT PUBLISH TIME is what
-- makes a release a record rather than a rendering of "whatever v1.2.0 means
-- today" — without it, moving a tag silently rewrites what an already-published
-- release describes. Same shape ADR-0071 fixed for repositories: the record is
-- the truth, not the disk.
--
-- RLS follows 0001_tenancy_baseline.sql: enabled and forced, one
-- tenant_isolation policy keyed on tenant_id, failing closed when
-- app.tenant_id is unset.

CREATE SCHEMA IF NOT EXISTS release;

-- rls: tenant-key=tenant_id
CREATE TABLE IF NOT EXISTS release.releases (
  tenant_id        TEXT        NOT NULL,
  repository_id    TEXT        NOT NULL,
  tag              TEXT        NOT NULL,
  published_commit TEXT        NOT NULL,
  notes            TEXT        NOT NULL DEFAULT '',
  published_by     TEXT        NOT NULL,
  published_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  -- NULL until the notes are first edited. Notes are documentation and may be
  -- corrected; the tag and the commit may not (SPEC-0056 AC4).
  notes_updated_at TIMESTAMPTZ,
  -- One release per tag per repository. The constraint IS the rule: two
  -- releases of v1.2.0 is not a state this product has an answer for, so the
  -- database refuses it rather than the application resolving it.
  PRIMARY KEY (tenant_id, repository_id, tag),
  CHECK (tenant_id <> ''),
  CHECK (repository_id <> ''),
  CHECK (tag <> ''),
  CHECK (published_commit <> ''),
  CHECK (octet_length(notes) <= 65536)
);

-- The list walks (repository, published_at DESC, tag DESC) — newest first,
-- with the tag breaking ties so the ordering is total and a cursor is a
-- position in it rather than an offset into an answer.
CREATE INDEX IF NOT EXISTS releases_repo_published_idx
  ON release.releases (tenant_id, repository_id, published_at DESC, tag DESC);

ALTER TABLE release.releases ENABLE ROW LEVEL SECURITY;
ALTER TABLE release.releases FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON release.releases;
CREATE POLICY tenant_isolation ON release.releases
  FOR ALL
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

-- Minimal grants: the application role publishes and edits notes. It does not
-- delete — SPEC-0056 keeps a release of a deleted tag rather than hiding it,
-- because it happened and was announced, and hiding it would make the record
-- less true than the world.
GRANT USAGE ON SCHEMA release TO gitfrok_app;
GRANT SELECT, INSERT, UPDATE ON release.releases TO gitfrok_app;
REVOKE DELETE, TRUNCATE ON release.releases FROM gitfrok_app;
