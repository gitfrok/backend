-- T-0078 / SPEC-0061 / ADR-0080: the Code Review context, made durable.
--
-- This context has never had a durable store. cmd/dataplane-app built it on
-- NewMemoryStore, whose old comment promised that "Production injects a
-- tenant-scoped database store" — describing an adapter that did not exist.
-- Every merge request, review, branch-protection rule, ref revision and
-- external issue reference emptied when the process did.
--
-- It is the gap ADR-0071 closed for the repository registry, and worse in
-- consequence. A registry that emptied could be re-registered: the bare
-- repositories were still on disk and what was lost was a record of which ones
-- the product knew about. What empties here is the review itself — who approved
-- what, at which revision, against which rule. SPEC-0019 AC6 makes an accepted
-- approval an audit record because it is evidence; the trail kept the act while
-- the merge request that gave it meaning did not survive a deploy.
--
-- THE TABLES FOLLOW THE PORT, NOT THE AGGREGATE (ADR-0080 accepted scope).
-- Reviews, branch protections and ref revisions each have their own port methods
-- and their own keys, so each gets a table. An idempotency key and a `seen`
-- request ID are the same fact — this was already applied — so they share one.
-- External issue references get neither: they are a field of the aggregate,
-- loaded and saved with it, so they are a JSONB column (decision 2).
--
-- RLS follows 0001_tenancy_baseline.sql on every table: enabled and forced, one
-- tenant_isolation policy keyed on tenant_id, failing closed when app.tenant_id
-- is unset.

CREATE SCHEMA IF NOT EXISTS codereview;

-- rls: tenant-key=tenant_id
CREATE TABLE IF NOT EXISTS codereview.merge_requests (
  tenant_id         TEXT        NOT NULL,
  merge_request_id  TEXT        NOT NULL,
  repository_id     TEXT        NOT NULL,
  source_ref        TEXT        NOT NULL,
  target_ref        TEXT        NOT NULL,
  title             TEXT        NOT NULL,
  description       TEXT        NOT NULL DEFAULT '',
  creator_id        TEXT        NOT NULL,
  state             TEXT        NOT NULL,
  head_revision     TEXT        NOT NULL DEFAULT '',
  -- Where the target ref stood when this context last saw it. It comes from
  -- Repository/Git's own announcements; a caller cannot assert it.
  target_revision   TEXT        NOT NULL DEFAULT '',
  created_at        TIMESTAMPTZ NOT NULL,
  updated_at        TIMESTAMPTZ NOT NULL,
  -- Server-assigned and positive. Every mutation is guarded by it, and since
  -- ADR-0080 decision 3 that guard is the UPDATE's own WHERE clause rather than
  -- a load-then-save the caller hopes nobody raced.
  version           BIGINT      NOT NULL CHECK (version > 0),
  -- References to issues in the customer's own tracker (SPEC-0059). A field of
  -- the aggregate, bounded at 25 by the domain and again here, because a column
  -- is the last place that can still refuse. Defaults to an empty array so a
  -- merge request with no references is not a null a reader has to interpret.
  external_issues   JSONB       NOT NULL DEFAULT '[]'::jsonb
    CHECK (jsonb_typeof(external_issues) = 'array' AND jsonb_array_length(external_issues) <= 25),
  PRIMARY KEY (tenant_id, merge_request_id),
  CHECK (tenant_id <> ''),
  CHECK (merge_request_id <> ''),
  CHECK (repository_id <> '')
);

-- The two open-merge-request lookups the ref-update path makes on every push.
CREATE INDEX IF NOT EXISTS merge_requests_open_by_target_idx
  ON codereview.merge_requests (tenant_id, repository_id, target_ref) WHERE state = 'OPEN';
CREATE INDEX IF NOT EXISTS merge_requests_open_by_source_idx
  ON codereview.merge_requests (tenant_id, repository_id, source_ref) WHERE state = 'OPEN';

-- rls: tenant-key=tenant_id
-- One CURRENT review per actor per merge request: PutReview replaces, which is
-- what SPEC-0019 specified. Whether superseded reviews should be kept is a
-- different decision about what a review is (ADR-0080 follow-up).
CREATE TABLE IF NOT EXISTS codereview.reviews (
  tenant_id         TEXT        NOT NULL,
  merge_request_id  TEXT        NOT NULL,
  actor_id          TEXT        NOT NULL,
  disposition       TEXT        NOT NULL,
  head_revision     TEXT        NOT NULL,
  submitted_at      TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, merge_request_id, actor_id),
  CHECK (tenant_id <> ''),
  CHECK (actor_id <> '')
);

-- rls: tenant-key=tenant_id
-- An exact refs/heads/... rule. Zero required approvals still protects the ref
-- from direct pushes while permitting authorized merges, so the column is bounded
-- below at zero rather than at one.
CREATE TABLE IF NOT EXISTS codereview.branch_protections (
  tenant_id          TEXT        NOT NULL,
  repository_id      TEXT        NOT NULL,
  target_ref         TEXT        NOT NULL,
  required_approvals INTEGER     NOT NULL CHECK (required_approvals >= 0),
  version            BIGINT      NOT NULL CHECK (version > 0),
  PRIMARY KEY (tenant_id, repository_id, target_ref),
  CHECK (tenant_id <> ''),
  CHECK (target_ref <> '')
);

-- rls: tenant-key=tenant_id
-- Where Repository/Git last announced a ref to be. Empty is a real answer — this
-- context has never been told about that ref — so absence is not an error.
CREATE TABLE IF NOT EXISTS codereview.ref_revisions (
  tenant_id     TEXT NOT NULL,
  repository_id TEXT NOT NULL,
  ref           TEXT NOT NULL,
  revision      TEXT NOT NULL,
  PRIMARY KEY (tenant_id, repository_id, ref),
  CHECK (tenant_id <> '')
);

-- rls: tenant-key=tenant_id
-- Idempotency keys and `seen` request IDs in one table, because they are one
-- fact: this was already applied. The kind column keeps them legible to whoever
-- reads the table, not to the code — the port asks about one or the other and
-- never about both.
--
-- The rows grow without bound and nothing removes them. That is ADR-0080's named
-- follow-up rather than an oversight: retention here is a data-lifecycle question
-- like the one ADR-0076 decision 3 left open for repository deletion.
CREATE TABLE IF NOT EXISTS codereview.applied_requests (
  tenant_id  TEXT        NOT NULL,
  kind       TEXT        NOT NULL CHECK (kind IN ('idempotency', 'seen')),
  key        TEXT        NOT NULL,
  -- The merge request an idempotency key resolved to; empty for a `seen` row,
  -- which records only that the request was applied.
  subject_id TEXT        NOT NULL DEFAULT '',
  applied_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, kind, key),
  CHECK (tenant_id <> ''),
  CHECK (key <> '')
);

ALTER TABLE codereview.merge_requests     ENABLE ROW LEVEL SECURITY;
ALTER TABLE codereview.merge_requests     FORCE  ROW LEVEL SECURITY;
ALTER TABLE codereview.reviews            ENABLE ROW LEVEL SECURITY;
ALTER TABLE codereview.reviews            FORCE  ROW LEVEL SECURITY;
ALTER TABLE codereview.branch_protections ENABLE ROW LEVEL SECURITY;
ALTER TABLE codereview.branch_protections FORCE  ROW LEVEL SECURITY;
ALTER TABLE codereview.ref_revisions      ENABLE ROW LEVEL SECURITY;
ALTER TABLE codereview.ref_revisions      FORCE  ROW LEVEL SECURITY;
ALTER TABLE codereview.applied_requests   ENABLE ROW LEVEL SECURITY;
ALTER TABLE codereview.applied_requests   FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON codereview.merge_requests;
CREATE POLICY tenant_isolation ON codereview.merge_requests FOR ALL
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
DROP POLICY IF EXISTS tenant_isolation ON codereview.reviews;
CREATE POLICY tenant_isolation ON codereview.reviews FOR ALL
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
DROP POLICY IF EXISTS tenant_isolation ON codereview.branch_protections;
CREATE POLICY tenant_isolation ON codereview.branch_protections FOR ALL
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
DROP POLICY IF EXISTS tenant_isolation ON codereview.ref_revisions;
CREATE POLICY tenant_isolation ON codereview.ref_revisions FOR ALL
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
DROP POLICY IF EXISTS tenant_isolation ON codereview.applied_requests;
CREATE POLICY tenant_isolation ON codereview.applied_requests FOR ALL
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

-- Minimal grants. The application role records and reads review state; it does
-- not delete any of it. Nothing in the Store port removes a merge request, a
-- review, a protection or a ref revision — closing a merge request is a state
-- change — so the capability is not granted rather than left lying around
-- (SPEC-0061 AC14).
GRANT USAGE ON SCHEMA codereview TO gitfrok_app;
GRANT SELECT, INSERT, UPDATE ON codereview.merge_requests     TO gitfrok_app;
GRANT SELECT, INSERT, UPDATE ON codereview.reviews            TO gitfrok_app;
GRANT SELECT, INSERT, UPDATE ON codereview.branch_protections TO gitfrok_app;
GRANT SELECT, INSERT, UPDATE ON codereview.ref_revisions      TO gitfrok_app;
GRANT SELECT, INSERT, UPDATE ON codereview.applied_requests   TO gitfrok_app;
REVOKE DELETE, TRUNCATE ON codereview.merge_requests     FROM gitfrok_app;
REVOKE DELETE, TRUNCATE ON codereview.reviews            FROM gitfrok_app;
REVOKE DELETE, TRUNCATE ON codereview.branch_protections FROM gitfrok_app;
REVOKE DELETE, TRUNCATE ON codereview.ref_revisions      FROM gitfrok_app;
REVOKE DELETE, TRUNCATE ON codereview.applied_requests   FROM gitfrok_app;
