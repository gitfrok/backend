-- T-0068 / SPEC-0057 / ADR-0076: repository settings on the registry record.
--
-- Additive over 0001_repository_registry.sql. Settings are properties of the
-- registry row and not a table of their own: a second table keyed on
-- (tenant_id, repo_id) would be a second answer to whether a repository exists,
-- and ADR-0071 makes this row the product's truth for that.
--
-- WHAT IS NOT HERE IS ADR-0076's DECISION. There is no visibility column, no
-- members table and no per-repository role, because neither is a setting: a
-- public read is a different authorization model, and per-repository membership
-- is one the PDP would have to learn everywhere repo.read is asked. There is no
-- branch-protection or approval column either — PR-10 puts those in
-- governance/policies, "enforced server-side and expressed as policy, not UI
-- toggles".
--
-- archived_at is an instant and there is no paired boolean. A flag plus a
-- timestamp can disagree, and "archived, but we do not know when" is not a state
-- anyone can act on. NULL is not archived.
--
-- Archival is a LABEL. Nothing in this migration or its adapter makes an
-- archived repository read-only: a read-only condition must name its cause from
-- the two-member vocabulary in repository/api/readonly.go, and adding a third is
-- a decision about the git write path, not about a settings form (SPEC-0057's
-- archival rule).
--
-- RLS needs no change: the policy on repo.repositories is keyed on tenant_id and
-- covers every column, present and future.

ALTER TABLE repo.repositories
  ADD COLUMN IF NOT EXISTS description         TEXT        NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS archived_at         TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS settings_updated_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS settings_updated_by TEXT;

-- The description is prose about a repository, not a document store. The bound
-- is stated here as well as at the contract, because a column is the last place
-- that can still refuse.
ALTER TABLE repo.repositories
  DROP CONSTRAINT IF EXISTS repositories_description_bounded;
ALTER TABLE repo.repositories
  ADD CONSTRAINT repositories_description_bounded CHECK (length(description) <= 4096);

-- The who and the when of a settings change travel together: a record naming an
-- actor with no instant, or an instant with no actor, is half a record and the
-- audit trail is the half that matters (ADR-0007, SPEC-0057 AC4).
ALTER TABLE repo.repositories
  DROP CONSTRAINT IF EXISTS repositories_settings_change_is_whole;
ALTER TABLE repo.repositories
  ADD CONSTRAINT repositories_settings_change_is_whole CHECK (
    (settings_updated_at IS NULL AND settings_updated_by IS NULL)
    OR (settings_updated_at IS NOT NULL AND settings_updated_by IS NOT NULL AND settings_updated_by <> '')
  );

-- No new grant. The application role already holds SELECT, INSERT and UPDATE on
-- this table, and 0001 revoked DELETE naming PR-30 as the reason. PR-30 is now
-- specified and deletion is still out of scope (ADR-0076 decision 3), so the
-- revocation stands rather than being quietly reversed by the migration that
-- delivers the feature it was waiting for.
