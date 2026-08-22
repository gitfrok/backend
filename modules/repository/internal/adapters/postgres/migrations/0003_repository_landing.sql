-- T-0082 / SPEC-0065 / ADR-0088: the per-repository landing policy.
--
-- Additive over 0002_repository_settings.sql, on the registry row for the same
-- reason the rest of settings lives there: a second table keyed on
-- (tenant_id, repo_id) would be a second answer to whether a repository exists
-- (ADR-0071).
--
-- merge_strategy is '' when no explicit choice has been made, and a repository
-- with none merges exactly as it always did — fast-forward when possible
-- (SPEC-0065 AC1). The CHECK is the column refusing last what the domain
-- refuses first: an unknown strategy must fail loudly rather than degrade to
-- unset, because an operator who chose squash would otherwise be running
-- fast-forward landings and never learn it.
--
-- trunk_based constrains the SHAPE of landings — merge commits refused,
-- fast-forward preferred, rebase the fallback — never who may land or whether
-- (ADR-0088 decision 3). It is not an authorization column and grants nothing.

ALTER TABLE repo.repositories
  ADD COLUMN IF NOT EXISTS merge_strategy TEXT    NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS trunk_based    BOOLEAN NOT NULL DEFAULT false;

ALTER TABLE repo.repositories
  DROP CONSTRAINT IF EXISTS repositories_merge_strategy_known;
ALTER TABLE repo.repositories
  ADD CONSTRAINT repositories_merge_strategy_known CHECK (
    merge_strategy IN ('', 'merge_commit', 'squash', 'rebase')
  );

-- No new grant: the application role already holds SELECT and UPDATE on this
-- table for the settings columns, and RLS covers every column, present and
-- future.
