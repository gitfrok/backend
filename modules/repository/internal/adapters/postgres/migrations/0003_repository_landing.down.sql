-- Down for 0003_repository_landing.sql (T-0082, SPEC-0065).
--
-- Dropping these columns discards the landing policy's current value. Every
-- change to it is its own audit record (ADR-0007), so what is lost here is the
-- current choice, not the history of choices.

ALTER TABLE repo.repositories
  DROP CONSTRAINT IF EXISTS repositories_merge_strategy_known;

ALTER TABLE repo.repositories
  DROP COLUMN IF EXISTS trunk_based,
  DROP COLUMN IF EXISTS merge_strategy;
