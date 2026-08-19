-- Down for 0002_repository_settings.sql (T-0068, SPEC-0057).
--
-- Dropping these columns discards the description, the archived instant and the
-- record of who last changed the settings. The audit trail keeps every one of
-- those changes as its own record (ADR-0007), so what is lost here is the current
-- value, not the history.

ALTER TABLE repo.repositories
  DROP CONSTRAINT IF EXISTS repositories_settings_change_is_whole;
ALTER TABLE repo.repositories
  DROP CONSTRAINT IF EXISTS repositories_description_bounded;

ALTER TABLE repo.repositories
  DROP COLUMN IF EXISTS settings_updated_by,
  DROP COLUMN IF EXISTS settings_updated_at,
  DROP COLUMN IF EXISTS archived_at,
  DROP COLUMN IF EXISTS description;
