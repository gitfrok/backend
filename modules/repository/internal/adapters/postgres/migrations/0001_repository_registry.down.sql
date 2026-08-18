-- Reverses 0001_repository_registry.sql. Dropping the table drops the
-- registry, which — per ADR-0071 decision 2 — is the product's truth for
-- which repositories exist. The bare repositories on disk are untouched and
-- become invisible to every product surface, exactly as a RUNBOOK §8a
-- recovered repository is.
DROP POLICY IF EXISTS tenant_isolation ON repo.repositories;
DROP INDEX IF EXISTS repo.repositories_tenant_id_repo_id_idx;
DROP TABLE IF EXISTS repo.repositories;
