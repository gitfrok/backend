-- Reverses 0001_releases.sql. The tags themselves are git objects and are
-- untouched; what is dropped is the record that any of them were announced.
DROP POLICY IF EXISTS tenant_isolation ON release.releases;
DROP INDEX IF EXISTS release.releases_repo_published_idx;
DROP TABLE IF EXISTS release.releases;
