-- Reverses 0001_ci_jobs.sql. Dropping the table drops the record of what ran;
-- the runs themselves already happened and their audit records are elsewhere.
DROP POLICY IF EXISTS tenant_isolation ON ci.jobs;
DROP INDEX IF EXISTS ci.jobs_tenant_queued_idx;
DROP TABLE IF EXISTS ci.jobs;
