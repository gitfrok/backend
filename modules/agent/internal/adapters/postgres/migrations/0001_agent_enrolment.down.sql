-- Rollback half of 0001_agent_enrolment.sql (SPEC-0042 AC5: additive AND
-- rollback-tested). Drops exactly what the up migration creates, in
-- dependency order: the exempt functions first (they reference the token
-- table), then the tables, then the schema. Safe to run against a database
-- where the up migration was applied any number of times.
--
-- The up migration is idempotent (IF NOT EXISTS / CREATE OR REPLACE /
-- DROP POLICY IF EXISTS), so this file deliberately is not: dropping what
-- never existed is an error an operator should see, not silence.

DROP FUNCTION IF EXISTS agent.claim_enrolment_token(BYTEA, TEXT);
-- The superseded (BYTEA, TEXT, TIMESTAMPTZ) overload: the up migration drops
-- it on re-apply, so the down drops it too — a rollback must leave NO claim
-- surface behind, whichever signature the database still carries.
DROP FUNCTION IF EXISTS agent.claim_enrolment_token(BYTEA, TEXT, TIMESTAMPTZ);
DROP FUNCTION IF EXISTS agent.lookup_enrolment_token(BYTEA);

DROP TABLE IF EXISTS agent.data_planes;
DROP TABLE IF EXISTS agent.enrolment_tokens;

DROP SCHEMA IF EXISTS agent;
