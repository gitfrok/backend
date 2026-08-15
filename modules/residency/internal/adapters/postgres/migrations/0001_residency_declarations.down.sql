-- Rollback half of 0001_residency_declarations.sql (SPEC-0042 AC5: additive
-- AND rollback-tested). Drops exactly what the up migration creates, in
-- dependency order: the tables first, then the schema. Safe to run against
-- a database where the up migration was applied any number of times.
--
-- The up migration is idempotent (IF NOT EXISTS / DROP POLICY IF EXISTS),
-- so this file deliberately is not: dropping what never existed is an error
-- an operator should see, not silence.

DROP TABLE IF EXISTS residency.observations;
DROP TABLE IF EXISTS residency.declarations;

DROP SCHEMA IF EXISTS residency;
