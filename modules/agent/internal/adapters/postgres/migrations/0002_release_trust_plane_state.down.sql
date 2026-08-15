-- Down migration for 0002_release_trust_plane_state.sql.
-- Removing the table loses the fleet's recorded convergence on the release
-- trust bundle — acceptable for a downgrade, because the bundle itself is
-- re-distributed over the reconcile channel and planes re-ack from scratch.
DROP POLICY IF EXISTS tenant_isolation ON agent.release_trust_plane_state;
DROP TABLE IF EXISTS agent.release_trust_plane_state;
