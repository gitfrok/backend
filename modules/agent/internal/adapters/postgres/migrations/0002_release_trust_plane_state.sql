-- T-0041 / SPEC-0045 AC2: the durable RELEASE trust distribution registry.
--
-- The staged release trust bundle (the cosign release-signing keys of
-- ADR-0044/ADR-0065) rides the reconcile channel as desired state; the
-- control plane's durable memory of which data plane has APPLIED which
-- bundle revision lives here, keyed by data_plane_id (ADR-0065's registry
-- keying). A mid-window control-plane restart must not lose convergence:
-- the planes that already applied a revision stay recorded.
--
-- This is a DIFFERENT artifact from the CA trust bundle of SPEC-0044 — the
-- agent-identity roots — and shares neither table, column nor name with it
-- (SPEC-0045's two-bundles note).
--
-- The table carries PUBLIC trust metadata only: a revision number and when
-- the plane applied it. No key material — the bundle itself is an
-- operator-owned artifact distributed over the channel — and no credential.
--
-- Unlike the enrolment tables of 0001, every path here is tenant-scoped:
-- the plane's applied revision is only ever read or written under the
-- tenant the plane belongs to, so there is NO pre-tenancy exemption and no
-- SECURITY DEFINER function (the exemption enumeration of SPEC-0042 AC5
-- stays exactly what 0001 declared).

-- rls: tenant-key=tenant_id
CREATE TABLE IF NOT EXISTS agent.release_trust_plane_state (
  tenant_id        TEXT NOT NULL,
  -- The registry key of ADR-0065: one row per data plane.
  data_plane_id    TEXT NOT NULL,
  -- The newest release trust bundle revision the plane acked as applied.
  applied_revision BIGINT NOT NULL,
  applied_at       TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, data_plane_id)
);

ALTER TABLE agent.release_trust_plane_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.release_trust_plane_state FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON agent.release_trust_plane_state;
CREATE POLICY tenant_isolation ON agent.release_trust_plane_state
  FOR ALL
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

-- Minimal grants, mirroring 0001's posture: the application role reads and
-- advances convergence, never deletes it — a revocation is an UPDATE, never
-- a DELETE (the forward-only ledger of RecordReleaseTrustApplied).
GRANT USAGE ON SCHEMA agent TO gitfrok_app;
GRANT SELECT, INSERT, UPDATE ON agent.release_trust_plane_state TO gitfrok_app;
REVOKE DELETE, TRUNCATE ON agent.release_trust_plane_state FROM gitfrok_app;
