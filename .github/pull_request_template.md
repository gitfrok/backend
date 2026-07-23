# backend PR

SoT & governance checklists: `../governance/docs/process/definition-of-done.md` and
`../governance/.github/pull_request_template.md` (G1–G9 + ADR).

## Backend-specific gates
- [ ] Spec approved (`governance/docs/specs/…`) or chore with acceptance criteria stated.
- [ ] Tests written first; unit + contract + integration pass.
- [ ] **Boundaries:** no import of another module's `internal/*`; cross-module via `api/`/bus;
      `domain` imports no infra (invariants 14–20). Arch/fitness tests green.
- [ ] **Security:** every query tenant-scoped + RLS; all authZ via the PDP (invariants 1–4).
- [ ] gRPC/events match `governance/contracts/` (additive-only, governance-first).
- [ ] Version floors respected (ADR-0023). Single submodule; no cross-repo edits.
