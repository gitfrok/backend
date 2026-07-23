# AGENTS.md — backend (Go modular monolith)

Depends on **governance** (SoT + `contracts/` + `policies/`). Read `../governance/AGENTS.md`
and `../governance/docs/` **first**; obey invariants 1–25.

## This repo owns
`modules/<ctx>/{api,internal/{domain,app,adapters}}`, `cmd/{dataplane-app,controlplane-app}`,
`platform/{ids,bus,telemetry}`, plus `git-storaged`, the `agent`, and the `operator`.

## Strict
- **Modular monolith** (ADR-0025): one binary per plane; cross-module only via `api/` or the
  in-process bus; **never** import another module's `internal/*` (Go `internal/` enforces it).
- Each module **owns its schema**; no cross-module DB access. Prefer events over sync.
- `domain` imports no infra. All authZ via the **PDP**; every query **tenant-scoped** + RLS.
- gRPC/events must match `../governance/contracts/` (additive-only, changed in governance first).
- **TDD**: failing tests from the spec's acceptance criteria before code.
- Do not expose infra types in a module's `api/` (fitness-checked — T-0009).
