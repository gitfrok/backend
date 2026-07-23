# CLAUDE.md — backend

**Read `AGENTS.md` in this repo first — it is canonical.** This is the Go modular monolith (ADR-0025).

- The Source of Truth is the **governance** repo: `../governance/docs/` (ADRs, specs,
  invariants, contracts, policies). Read `../governance/AGENTS.md` before coding.
- Follow **AGDD** (`../governance/docs/process/agdd.md`): confirm your target repo, ensure an
  approved spec, write failing tests, implement, refactor within boundaries, pass CI gates, PR.
- Obey invariants 1–25 (`../governance/docs/agents/invariants.md`). New decision → Proposed
  ADR in governance and stop. API change → governance PR first (additive), then bump the pin.
- Keep diffs focused; never span two submodules in one commit.
