# backend

Go modular monolith (ADR-0025). Scaffolded by governance task **T-0001**; features from **T-0010+**. See `AGENTS.md`.

## Running `dataplane-app`

The plane needs a policy bundle and refuses to start without a usable one (ADR-0006, T-0005):

```
GITFROK_POLICY_BUNDLE_DIR=../governance/policies go run ./cmd/dataplane-app
```

The path is per-environment configuration (invariant 13) pointing at a copy of
`governance/policies`. The bundle is **not** embedded in the binary: a copy of the rules here would
be a second source of truth for something governance owns (invariant 21), and it would make every
policy change a backend release.

Failing at startup is deliberate. A plane that came up with an unusable bundle would deny every
request in the system, which reaches an operator as an unexplained total outage rather than as a
rollout that refused and said why.

## Authorization

Ask `modules/policy/api.DecisionPoint`. Do not write permission logic anywhere else — invariant 2,
and `internal/arch`'s `inline-permission-check` fitness function fails the build over it. If
something it flags genuinely decides no access, waive that line with
`//arch:allow-inline-authz <reason>`; the reason is what review assesses.
