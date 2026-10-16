# ADR 0001 — Package name iotwarden

## Status

Accepted (2026-10-16)

## Context

The spec draft used the npm name `cybershield`. `scripts/check-name.mjs` queried the npm registry and `github.com/kathanp/<name>` on 2026-10-16.

| Candidate    | Verdict |
| ------------ | ------- |
| cybershield  | RISKY   |
| edgewarden   | CLEAR   |
| iotwarden    | CLEAR   |
| lanwarden    | CLEAR   |
| devicewarden | CLEAR   |

`cybershield` was free as an exact name. Securas already publishes CyberShield WAF packages under that brand: `cybershield-js`, `react-cybershield`, `angular-cybershield`, `plugin-cybershield`, `cyber-shield-express`. npm can transfer a name after a trademark claim.

## Decision

The package name is `iotwarden`. Scoped packages will be `@iotwarden/*`.

## Consequences

- `docs/SPEC.md` and `packages/core` use `iotwarden`.
- USPTO and EUIPO searches stay manual, before any publish.
- The npm org is not created by this repository. Create it at https://www.npmjs.com/org/create before publishing scoped packages.
