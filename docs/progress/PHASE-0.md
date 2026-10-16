# Phase 0

Date: 2026-10-16. Package name: `iotwarden`.

## What was built

- `scripts/check-name.mjs` checks the npm exact name, punctuation variants, similar packages, `@name/core`, and an optional GitHub repo.
- npm workspaces. The publishable package is `packages/core` (`iotwarden@0.0.1`) with empty `dependencies`.
- Root tooling: ESLint flat config, Prettier, `tsc --noEmit` with `checkJs`, `npm run check`, and `npm run gate`.
- `scripts/pack-check.mjs` rejects a tarball that leaves the allowlist, a core dependency, a size over 500 KB, `TODO` / `FIXME` / `console.log`, or a token-shaped string.
- CI on Node 22, 24, and 26, on `ubuntu-latest` and `ubuntu-24.04-arm`. Actions are pinned to commit SHAs (`actions/checkout` v7.0.1, `actions/setup-node` v7.1.0).
- The 0.0.1 prototype lives at `packages/core/src/index.js`, with its six tests and the camera demo. Behavior of those tests is unchanged.
- `bench` and `fuzz` are no-ops until Phase 5.
- `cursor-kit/` is the original instruction drop. Canonical spec is `docs/SPEC.md`.

## What was skipped, and why

- No git remote, no `npm publish`, no npm login. The playbook leaves those to the human.
- `repository`, `bugs`, and `homepage` are omitted until a GitHub remote exists.
- Adapters, the engine refactor, and every detector past the original four belong to later phases.
- Real benchmarks and fuzzing belong to Phase 5.

## Open questions

See `docs/QUESTIONS.md`: disclosure email, and repository URLs.

`lock()` (lines 171–172 of `packages/core/src/index.js`) is the only uncovered prototype code. The six original tests never call it. Line coverage is 99.08% and branch coverage is 86.36%, both above the gate.

## Gate

`node scripts/check-name.mjs iotwarden` → **CLEAR**.

`npm ci && npm run check` → lint, types, and 6/6 tests passed.

`npm run gate` (what CI runs) also passed: coverage 99.08% lines / 86.36% branches, pack-check 7 files and 24906 bytes unpacked, bench and fuzz no-ops.

```
iotwarden  →  CLEAR
exact npm       free        HTTP 404
punctuation     none        iot-warden, iot_warden, iot.warden
@iotwarden/core free
similar (name contains candidate): none

✔ normal week after learning produces no alerts
✔ catches a new destination
✔ catches Mirai-style fan-out
✔ catches a volume spike
✔ catches 3 a.m. activity
✔ baseline export/import keeps detection
ℹ tests 6
ℹ pass 6
ℹ fail 0
```

GitHub `kathanp/iotwarden` was free on the same day when `--github-user=kathanp` was passed. The gate command above does not pass that flag, so it reports GitHub as skipped.

Trademark search is manual: https://tmsearch.uspto.gov/ and https://euipo.europa.eu/eSearch/

Stopped here. Phase 1 starts only after an explicit go.
