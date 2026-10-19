# Finish-spec run

Branch target: `work/finish-spec` from `main`, with `wp-21/shadow` merged in. Local commits only. Nothing is pushed or published.

Tick an item only after its checks pass. A blocked item names the reason in `docs/QUESTIONS.md`.

## Step 1 — Finish 0.8

- [x] 1a. WP-21 shadow detectors green (gate on this branch)
- [ ] 1b. WP-22 rule language (`loadRules`, sequences, examples, fuzz)
- [ ] 1c. `peer-divergence-federated` marked Rel 0.9 in SPEC
- [ ] 1d. 0.8.0 bump, CHANGELOG, local tag `v0.8.0`

## Step 2 — Code quality (each check added to `npm run gate`)

- [ ] 2a. ESLint core rules as errors; violations split, under 10 justified disables
- [ ] 2b. `IotwardenError`, `docs/ERRORS.md`, undocumented-code test
- [ ] 2c. `scripts/detector-lint.mjs` (fix silent oversize imports, including `beacon-change`)
- [ ] 2d. Shared helpers for logic copied across 3 or more detectors
- [ ] 2e. knip dead-code pass
- [ ] 2f. Public API snapshot
- [ ] 2g. Coverage ratchet: lines 95, branches 85
- [ ] 2h. Stryker on validate, baseline, incidents (recorded, not gated)
- [ ] 2i. No `child_process` / `eval` / `new Function` / dynamic `require`; `npm audit --omit=dev` is 0
- [ ] 2j. `docs/QUALITY.md`

## Step 3 — WP-23

- [ ] 3a. Load shedding (`budget`, default off)
- [ ] 3b. Incremental checkpoints (`checkpointDelta`, `applyDelta`)

## Step 4 — WP-24 (each default off, own commit)

- [ ] 4a. `calibratedConfidence`
- [ ] 4b. Class suggestion
- [ ] 4c. `setDeviceTimezone`
- [ ] 4d. `redact`

## Step 5 — WP-25

- [ ] 5a. `createShardedEngine` inline only
- [ ] 5b. Federation summaries
- [ ] 5c. `peer-divergence-federated` (shadow)

## Step 6 — WP-27 ten detectors (shadow, Rel 0.9)

- [ ] 6.1 `day-of-week-drift`
- [ ] 6.2 `sni-ip-mismatch`
- [ ] 6.3 `mac-randomization-churn`
- [ ] 6.4 `discovery-spoof`
- [ ] 6.5 `mud-violation`
- [ ] 6.6 `fleet-baseline-poisoning`
- [ ] 6.7 `ot-schedule-drift`
- [ ] 6.8 `reverse-shell-shape`
- [ ] 6.9 `llmnr-nbns-poison`
- [ ] 6.10 `dns-answer-mismatch`
- [ ] 6.11 spec-coverage has zero unimplemented rows

## Step 7 — WP-26 packages

- [ ] 7a. `adapter-unbound`
- [ ] 7b. `adapter-ipfix`
- [ ] 7c. `adapter-openwrt`
- [ ] 7d. `adapter-nftables`
- [ ] 7e. `adapter-ssdp`
- [ ] 7f. `export-prometheus`
- [ ] 7g. `export-ecs`
- [ ] 7h. `export-mqtt`
- [ ] 7i. OCSF campaign mapping and explain text
- [ ] 7j. `respond-nftables` and `responseHints`
- [ ] 7k. `@iotwarden/cli`

## Step 8 — Package quality and docs

- [ ] 8a. package.json fields and ESM entry for every public package
- [ ] 8b. `index.d.ts` and `test/types`
- [ ] 8c. `scripts/publint-lite.mjs` in the gate
- [ ] 8d. Root and core README
- [ ] 8e. examples 01–08 and a test that runs them
- [ ] 8f. ARCHITECTURE, RULES, OPERATIONS, ERRORS, QUALITY, CONTRIBUTING, CODE_OF_CONDUCT

## Step 9 — Final pass

- [ ] 9a. Clean clone, `npm ci`, `npm run gate`
- [ ] 9b. Pack tarballs and run examples/01 under CJS and ESM
- [ ] 9c. 0.9.0 bump and local tag `v0.9.0` if the 0.9 gate is met
- [ ] 9d. Merge `work/finish-spec` into local main with `--no-ff`

## Session note

2026-10-19: 1a is green. Check 282/282. Coverage 98.04% lines, 86.84% branches. Rich bench 87.35 KB/device. Demo score 100. Next is 1b, the rule language, on `work/finish-spec`.
