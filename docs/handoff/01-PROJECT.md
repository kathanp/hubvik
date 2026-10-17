# iotwarden — project briefing

Read this before changing the package. The behavior spec is `docs/SPEC.md`. The build order is `CURSOR_BUILD.md`. Developer usage is `docs/DEVELOPERS.md`. This file is the state of the tree on 2026-10-17.

## What it is

`iotwarden` is a zero-dependency Node.js library that runs on an IoT gateway. It learns each device's normal network behavior and emits anomalies. It never blocks, drops, or modifies traffic. The host product decides what to do with a report.

Author: Kathan Patel. License: Apache-2.0. Package name: `iotwarden` (unscoped core). Adapters and exporters are `@iotwarden/*`. The repo folder is `cybershield`; that name is not the npm name.

Status line, and it must stay until a script in this repo produces real numbers: **prototype — not validated on real traffic.** Do not claim a detection rate, a benchmark, a dataset result, or a market rank. Do not cite CICIoT2023, IoT-23, or N-BaIoT as results. Those names appear only as future evaluation inputs.

Highest version this playbook may publish is `0.4.x`. `1.0.0` requires the spec's evaluation harness results and a 30-day real deployment. Do not bump to 1.0.

## Versions in the tree

| Package                           | Version | Role                                                    |
| --------------------------------- | ------- | ------------------------------------------------------- |
| `packages/core` (`iotwarden`)     | 0.4.0   | Engine and all detectors                                |
| `@iotwarden/adapter-conntrack`    | 0.2.0   | `conntrack -L` / `-E` lines to flows                    |
| `@iotwarden/adapter-dnsmasq`      | 0.2.0   | `log-queries=extra` lines to DNS events                 |
| `@iotwarden/adapter-zeek`         | 0.1.0   | Zeek JSON logs                                          |
| `@iotwarden/adapter-suricata-eve` | 0.1.0   | Suricata EVE JSON                                       |
| `@iotwarden/export-ocsf`          | 0.1.0   | OCSF Detection Finding, class_uid 2004                  |
| `@iotwarden/export-syslog`        | 0.1.0   | RFC 5424 plus a CEF message                             |
| `@iotwarden/export-webhook`       | 0.1.0   | POST with retry, backoff, HMAC. Caller supplies `fetch` |

Git: commits on `main` stop at `0.1.0` (`ccdc4d3`, then `bde8b12`). Releases 0.2.0, 0.3.0, and 0.4.0 are implemented and the 0.4.0 gate passed, and they are not committed. Do not commit, push, or `npm publish` unless the human asks. The human does every `npm login`, `npm publish`, `git push`, and `gh repo create`.

## Gate that already passed for 0.4.0

`npm run gate`: 91/91 tests, 97.06% lines, 84.99% branches. Thresholds are 90% lines and 80% branches. Core tarball: 146 files, 297,212 bytes unpacked. Cap is 500 KB unpacked. `npm run demo` prints the camera hijack and one critical incident with stages c2, recon, and impact.

`bench` and `fuzz` are no-ops until Phase 5. Do not start Phase 5 unless the human says go.

Local Node on the default PATH may be 18. This repo needs Node ≥ 22. The known-good binary is `~/.nvm/versions/node/v24.21.0/bin`. Put that directory first on `PATH` before `npm` or `node`.

## Layout

```
packages/core/src/index.js          public API
packages/core/src/index.d.ts        types, keep in sync
packages/core/src/engine/           engine, validate, baseline, net, incidents, classes
packages/core/src/detectors/<id>.js one file per detector
packages/core/src/data/             JSON tables (suffixes, ports, classes, attack map, stages)
packages/core/test/                 engine, phase2, phase3, phase4, benign, replay
packages/adapter-*/                 parsers, empty dependencies
packages/export-*/                  formatters, empty dependencies
docs/SPEC.md                        source of truth for behavior
docs/DEVELOPERS.md                  how a host feeds the engine
docs/progress/PHASE-0.md … PHASE-4.md
```

Root `package.json` is private (`iotwarden-workspace`). Workspaces are `packages/*`. DevDependencies live only at the repo root. `packages/core` `dependencies` must stay `{}`. Adapters and exporters also have empty `dependencies`.

## Hard rules for anyone editing this repo

- Node ≥ 22, CommonJS, `'use strict'`, JSDoc on every public function.
- `tsconfig.json` is `checkJs` plus `strict` and only includes `packages/core/src`. Inline `@param` on an arrow function gets moved by Prettier and then fails `tsc`. Use a named function.
- Do not add a runtime dependency.
- Do not change a threshold, default, severity, or formula unless `docs/SPEC.md` and `packages/core/CHANGELOG.md` change in the same edit.
- Do not skip, weaken, or delete a failing test. The six tests in `packages/core/test/engine.test.js` are the prototype and must keep passing.
- Do not block, drop, or rewrite traffic.
- Do not invent metrics.
- Reject object keys `__proto__`, `constructor`, and `prototype` on events, options, baselines, and indicators.
- Every `Set`, `Map`, or array that grows with traffic has a cap from options, and a test that hits the cap.
- Tests are deterministic. Use `packages/core/test/fixtures/prng.js`. No `Date.now()` and no `Math.random()` in tests. A test that needs `flush` passes an explicit `now`.
- Pack allowlist: `src/`, `README.md`, `LICENSE`, `CHANGELOG.md`, `SECURITY.md`, `package.json`. No `TODO`, `FIXME`, `console.log`, or token-shaped strings in packed files.
- JA4 is an opaque string the host supplies. Do not implement JA4, JA4S, JA4H, JA4X, JA4SSH, JA4T, or JA4D computation. JA4S and the rest are FoxIO-licensed. Core must not compute them.
- Core ships no threat feed, no ASN database, no country database, no Tor relay list, and no ad-domain list. The host passes `lookup()`, `loadIndicators()`, `browserJa4`, `dhcpServers`, `routers`, `zones`, and `gatewayIp`.

## Public API

```js
const { createEngine, detectors, SEVERITY } = require('iotwarden');
const engine = createEngine({ learnMs: 7 * 24 * 3600e3, tiers: ['T0'] });
engine.feed({ device, dst, bytes, ts });
engine.on('anomaly', (a) => {});
engine.flush();
```

Methods: `feed`, `feedBatch` (sorts by `ts`, does not mutate the input), `flush(now = Date.now())`, `lock`, `relearn`, `allow`, `suppress`, `ack`, `forget`, `setPeerGroup`, `setDeviceClass`, `use`, `stats`, `loadIndicators`, `exportBaseline`, `importBaseline`.

Events: `anomaly`, `incident`, `learned` `{device, ts}`, `device-new`, `warning`. A throwing listener is caught and re-emitted as `warning` `LISTENER_ERROR`.

`allow(device, kind, value)` kinds: `dst`, `port`, `asn`, `country`, `ja4`, `certIssuer`, `resolver`, `peer`.

Default options that matter: `learnMs` 7 days, `windowMs` 60 seconds, `tiers` `['T0']`, `sigma` 4, `minBytes` 1e6, `minFanout` 10, `fanoutFactor` 3, `peakFactor` 2, `maxNewDstPerWindow` 3. Those root keys override the original four detectors only when the host passes them. Newer detectors read tunables from their own `defaults` and from `detectors[id]` overlay, not from root keys.

## What 0.4.0 does not include

Phase 5 is not started: fuzz (100,000 seeded inputs), benchmarks, the evaluation harness, generated `docs/DETECTORS.md`, OpenWrt wiring docs.

Phase 6 is not started: GitHub repo, npm org, trusted publishing. Before any future publish the human still has to do a trademark search, create the npm org, and choose a disclosure email. `SECURITY.md` has no disclosure address yet. `repository`, `bugs`, and `homepage` are omitted until a GitHub remote exists.

Spec rows still unimplemented are listed in `03-DETECTORS.md`. The one row marked 0.4 that has no file is `identity-change`.
