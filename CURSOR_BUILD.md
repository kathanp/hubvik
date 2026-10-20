# CURSOR BUILD PLAYBOOK — IoT network anomaly detection package

Chosen package name: **hubvik** (2026-10-16, verdict CLEAR). `<pkg>` below means `hubvik`.

You are building an npm package from `docs/SPEC.md` (spec v2.1, 118 detectors). This file says **in what order**, **what "done" means**, and **when to stop**. `.cursor/rules/project.mdc` holds the rules that always apply.

## How to work

1. Do phases in order: 0 → 1 → 2 → 3 → 4 → 5 → 6. Never skip one, never merge two.
2. Inside a phase, do tasks in the listed order. Commit after each task once `npm run check` is green.
3. At the end of each phase, run the **GATE** commands. Append a short summary to `docs/progress/PHASES.md`: what was built, what was skipped and why, open questions, and the gate output.
4. **Then STOP and wait for the human to say "go".**
5. If a task is blocked for more than 2 attempts, stop and report. Do not paper over it.

Placeholder `<pkg>` = the npm package name chosen in Phase 0. Replace it everywhere once decided.

---

## PHASE 0 — Repo bootstrap and name check

### 0.1 Name check (do this first, before writing any package code)

Write `scripts/check-name.mjs` (Node built-ins only, `fetch` is global in Node ≥ 22):

- Input: one or more candidate names on argv.
- For each candidate, check:
  1. **Exact name:** `GET https://registry.npmjs.org/<name>` → 404 = free.
  2. **Punctuation variants:** npm rejects names that differ from an existing package only by `-` `_` `.`. Test the name with all punctuation removed and with each punctuation char inserted at word boundaries.
  3. **Similar names:** `GET https://registry.npmjs.org/-/v1/search?text=<name>&size=20`. List every result whose name contains the candidate with punctuation stripped, with description and maintainer.
  4. **Scope:** `GET https://registry.npmjs.org/@<name>%2fcore` → 404 means the package is free. It does not prove the org is free; print a reminder to create the org at npmjs.com/org/create.
  5. **GitHub:** `GET https://api.github.com/repos/<github-user>/<name>` → 404 = repo name free (unauthenticated is fine).
  6. **Trademark reminder:** print a link to search USPTO, plus EUIPO if selling in the EU. Do not try to automate this.
- Output: a table plus a verdict per candidate: `CLEAR`, `CONFLICT` (taken or punctuation clash), or `RISKY` (free, but an existing product with the same brand appears in search).

Run it:

```
node scripts/check-name.mjs cybershield edgewarden hubvik lanwarden devicewarden
```

**Known result on 2026-10-16:** `cybershield` is free on npm, but **RISKY**. A French security company (Securas) already publishes five "CyberShield WAF" packages: `cybershield-js`, `react-cybershield`, `angular-cybershield`, `plugin-cybershield`, `cyber-shield-express`. Same brand, same industry, so there is confusion and trademark-dispute risk; npm can transfer a name on a trademark claim. `edgewarden`, `hubvik`, `lanwarden` and `devicewarden` were free with no similar packages.

**STOP. Ask the human to pick the final name.** Do not continue until they answer.

### 0.2 Repository layout (npm workspaces)

```
<repo>/
  package.json                 # private: true, workspaces, devDeps, scripts
  .cursor/rules/project.mdc
  CURSOR_BUILD.md
  docs/
    SPEC.md                    # copy of the spec; source of truth
    QUESTIONS.md
    progress/
    adr/                       # architecture decision records, 1 page each
  packages/
    core/                      # name: <pkg>
      package.json             # dependencies: {}
      src/index.js
      src/index.d.ts
      src/engine/              # engine.js, window.js, validate.js, baseline.js, incidents.js, stats.js, caps.js
      src/detectors/           # one file per detector
      src/data/                # psl.json, attack-map.json, classes/*.json, ports.json
      test/
      README.md LICENSE CHANGELOG.md SECURITY.md
    adapter-conntrack/         # name: @<pkg>/adapter-conntrack   (Phase 2)
    adapter-dnsmasq/           # Phase 2
    adapter-zeek/              # Phase 4 (incl. ICSNPP logs)
    adapter-suricata-eve/      # Phase 4
    export-ocsf/               # Phase 4
    export-syslog/             # Phase 4
    export-webhook/            # Phase 4
  test/fixtures/               # shared simulator, PRNG, device profiles
  bench/
  fuzz/
  eval/
  scripts/
  .github/workflows/ci.yml
  .github/workflows/release.yml   # Phase 6
```

### 0.3 Root tooling

- `package.json` (root, `"private": true`) with `"engines": { "node": ">=22" }`.
- devDependencies, root only: `eslint` (flat config, `eslint:recommended` + `no-console` in src), `typescript` (only for `tsc --noEmit` on `.d.ts` + `checkJs`), `prettier`.
- Scripts:

| Script       | Command / purpose                                                                                                                             |
| ------------ | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `test`       | `node --test --test-reporter=spec "packages/*/test/**/*.test.js"`                                                                             |
| `coverage`   | `node --test --experimental-test-coverage --test-coverage-lines=90 --test-coverage-branches=80 "packages/*/test/**/*.test.js"`                |
| `lint`       | `eslint . && prettier --check .`                                                                                                              |
| `types`      | `tsc -p tsconfig.json --noEmit`                                                                                                               |
| `pack:check` | `node scripts/pack-check.mjs` (§0.5)                                                                                                          |
| `check`      | `npm run lint && npm run types && npm run test`                                                                                               |
| `gate`       | `npm run check && npm run coverage && npm run pack:check && npm run bench && npm run fuzz` (bench/fuzz are no-ops until Phase 5 creates them) |

- `.editorconfig`, `.gitignore` (`node_modules`, `coverage`, `*.tgz`, `eval/data/`, `.env*`, `.npmrc`).
- `.nvmrc` → `22`.

### 0.4 CI — `.github/workflows/ci.yml`

- Triggers: push, pull_request.
- Matrix: Node `22`, `24`, `26` × `ubuntu-latest`, `ubuntu-24.04-arm`. Gateways are mostly ARM, so ARM must pass.
- Steps: checkout → setup-node with cache → `npm ci` → `npm run gate`.
- `permissions: contents: read`. Pin actions to full commit SHAs, not tags.

### 0.5 `scripts/pack-check.mjs`

Runs `npm pack --dry-run --json` in every publishable workspace and fails if:

- any file outside `src/`, `README.md`, `LICENSE`, `CHANGELOG.md`, `SECURITY.md`, `package.json` is included;
- `packages/core` has any `dependencies`;
- the tarball is > 500 KB unpacked;
- any file contains `TODO`, `FIXME`, `console.log`, or a string matching a token pattern (`npm_[A-Za-z0-9]{36}`, `ghp_`, `github_pat_`).

### 0.6 Move the prototype in

Copy the existing 0.0.1 files into the new layout: `src/index.js`, `test/engine.test.js`, `examples/camera-botnet.js`. Run the 6 existing tests unchanged; they must pass before Phase 1 starts. This is the regression baseline.

### 0.7 Git

`git init`, main branch `main`, first commit. **No remote yet.**

### GATE 0

```
node scripts/check-name.mjs <chosen-name>   # verdict CLEAR
npm ci && npm run check                     # 6/6 prototype tests pass
```

Append the Phase 0 section to `docs/progress/PHASES.md`. **STOP.**

---

## PHASE 1 — Engine core (release 0.1.0)

Spec: Part A (A1–A7), spec-v1 gaps, Appendix (9 acceptance tests).

### 1.1 Test fixtures first

`test/fixtures/`:

- `prng.js`: mulberry32 seeded PRNG.
- `clock.js`: helpers `T0`, `H`, `DAY`, `at(day, hour, min)`.
- `profiles.js`: synthetic benign device classes with realistic numbers:

| Class             | Benign traffic profile                                                     |
| ----------------- | -------------------------------------------------------------------------- |
| `camera`          | 2 Mbps upstream (~15 MB/min) to 1–2 vendor hosts, NTP, DNS, 24/7           |
| `thermostat`      | ≤ 50 KB/h, 3 hosts, MQTT 8883                                              |
| `plug`            | heartbeat every 30 s ± jitter to 1 host                                    |
| `tv-box`          | evenings, large downloads, 30–80 CDN domain families, browser-class JA4    |
| `hvac-controller` | BACnet reads every 10 s from 1 BMS server, writes only in schedule windows |
| `hub`             | LAN peers + 5 cloud hosts                                                  |
| `printer`         | bursty, mostly idle                                                        |

- `sim.js`: `simulate({ profile, days, seed, startTs }) → Event[]` producing T0–T5 events per profile, with jitter.
- `attacks.js`: generators `mirai(ts)`, `portScan`, `udpFlood`, `dnsTunnel`, `dga`, `proxyRelay`, `bacnetWrite`, etc. Built incrementally as detectors land.

### 1.2 Engine refactor (`src/engine/`)

Implement in this order, each with tests:

1. `validate.js`: event, option, indicator and baseline validators (A2.1, A6). Messy optional fields → dropped and counted, not thrown.
2. `window.js`: epoch-aligned windows. **`flush(now)` closes only windows whose end ≤ now.** Idle windows are counted as zero-byte windows during learning.
3. `caps.js`: LRU-bounded Set/Map helpers used everywhere.
4. `engine.js`: lifecycle (learning/watching, lock, relearn, forget, allow, suppress, ack), detector registry, tier routing (A2), listener isolation (throwing listener → `warning LISTENER_ERROR`), events `anomaly`/`learned`/`device-new`/`warning`.
5. Detector interface (A5) + `engine.use(detector)`.
6. `baseline.js`: format v2, read/upgrade v1, `windowMs` check, validation-before-mutation, optional HMAC-SHA256 sign/verify via `node:crypto`.
7. `stats.js`: counters, active/disabled detectors with reason, memory estimate.
8. Anomaly shape (A7) with monotonic `id`, `category`, `confidence`, `attack`, `hardRule`.

### 1.3 Port the 4 original detectors as plugins

`new-destination`, `fan-out`, `volume-spike` (with idle windows), `wrong-time` (with `dayOf` matching `hourOf`).

### 1.4 Types and docs

- `src/index.d.ts` covering every public API and every event payload.
- README: install, quick start, tiers table, detector table (only shipped detectors), options, limits, "status: prototype, not validated on real traffic".

### 1.5 Tests required in Phase 1

- The 6 prototype tests, unchanged.
- The 9 acceptance tests (Appendix).
- Validation tests for every option and every malformed input.
- Memory: 1,000,000 distinct `dst` values keep heap growth < 20 MB (`--expose-gc`, `process.memoryUsage().heapUsed`).
- Determinism: same seed → identical anomaly stream.

### GATE 1

```
npm run gate        # lint, types, tests, coverage ≥ 90 % lines / 80 % branches, pack-check
npm run demo        # still prints the hijack story
```

Version `packages/core` → `0.1.0`. `CHANGELOG.md` entry. Append the Phase 1 section to `docs/progress/PHASES.md`. **STOP.**

---

## PHASE 2 — Flows, DNS, hard rules (release 0.2.0)

Spec: A2 tiers T1+T2, B10 hard rules, and every detector marked `Rel 0.2`.

### 2.1 Input

T1 `flow` and T2 `dns` event types, normalization (lowercase, punycode, IPv4-mapped IPv6), dropped-field counting.

### 2.2 Hard-rule framework

`hardRule: true` detectors run during learning. Add `SUSPICIOUS_LEARNING` warnings (B10).

### 2.3 Data files

- `src/data/psl.json`: Public Suffix List snapshot + `scripts/update-psl.mjs`.
- `ports.json`: risky ports.
- `attack-map.json`: MITRE ATT&CK IDs.

### 2.4 Detectors, one commit each, in this order

| Order | Detectors                                                                                                     |
| ----- | ------------------------------------------------------------------------------------------------------------- |
| 1     | `new-domain-family`, `new-port`, `new-protocol`, `inbound-from-wan`, `bogon-destination`                      |
| 2     | `threat-intel-match` + `engine.loadIndicators()` (IP, CIDR tree, domain suffix, JA4; expiry)                  |
| 3     | `horizontal-scan`, `vertical-scan`, `failed-connection-ratio`, `lan-lateral`                                  |
| 4     | `volume-spike-hourly`, `upload-ratio-shift`, `packet-flood`, `reflection-participation`, `coap-amplification` |
| 5     | `went-silent`, `nxdomain-burst`, `resolver-bypass`, `dns-rebinding`, `private-answer-for-public-name`         |
| 6     | `new-device`, `policy-violation` (declarative rule DSL as JSON, validated)                                    |
| 7     | `adb-exposure`, `mqtt-new-broker`, `spam-relay`, `tftp-activity`                                              |
| 8     | `posture-listening-risky`, `posture-wan-exposed`                                                              |
| 9     | Integrity: `input-gap`, `clock-jump`, `state-cap`, `alert-storm`                                              |

### 2.5 Adapters (separate workspaces, zero deps)

- `adapter-conntrack`: parses `conntrack -L -o extended` and `conntrack -E` event lines → T1.
- `adapter-dnsmasq`: parses `log-queries=extra` lines → T2.

Both ship fixture log files and stream-friendly APIs (`createParser().write(line)`).

### GATE 2

```
npm run gate
node --test packages/core/test/benign-matrix.test.js   # every class × 14 days × 3 seeds → 0 anomalies ≥ medium
```

Bump to `0.2.0`. **STOP.**

---

## PHASE 3 — Proxyware, link layer, incidents (release 0.3.0)

Spec: B12 (proxyware) first, then the rest of `Rel 0.3`, plus T4, C1, C2 and B19 class priors.

| Order | Work                                                                                                                                                                       |
| ----- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1     | **Device-class priors** (B19): `src/data/classes/*.json`, `engine.setDeviceClass(device, cls)`, `class-violation` hard rule                                                |
| 2     | **B12:** `proxy-relay`, `blockchain-c2`, `supply-chain-suspect`                                                                                                            |
| 3     | `direct-ip`, `new-asn`/`new-country` (host-supplied lookup function; core ships no DB), `upnp-port-open`, `tor-or-proxy`                                                   |
| 4     | `lan-sweep`, `brute-force-out`, `brute-force-in`                                                                                                                           |
| 5     | `slow-exfil` (CUSUM), `protocol-mix-shift`, `connection-churn`                                                                                                             |
| 6     | `new-beacon` (only non-baseline destinations; MAD/median + skew + count ≥ 20), `long-connection`                                                                           |
| 7     | `dga` (entropy + bigram table + vowel/digit ratio; burst-based), `dns-tunnel` (combined score)                                                                             |
| 8     | **T4:** `arp`, `dhcp`, `ra`, `discovery` events. Detectors: `arp-spoof`, `gratuitous-arp-flood`, `rogue-dhcp`, `dhcp-starvation`, `rogue-ra`, `src-spoof`, `icmp-redirect` |
| 9     | `zone-violation`, `stream-to-new-destination`, `cryptomining`, `ot-wan-exposure`                                                                                           |
| 10    | B16 tunnels: `tunnel-service`, `vpn-protocol`, `icmp-tunnel`, `ipv6-tunnel`, `ntp-rogue`                                                                                   |
| 11    | B17: `update-from-new-source`, `update-over-cleartext`, `post-update-drift`                                                                                                |
| 12    | `posture-cleartext-auth`                                                                                                                                                   |
| 13    | **Incidents** (C1): staging, risk score with decay, `ack`, one-line summary. **ATT&CK** (C2): `attack` on every anomaly via `attack-map.json`                              |

Attack replay tests:

- `test/replay/badbox-like.test.js`: a `tv-box` that runs proxy-relay from hour 0. Expect `supply-chain-suspect` + `proxy-relay` during learning.
- `test/replay/kimwolf-like.test.js`: proxy session → LAN 5555 sweep → ADB connect → ENS/RPC lookups. Expect a ≥ 3-stage incident.
- `test/replay/mirai-like.test.js`: telnet scan + GRE flood.

### GATE 3

```
npm run gate
node --test packages/core/test/replay/
node --test packages/core/test/benign-matrix.test.js
```

Bump to `0.3.0`. **STOP.**

---

## PHASE 4 — TLS, OT/building automation, fleet (release 0.4.0)

| Order | Work                                                                                                                                                                                                                                                                                            |
| ----- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1     | **T3** `tls`/`http` events. Detectors: `new-client-fingerprint`, `cert-change`, `sni-missing`, `tls-on-odd-port`, `cleartext-regression`, `browser-mimic`, `posture-weak-tls`. JA4 is accepted as a string only; **do not implement JA4S/H/X/SSH/T/D computation** (FoxIO License, see spec B6) |
| 2     | `proxy-backconnect`, `lan-via-proxy`, `p2p-pattern`, `credential-stuffing-out`, `ad-fraud`, `quic-new`                                                                                                                                                                                          |
| 3     | `beacon-change`, `answer-drift`, `fast-flux`                                                                                                                                                                                                                                                    |
| 4     | **T5** `app` events. **B13 OT:** `ot-new-master`, `ot-write-new`, `ot-dangerous-op`, `ot-value-out-of-range`, `ot-write-rate`, `ot-recon`, `ot-spoof`, `ot-error-burst`                                                                                                                         |
| 5     | **B14:** `mqtt-wildcard-subscribe`, `mqtt-topic-new`, `mqtt-publish-rate`, `onvif-config-change`                                                                                                                                                                                                |
| 6     | **B9 fleet:** `setPeerGroup`, `peer-divergence`, `fleet-wave`                                                                                                                                                                                                                                   |
| 7     | Adapters: `adapter-zeek` (`conn`, `dns`, `ssl`, `http`, `modbus`, `dnp3`, `mqtt_*` logs + CISA ICSNPP `bacnet`/`s7comm`/`enip` logs, JSON format), `adapter-suricata-eve` (`flow`, `dns`, `tls`, `http`, `alert` passthrough)                                                                   |
| 8     | Exporters: `export-ocsf` (Detection Finding), `export-syslog` (RFC 5424 + CEF), `export-webhook` (retry with backoff, HMAC signature header)                                                                                                                                                    |

Replay tests:

- `bms-hijack.test.js`: new master → `WriteProperty` out of range → `DeviceCommunicationControl`.
- `mitm.test.js`: cert issuer change for a known SNI.

### GATE 4

```
npm run gate
node --test packages/*/test/   # all workspaces
```

Bump core to `0.4.0`; adapters/exporters to `0.1.0`. **STOP.**

---

## PHASE 5 — Hardening, benchmarks, evaluation, docs

### 5.1 Fuzz

`fuzz/feed.fuzz.js` and `fuzz/baseline.fuzz.js`: 100,000 seeded random/malformed inputs. The engine must never throw on a valid shape, never hang, and never exceed caps. `npm run fuzz` exits non-zero on failure.

### 5.2 Benchmarks

`bench/feed.bench.js`:

- 10,000 devices with mixed profiles, all detectors on.
- Report: median and p99 `feed()` time, per-device memory.
- CI enforces a proxy budget on x86: **median < 10 µs, memory < 100 KB per device.** Record the real Raspberry Pi 4 numbers manually in `docs/BENCHMARKS.md`; the human runs that.

### 5.3 Evaluation harness (C6) — numbers only from real runs

`eval/README.md` gives the human the steps:

1. Download the datasets: CICIoT2023, IoT-23, N-BaIoT. They are large, so they are **not** committed.
2. Run Zeek on the PCAPs.
3. Run `node eval/run.mjs --dataset <name> --zeek-logs <dir>`.

The script feeds events through `adapter-zeek` into the engine, joins anomalies with dataset labels, and writes `eval/results/<dataset>.json` + `.md`:

- detection rate per attack class;
- time-to-detect;
- false positives per device-day on benign traffic.

**Cursor writes the harness. The human runs it.** README numbers come only from these files.

### 5.4 Docs

- `README.md`: rewrite with tiers, every shipped detector, "how to wire it on OpenWrt" example, limits, eval results table (or "not yet evaluated").
- `docs/DETECTORS.md`: generated by `scripts/gen-detector-docs.mjs` from each detector's metadata. Never hand-written.
- `SECURITY.md`: disclosure email, 90-day policy, supported versions.
- `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`.
- `examples/`: camera-botnet, badbox-tvbox, bms-hijack, openwrt-conntrack-dnsmasq.

### GATE 5

```
npm run gate     # now includes bench + fuzz
```

Every `Rel ≤ 0.4` detector in SPEC has a file, a test and a docs entry: `node scripts/spec-coverage.mjs` parses SPEC tables and fails on any gap. **STOP.**

---

## PHASE 6 — GitHub and npm release (human-run, Cursor prepares)

Cursor prepares everything below. The human runs every command that touches GitHub or npm.

### 6.1 Cursor prepares

1. `.github/workflows/release.yml`:
   - Trigger: tag `v*`.
   - Permissions: `contents: read`, `id-token: write` (OIDC).
   - Steps: `npm ci` → `npm run gate` → publish **core first, then adapters/exporters** with `npm publish --workspace <ws> --access public`.
   - Uses **npm trusted publishing** (no `NPM_TOKEN` secret). Provenance is attached automatically.
2. `scripts/release-checklist.mjs`: verifies version bumps, CHANGELOG entries, a clean git tree, the gate passing, `npm pack --dry-run` contents; prints the exact commands below.
3. `.github/dependabot.yml` (npm devDeps + actions), `CODEOWNERS`, issue/PR templates.

### 6.2 Human steps, in order

1. **Accounts:**
   - Turn on npm 2FA (WebAuthn preferred).
   - Create the npm org `<pkg>`, needed for the `@<pkg>/*` adapter packages.
   - Turn on GitHub 2FA.
2. **Final name re-check** (names can be taken at any time): `node scripts/check-name.mjs <pkg>` → CLEAR.
3. **GitHub:**
   ```
   gh repo create <github-user>/<pkg> --public --source . --remote origin
   git push -u origin main
   ```
   In repo settings: protect `main` (require CI), enable secret scanning + push protection, private vulnerability reporting.
4. **First npm publish is manual.** Trusted publishing is configured per package on npmjs.com, so each package must exist first.
   ```
   npm login
   npm run gate
   cd packages/core && npm publish --access public    # 2FA prompt
   # repeat for each @<pkg>/* workspace
   ```
5. **Configure trusted publishing** on npmjs.com for every package: GitHub Actions, repo `<github-user>/<pkg>`, workflow `release.yml`. Then delete any npm tokens created.
6. **Later releases:** bump versions + CHANGELOG, then `git tag v0.x.y && git push --tags`. The workflow publishes.
   - Optional stricter mode: switch the workflow to `npm stage publish` (npm CLI ≥ 11.15, Node ≥ 22.14). Each release then waits for your 2FA approval.
7. **Verify after publish:**
   - `npm view <pkg>` shows the version and provenance.
   - In a temp folder: `npm i <pkg> && node -e "require('<pkg>')"` runs the quick-start.

### GATE 6 (release done)

- Package page shows the README, version, provenance badge and repo link.
- A fresh install runs the README quick start.
- GitHub CI is green on `main` and the tag.

---

## Version rules recap

- Never publish `1.0.0` from this playbook. 1.0 requires the spec's C6 evaluation results **and** a 30-day real deployment pilot. Highest version this playbook produces: `0.4.x`.
- The README status line stays "prototype — not validated on real traffic" until eval results exist.
