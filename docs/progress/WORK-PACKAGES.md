# Work packages 0–10

Spec 3.0 notes. WP-9 was not run. Core was `iotwarden@0.4.0` through WP-10, then bumped to `0.5.0` after checkpoint B. Not validated on real traffic.

## WP-0

Date: 2026-10-17.

`scripts/spec-coverage.mjs` parses every Part B table that has an `ID` column and a `Rel` column. It writes `docs/DETECTORS.md` and is part of `npm run gate`. Every shipped detector exports `meta` with `rel`, `fpRisk`, and, when the JSON tables have them, `attack` and `stage`. `type: 'discovery'` was already accepted. An unknown proto is dropped with `warning` `FIELD_DROPPED`. A known proto (`mdns`, `ssdp`, `ws-discovery`, `coap`) is kept. The B7 `identity-change` cell said `00.5` and is now `0.5`. `class-violation` gained a B19 row: severity high, Rel 0.3.

`identity-change`, `tier-silent`, `egress-flood`, and `proxy-sdk-traffic` were Rel 0.5 and not yet implemented.

Gate: 92/92 tests, 97.19% lines, 84.97% branches. Pack-check: core 146 files, 305543 bytes unpacked. `spec-coverage`: 122 rows, 105 detector files. Demo stages: c2, recon, impact.

## WP-1

Date: 2026-10-17.

`packages/core/test/benign-matrix-tiers.test.js`: tiers T0–T5, every profile including `smart-tv`, 14 days × seeds 1, 2, and 3. No anomaly at medium or above. The test printed `low/info anomalies: none`. `simulate({ rich: true })` emits flow, DNS, TLS, DHCP, and ARP on the same schedule as the T0 summaries. Thermostat profiles also emit MQTT publishes. HVAC profiles also emit BACnet reads and scheduled writes. The default `simulate()` path is unchanged. Ordinary noise: the DHCP lease moves from `192.0.2.10` to `192.0.2.11` on day 2, DNS A answers alternate `1.2.3.10` and `1.2.3.11`, NTP goes to `1.1.1.1` and `9.9.9.9` every day, and one 30 MB firmware download arrives on day 1. `smart-tv` is a profile and a class file so `setDeviceClass` accepts it.

`answer-drift` used to replace a name's learned keys with the latest lookup. Learning now keeps the union, up to 8 keys. A key that was never seen while learning still alerts. No numeric detector threshold, default, or severity changed. No detector was disabled.

| Item                               | Before                         | After                                    |
| ---------------------------------- | ------------------------------ | ---------------------------------------- |
| `answer-drift` learned keys        | latest lookup replaces the set | union of keys seen while learning, cap 8 |
| `smart-tv` `maxFamilies`           | class did not exist            | 120                                      |
| `smart-tv` `maxUploadBytesPerHour` | class did not exist            | 50000000                                 |
| `smart-tv` `allowsInboundLan`      | class did not exist            | false                                    |

Gate: 93/93 tests, 97.39% lines, 85.78% branches. Pack-check: core 147 files, 306113 bytes unpacked. `spec-coverage`: 122 rows, 105 detector files, core 0.4.0. Pending Rel 0.5 rows: `identity-change`, `tier-silent`, `egress-flood`, `proxy-sdk-traffic`. Demo stages: c2, recon, impact.

## WP-2

Date: 2026-10-17.

Bare `flush()` drains every open window whose start is at or before the watermark, then calls `tick(watermark)`. `flush(now)` still closes only windows whose end is at or before `now`. A backward step inside the open window is accepted. `reorderMs` only extends tolerance before that window. After a drain, an event in the closed window is `LATE_EVENT`. `went-silent` stays on `tick()`.

`event-time.test.js` covers the drain, `flush(now)`, late events after a drain, in-window reorder, and the 2 s and 10 s skew cases. `went-silent.test.js` covers an unplugged camera, `forget()`, and a restart ticked at the watermark.

Fast check: 101/101 tests, duration 72443.960583 ms.

| Item                    | Before                                                            | After                                  |
| ----------------------- | ----------------------------------------------------------------- | -------------------------------------- |
| bare `flush()`          | `Date.now()`, then the watermark, and the open window stayed open | drains windows whose start ≤ watermark |
| in-window backward step | `CLOCK_JUMP` when `reorderMs` is 0                                | accepted                               |
| `reorderMs`             | not an option                                                     | 0                                      |
| `went-silent`           | next event                                                        | `tick()`                               |

## WP-3

Date: 2026-10-17.

`tier-silent` fires when an enabled tier has had no events for 6 h while another enabled tier is still live. Learning warnings use `SUSPICIOUS_LEARNING` with one of six reasons. `stats().learningQuality` reports windows, families, suspicious reasons, and `ready`. `minLearnWindows` defaults to 0. A device held past `learnMs` emits `LEARNING_EXTENDED` once. `lock()` on a device that is not ready emits `LOCKED_UNREVIEWED` and still enters watching.

The all-tier simulator keeps every enabled tier fresh: a one-byte T0 summary beside each flow, DHCP and ARP once per active hour, and a quiet MQTT publish on classes that do not already emit an app event. That is fixture traffic. `tier-silent` still treats a tier that was never seen as quiet.

`learning-quality.test.js` fires each suspicious-learning reason, `LOCKED_UNREVIEWED`, and `LEARNING_EXTENDED`. `tier-silent.test.js` stops DNS for 6 h and expects the DNS detectors named on tier T2. Both benign matrices assert no `SUSPICIOUS_LEARNING` warnings.

Fast check: 104/104 tests, duration 110624.197292 ms.

| Item              | Before        | After       |
| ----------------- | ------------- | ----------- |
| `minLearnWindows` | not an option | 0           |
| `tierSilentMs`    | not an option | 21600000 ms |

## WP-4

Date: 2026-10-17.

Anomalies include `schema` 1, a SHA-256 `fingerprint` (first 16 hex chars of detector, device, and actual text), and `evidence` unless `createEngine({ evidence: false })`. `evidence.sample` drops the engine-stamped `tier` and stays at most one event of 1 KB. `dns-rebinding` and `private-answer-for-public-name` share `dedupGroup` `private-answer`. `reflection-participation` and `coap-amplification` share `reflection`. `proxy-relay` and `credential-stuffing-out` share `proxy-relay`. An incident scores one contribution per group: the highest severity weight times confidence.

`evidence.test.js`: a `0.0.0.0` answer still emits both detectors, the incident score is 45, and the fingerprint matches after `exportBaseline` / `importBaseline`. A second test omits `evidence` when the option is false.

Fast check: 106/106 tests, duration 55952.209209 ms. No threshold changed.

## Checkpoint A

Date: 2026-10-17. After WP-4.

Gate passed. Coverage run: 106/106 tests, lines 97.58%, branches 86.26%. Pack-check: core 148 files, 319951 bytes unpacked. `spec-coverage`: 122 rows, 106 detector files, core 0.4.0. Pending: `identity-change`, `egress-flood`, `proxy-sdk-traffic`. Bench and fuzz were still no-ops. Demo printed `went-silent`, `volume-spike`, `volume-spike-hourly`, and incident stages c2, recon, impact.

## WP-5

Date: 2026-10-17.

DHCP events accept an opaque `fingerprint` of at most 255 characters. `identity-change` learns one fingerprint per MAC while the device is learning, keeps at most 5,000 MACs on the shared scratch table, and alerts at high severity while watching when that MAC presents a different fingerprint. A MAC that was never learned does not alert.

`identity-change.test.js`: fires after lock, stays quiet for 14 rich days on every profile, stops at 5,000 MACs and rejects a larger import, and keeps the learned fingerprint across export and import. `spec-coverage` no longer lists `identity-change` as pending.

Fast check: 110/110 tests, duration 55210.524084 ms. MAC cap: none → 5000.

## WP-6

Date: 2026-10-17.

`egress-flood` reports a one-way flow to a public address that reaches 50,000 packets or 200 MB in one window. While watching it also reports at least 5,000 packets and ten times the learned per-destination maximum. `proxy-sdk-traffic` matches a host-supplied `proxy-sdk` indicator on `qname`, `dstName`, or SNI. Severity is medium, with `consentPossible: true`, on `smart-tv` and `tv-box`, and high otherwise. `packet-flood` already reported `bytesPerPacket`. It shares `dedupGroup` `flood` with `egress-flood`. `browser-mimic` reads `allowsBrowserJa4`. That flag is true for `tv-box`, `nas`, `hub`, and `smart-tv`.

`test/replay/large-udp-flood.test.js` and `test/replay/smart-tv-proxy-sdk.test.js`. `browser-mimic.test.js` keeps a smart TV quiet and fires on a camera. `egress-flood.test.js` covers the learned-maximum path. `proxy-sdk-traffic.test.js` expects high severity on a camera. The all-tier benign matrix still passed.

Fast check: 115/115 tests, duration 103295.441083 ms.

| Item                       | Before         | After                              |
| -------------------------- | -------------- | ---------------------------------- |
| `egress-flood.minPkts`     | not a detector | 50000                              |
| `egress-flood.minBytesOut` | not a detector | 200000000                          |
| `egress-flood.watchFactor` | not a detector | 10                                 |
| `egress-flood.watchFloor`  | not a detector | 5000                               |
| `allowsBrowserJa4`         | hard-coded set | true on tv-box, nas, hub, smart-tv |

## WP-7

Date: 2026-10-17.

`checkpoint()` writes the baseline, the watermark, per-device learning progress, and the LAN scratch tables (`arp-spoof`, `identity-change`, `dhcp-starvation`, `fleet-wave`). A snapshot over 16 MB drops the oldest ARP bindings, then the oldest learned MACs, and emits `CHECKPOINT_TRUNCATED`. `restore()` checks the snapshot, including the same HMAC path as baselines, and replaces state only after that check. An unknown scratch table is rejected.

`checkpoint.test.js`: an ARP binding survives restore and the next claim of the gateway IP is `arp-spoof`. A fresh engine that never saw the original binding stays quiet. One thousand seeded corrupt checkpoints throw and leave the baseline unchanged.

Fast check: 117/117 tests, duration 92336.939792 ms. Checkpoint cap: none → 16 MB.

## WP-8

Date: 2026-10-17.

`npm run fuzz` runs 100,000 seeded inputs through `feed()`, `importBaseline()`, and `restore()`. `npm run bench` times `feed()` with every tier on. `spec-coverage` treats Rel 0.5 as due while the package is still 0.4.0, so a missing 0.5 row fails.

The fuzz scripts rejected 33,401 of 100,000 feed inputs and all 100,000 baseline and checkpoint inputs, then accepted one more event. No prototype pollution.

Fast check: 117/117 tests, duration 156587.972375 ms. No threshold changed. Bench median `feed()` was 24.29 µs and memory was 2.46 KB per device. The 10 µs budget was missed. The number is in `docs/BENCHMARKS.md`. The detectors were not tuned.

## WP-10

Date: 2026-10-17. Package: `@iotwarden/export-ocsf@0.2.0`.

`toFinding(record, { ocsfVersion })` defaults `ocsfVersion` to `1.4.0` and writes it into `metadata.version`. `fingerprint` is `finding_info.uid`. `evidence.sample` is `evidences[]` and is left off when the record has no evidence. A record with `anomalyIds` is an Update (`activity_id` 2, `type_uid` 200402).

`finding.test.js` checks one anomaly and one escalated incident against the hand-written 1.4.0 fixture, and checks that `ocsfVersion: '1.6.0'` appears in `metadata.version`.

Fast check: 118/118 tests, duration 117312.105208 ms. `ocsfVersion`: none → 1.4.0.

## Checkpoint B

Date: 2026-10-17. After WP-10, before the version bump.

Gate passed. Coverage run: 118/118 tests, lines 97.50%, branches 86.67%. Pack-check: core 152 files, 337414 bytes unpacked. `spec-coverage`: 122 rows, 109 detector files, core 0.4.0. Bench median 25.75 µs, 2.46 KB/device. Fuzz rejected 33,401 of 100,000 feed inputs and all 100,000 baseline and checkpoint inputs. Demo printed `went-silent`, `volume-spike`, `volume-spike-hourly`, and incident stages c2, recon, impact.

Core was then bumped to `0.5.0` locally and not published.

## WP-8.1 — tier-silent

Date: 2026-10-17.

A tier is armed by its first event. A tier that has never been seen does not alert. Each tier has its own silence limit. The default stays 6 h. T4 defaults to 26 h, because DHCP and ARP in the benign simulator are once a day. An armed tier alerts only when that limit has passed and some other armed tier has produced an event within the 6 h default. The simulator padding from WP-3 is gone: no 1-byte T0 summaries, DHCP and ARP once per day again, and no filler MQTT.

`tier-silent.test.js` covers a quiet DNS tier, a never-seen tier, and T4 quiet at 7 h then alerting at 26 h. The all-tier benign matrix passes without the padding.

| Threshold          | Before                          | After                 |
| ------------------ | ------------------------------- | --------------------- |
| `tierSilentMs`     | 6 h, including never-seen tiers | 6 h, armed tiers only |
| `tierSilentByTier` | none                            | T4 26 h               |

Fast check: 120/120 tests, duration 38274.549375 ms.

## WP-8.1 — fingerprint

Date: 2026-10-17.

`fingerprint` hashes the detector, the device, and a stable dedup key. It does not hash `actual`. A detector may set `dedupKey`. Otherwise the key is the non-magnitude fields of `data`. A horizontal scan's key is the destination port.

`fingerprint.test.js`: one telnet scan fires at 11 hosts during learning and at 76 hosts after lock. The display text differs. The fingerprint matches.

Fast check: 121/121 tests, duration 37988.776 ms.

## WP-8.1 — identity-change

Date: 2026-10-17. Revises D-7.

During learning the first DHCP fingerprint for a MAC is kept. A later fingerprint emits `SUSPICIOUS_LEARNING` reason `identity-change` and does not replace it. While watching, a different fingerprint still alerts at high, and `data.previous` is the first fingerprint.

`identity-change.test.js` expects the warning during learning and an alert after lock whose previous value is `1,3,6`. The benign matrices emit no `SUSPICIOUS_LEARNING`.

Fast check: 121/121 tests, duration 38381.363792 ms.

## WP-8.1 — went-silent on the demo

Date: 2026-10-17.

The demo prints `went-silent: silent for 2h` at `tick(awake + 2h)`. That tick is two hours after the last event, and the learned limit is 15 minutes, so the camera is not sending when the alert fires. The hijack events are fed after that tick. A device that keeps the learned 5-minute cadence, ticked at each event, stays quiet. The detector was not changed.

Fast check: 122/122 tests, duration 38723.986041 ms.

## WP-8.1 — mutation fuzz

Date: 2026-10-17.

`fuzz/mutate.fuzz.js` starts from one valid baseline and one valid checkpoint, then applies 100,000 seeded mutations to each. A mutation that imports and still accepts a later `feed()` is accepted. A thrown validation error is rejected. `restore()` now rejects a known scratch table with the wrong shape, which is what a mutated `fleet-wave` table was doing before it crashed `feed()`.

| Input      | Accepted | Rejected |
| ---------- | -------- | -------- |
| baseline   | 58,132   | 41,868   |
| checkpoint | 57,967   | 42,033   |

Fast check: 123/123 tests, duration 63370.813875 ms. The mutation run itself is part of `npm run fuzz`, not the fast check.

## WP-8.1 — bench

Date: 2026-10-17.

`bench/run.js` feeds 1,000 devices past `learnMs`, calls `lock()`, then times watching-state `feed()`. A miss exits non-zero, so `npm run gate` fails.

Measured: median 22.38 µs, 2.34 KB/device, 1,000 devices. The 10 µs budget was missed. The 100 KB budget was met. The number is in `docs/BENCHMARKS.md`. The detectors were not tuned.

Fast check: 123/123 tests, duration 156276.364334 ms. The fast check does not run the bench.

## WP-8.1 — release row

Date: 2026-10-17. Decision D-10.

Core stays `0.5.0`. SPEC C10 row 0.5 **Met?** is `No — bench median 22.38 µs, budget < 10 µs`. Reverting the package to 0.4.0 would not make that budget true, and the 0.5 detectors are already in the tree.

Fast check: 123/123 tests, duration 97295.495834 ms.

## WP-8.1 — docs

Date: 2026-10-17.

`docs/handoff/01-PROJECT.md`, `docs/handoff/03-DETECTORS.md`, and `docs/DEVELOPERS.md` now match the tree: core 0.5.0, export-ocsf 0.2.0, 109 detectors, `identity-change`, `tier-silent`, `egress-flood`, `proxy-sdk-traffic`, `checkpoint` / `restore`, and a bench that fails the gate at 22.38 µs.

Fast check: 123/123 tests, duration 137387.237 ms.

## WP-8.1 — gate

Date: 2026-10-17.

`npm run gate` passed check, coverage, pack-check, and spec-coverage, then the bench exited 1. Fuzz did not run in this gate because the bench failed first.

Coverage: 123/123 tests, lines 97.30%, branches 86.54%. Pack-check: core 152 files, 341715 bytes unpacked. `spec-coverage`: 122 rows, 109 detector files, core 0.5.0, ok. Bench median 21.04 µs, 2.34 KB/device, 1,000 devices.

## WP-8.2 — profile

Date: 2026-10-17.

`node --cpu-prof` on watching-state summary `feed()` with every tier on. The top self-time functions are in `docs/BENCHMARKS.md`. `_run` is 24.3% and `_optionsFor` is 23.2%.

## WP-8.2 — dispatch

Date: 2026-10-17.

Each detector declares `meta.consumes`. `feed()` runs only the detectors that list the event type. An empty array still runs on window close and on engine signals. `spec-coverage` fails when `consumes` is missing. Fast check: 125/125.

## WP-8.2 — bench

Date: 2026-10-17.

Watching-state median before dispatch: 22.38 µs (gate rerun 21.04 µs). After: 6.04 µs, 1.19 KB/device. The 10 µs budget is unchanged. `node bench/run.js` exited 0.

## WP-8.2 — gate

Date: 2026-10-17.

`npm run gate` runs check, coverage, pack-check, spec-coverage, fuzz, then the bench. A failed step does not skip the rest. The process exits non-zero and lists every failure.
