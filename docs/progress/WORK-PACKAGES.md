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

## WP-8.2 — mutation fuzz

Date: 2026-10-17.

Every accepted mutation kept collection caps, left `Object.prototype` clean, and matched `export` → `import` → `export` with `createdAt` fixed at 1.

Baseline: 100,000 inputs, 58,132 accepted, 41,868 rejected. Checkpoint: 100,000 inputs, 57,967 accepted, 42,033 rejected.

## WP-8.2 — tier never seen

Date: 2026-10-17.

A tier in `tiers` with no events once time reaches the first event plus `learnMs` emits warning `TIER_NEVER_SEEN` once. It is not an anomaly. `tier-silent` still stays quiet for a tier that was never armed.

## WP-8.2 — fingerprint allow

Date: 2026-10-17.

`allow(device, 'fingerprint', value)` is an allow kind. `identity-change` does not alert after lock when the presented fingerprint was allowed. A fingerprint that was not allowed still alerts.

## WP-8.2 — gate

Date: 2026-10-17.

`npm run gate` exited 0. Check 127/127. Coverage lines 97.23%, branches 85.14%. Pack-check: core 152 files, 350905 bytes unpacked. `spec-coverage`: 122 rows, 109 detector files, core 0.5.0, ok. Fuzz: feed 100,000 inputs, 33,401 rejected; baseline 100,000 rejected; checkpoint 100,000 rejected; baseline mutation 58,132 accepted / 41,868 rejected; checkpoint mutation 57,967 accepted / 42,033 rejected. Bench median 6.13 µs, 1.19 KB/device. The 10 µs budget is unchanged. C10 row 0.5 Met? records this pass. Core stays 0.5.0.

## WP-8.3 — dispatch differential

Date: 2026-10-17.

`test/diff/dispatch.test.js` replays every replay test, both attack generators, and the all-tier benign matrix for seeds 1–3. The anomaly stream and `exportBaseline()` match `test/diff/golden.json`, captured at `0a1755b` (the commit before `da835a0`). No detector stream or exported state changed, so no `consumes` list was edited. The golden file was not regenerated from HEAD.

The 2.34 KB to 1.19 KB drop is recorded in `docs/BENCHMARKS.md`. `bench/run.js` did not change. The drop is `stats().memoryBytes` skipping detector states a summary feed no longer allocates. Exported state is unchanged, which is why the differential test did not flag a detector.

C10 row 0.5 Met?: x86 proxy met (6.13 µs); Raspberry Pi 4 not measured; no real-traffic evaluation.

## WP-8.3 — gate

Date: 2026-10-17.

`npm run gate` exited 0. Check 140/140. Coverage lines 97.79%, branches 86.64%. Pack-check: core 152 files, 350905 bytes unpacked. `spec-coverage`: 122 rows, 109 detector files, core 0.5.0, ok. Fuzz: feed 100,000 inputs, 33,401 rejected; baseline 100,000 rejected; checkpoint 100,000 rejected; baseline mutation 58,132 accepted, 41,868 rejected, 0 invariant failures; checkpoint mutation 57,967 accepted, 42,033 rejected, 0 invariant failures. Bench median 5.38 µs, 1.19 KB/device. The 10 µs budget is unchanged. `npm run demo` printed went-silent, new-destination, new-domain-family, wrong-time, fan-out, volume-spike, volume-spike-hourly, and incident stages c2, recon, impact.

## WP-9 — eval harness

Date: 2026-10-17.

`eval/run.mjs --dataset iot23 --zeek-logs <dir>` follows C6.2: benign learning prefix (24 h when the capture has it, otherwise the actual span), `lock()`, detection at medium or above inside the attack interval plus 5 minutes, false positives per benign device-day, 95% Wilson intervals, `n too small` under 20 instances, per-detector ablation, and a written proposal the human decides. The IoT-23 joiner reads Zeek TSV `conn.log` with `label` and `detailed-label` and parses each row with `adapter-zeek`. The engine runs at T1 only. `eval/evasion/` runs the four synthetic cases and records what fired. Thresholds were not changed. No dataset was downloaded and no detection rate was written into a README. CICIoT2023, the IEEE DataPort ARP set, and CICIoMT2024 have no joiner yet.

## WP-9.1 — harness correctness

Date: 2026-10-17.

Wilson uses z = 1.96. `0/0` prints `no rate`. The synthetic corpus is `eval/fixtures/conn.log.labeled`, written by `eval/fixtures/gen.mjs` with seed 20261017. Five devices each learn for 2 days, then lock. The post-lock benign remainder is 3 device-days. There are 25 labeled attack instances: horizontal scan, slow vertical scan, C2 beacon, and UDP flood. The committed report is `eval/fixtures/golden.md`. It prints a detection percentage with a Wilson interval, `n too small` on each attack type, false positives per device-day, time to detect, and the per-detector table. `eval/run.mjs` prints five summary lines. Ablation marks zero-unique detectors in `golden.proposals.md`. No detector default changed. `eval/results/evasion.md` records the four synthetic cases. The exfil case is a blind spot. The other three fired. Thresholds were not tuned.

The WP-9 fixture `eval/test/fixtures/conn.log.labeled` labels one `PartOfAHorizontalPortScan` and no beacon. The beacon was not labeled, so it was not scored. That is not a missed detection.

## WP-9.2 — IoT-23 parser and attack intervals

Date: 2026-10-17.

Zeek logs require `#separator`, `#fields`, and `#types`. `-` and `(empty)` are unset. Rows whose `tunnel_parents`, `label`, and `detailed-label` are space-separated are accepted. Outbound rows use `id.orig_h`. Inbound rows (`local_orig` F and `local_resp` T) use `id.resp_h`. Attack intervals merge when the gap is under 5 minutes. A 2 minute gap is one instance. A 10 minute gap is two. IoT-23 results files state: T1 only (conn.log). DNS, TLS, link-layer and app detectors not exercised. D-12 records the per-row device choice.

## WP-9.3 — CICIoT2023 joiner

Date: 2026-10-17.

`eval/ciciot2023.js` reads Zeek `conn.log`, `dns.log`, and `ssl.log` from a directory named with the source PCAP's attack category. `Benign` is benign. The joiner header and `eval/README.md` say UNVERIFIED: written from documentation, not run on real data. The README command is `zeek -C -r capture.pcap`, then `node eval/run.mjs --dataset ciciot2023 --zeek-logs <dir>`. The fixture test uses hand-written lines only. No PCAP was downloaded.

## WP-9.4 — measured heap

Date: 2026-10-17.

`bench/run.js` prints `memoryEstimate` and the heap delta per watching device. The 100 KB check uses the heap number. The autopilot-2 gate printed median 5.83 µs, estimate 1.19 KB/device, heap 12.33 KB/device, 1,000 devices. That is under 100 KB. Detectors were not tuned. `docs/BENCHMARKS.md` has the measured-heap column and a Raspberry Pi 4 row: not measured.

## WP-9.5 — docs

Date: 2026-10-17.

`README.md` and `packages/core/README.md` say: Not yet evaluated on real traffic. Harness: `eval/README.md`. No detection numbers. `docs/QUESTIONS.md` asks whether IoT-23 labels other than Benign and Malicious, such as Background, should be benign.

## WP-9.6 — harness, evasion, stream guard, memory

Date: 2026-10-17.

The five synthetic misses are `SlowVerticalScan` on `10.0.0.2`, ports 2000, 2001, 2002, 2004, and 2005, one flow each at 172800000, 173400000, 174000000, 175200000, and 175800000. The only medium-or-above anomaly on that device after lock is `beacon-change` at 174600000 (learned gap 120000 ms, later median 360000 ms). That timestamp is the port-2003 hit. It is at least 600000 ms from each miss, outside the 5-minute grace, so it does not count. `vertical-scan` needs more than `max(15, 3 × learned)` ports in one window. `new-port` already learned those ports. Thresholds were not changed.

Evasion attacks now use learned ports, learned protocols, and the learned /24 (`45.2.1.0/24`, D-13). Blind spots: slow-scan, beacon-jitter-40, exfil-0.9-limit. `flood-10-destinations` fired `egress-flood` only.

`stream-to-new-destination` does not alert when `proto` is `udp` and `bytesIn / bytesOut` is under 0.05. Recorded in SPEC "Defaults shipped in 0.5" and the 0.5.0 changelog. Learning still records the destination, so the differential golden stayed byte-identical. The one-way UDP flood is still detected by `egress-flood`.

Ablation lists a detector only when its required tiers are on and the capture has an event of a type it consumes. The other 58 are under "not exercised", not "zero unique". 51 detectors were exercised. 48 of those had zero unique detections. No default was changed.

Results headers state the learning span and the malicious-label share inside the learning prefix. The synthetic corpus is 172800000 ms and 0/55. It does not say POISONED PREFIX.

`memoryEstimate` now counts the 24 hourly rings and two empty `LruSet`s on `blockchain-c2`, `tor-or-proxy`, `cryptomining`, and `tunnel-service`. Stored state was not changed. Each bench device learned 2 summary events before the heap sample. The gate printed median 5.46 µs, estimate 5.70 KB/device, heap 12.27 KB/device. Heap / estimate is 2.15, outside 2×. Ratios are in `docs/BENCHMARKS.md`.

No IoT-23 capture was on disk. None was downloaded.

## WP-9.6 gate

Date: 2026-10-17.

`npm run gate` exited 0. Check 155/155. Coverage lines 97.86%, branches 86.25%. Pack-check: core 152 files, 351746 bytes unpacked. `spec-coverage`: 122 rows, 109 detector files, core 0.5.0, ok. Fuzz: feed 100,000 inputs, 33,401 rejected; baseline 100,000 rejected; checkpoint 100,000 rejected; baseline mutation 58,132 accepted, 41,868 rejected, 0 invariant failures; checkpoint mutation 57,967 accepted, 42,033 rejected, 0 invariant failures. Bench median 5.46 µs, estimate 5.70 KB/device, heap 12.27 KB/device. `npm run demo` printed went-silent, new-destination, new-domain-family, wrong-time, fan-out, volume-spike, volume-spike-hourly, and incident stages c2, recon, impact.

## WP-9.7 — D-13 scope

Date: 2026-10-17.

The /24 rule is the destination list in `eval/evasion/scenarios.js` only. `packages/core/src/engine/net.js` `domainFamily()` still returns null for an IP. No detector changed for it. `git diff d4a742f -- test/diff/golden.json` is empty. The same sentence is in `eval/README.md`, `docs/DECISIONS.md`, and this file.

## WP-9.7 — stream suppression

Date: 2026-10-17.

`stream-to-new-destination` no longer uses `bytesIn / bytesOut`. It stays quiet only when `egress-flood` has fired for the same device and `dstIp` in that window. A 900-packet UDP flow at 1,200 bytes per packet with 1% reverse bytes still alerts. A 60,000-packet flood alerts `egress-flood` only. SPEC Defaults shipped in 0.5 and the changelog say so.

## WP-9.7 — strict detection

Date: 2026-10-17.

`eval/label-map.json` maps scan to recon or scan, C&C and beacon to c2, DDoS to impact or volume, and FileDownload to update. Strict detection counts a hit only when the anomaly stage or category is one of those tokens. Unmapped labels print `unmapped`. The synthetic corpus C6.2 rate stays 20/25. Strict is 13/19 = 68.4% (95% Wilson 46.0%–84.6%). The slow vertical hit is `beacon-change`, category timing, so it does not count. UdpFlood is unmapped.

## WP-9.7 — 7-day bench

Date: 2026-10-17.

`bench/run.js` still checks the 1,000-device watching bench, then feeds 200 devices 7 days of rich class traffic, calls `lock()`, and prints heap per device and the watching-state median. This run: median 6.38 µs, heap 374.99 KB/device, 200 devices, 6,947,350 events. The same process printed the 1,000-device line as median 5.33 µs, estimate 5.70 KB/device, heap 12.27 KB/device. The 7-day heap is over 100 KB. Detectors were not tuned. HARD STOP. Item 5 was not started. The full gate and the demo were not run.

## WP-9.8 — gate on main

Date: 2026-10-17. Commit `61e6f4d`.

`npm run gate` exited 0. Check 155/155. Coverage lines 97.90%, branches 86.22%, functions 98.13%. Pack-check: core 152 files, 352217 bytes unpacked. `spec-coverage`: 122 rows, 109 detector files, core 0.5.0, ok. Fuzz: feed 100,000 inputs, 33,401 rejected; baseline 100,000 rejected; checkpoint 100,000 rejected; baseline mutation 58,132 accepted, 41,868 rejected, 0 invariant failures; checkpoint mutation 57,967 accepted, 42,033 rejected, 0 invariant failures. Bench median 6.00 µs, estimate 5.70 KB/device, heap 12.27 KB/device, 1,000 devices. `npm run demo` printed went-silent, new-destination, new-domain-family, wrong-time, fan-out, volume-spike, volume-spike-hourly, and incident stages c2, recon, impact.

## WP-9.8 — UdpFlood label map

Date: 2026-10-17.

`eval/label-map.json` maps `UdpFlood` to impact or volume, the same tokens as DDoS. The synthetic corpus was regenerated. C6.2 stays 20/25 = 80.0% (95% Wilson 60.9%–91.1%). Strict detection is 19/25 = 76.0% (95% Wilson 56.6%–88.5%). UdpFlood strict is 6/6 = 100.0% (95% Wilson 61.0%–100.0%). SlowVerticalScan strict stays 0/6. No detector default changed.

## WP-9.8 — 7-day heap profile

Date: 2026-10-17.

`bench/heap-one.js` fed 16 devices, two of each class, 7 days of rich traffic, then `lock()`. Sequential disable-one-detector heap deltas are in `docs/BENCHMARKS.md`. The top three are `volume-spike-hourly` 107.84 KB, `volume-spike` 98.70 KB, and `fan-out` 97.86 KB. The 200-device run on this tree measured median 6.75 µs and heap 374.99 KB/device. No threshold or cap changed.

## WP-9.8 — representation

Date: 2026-10-17.

Sample rings use a `Float64Array`. Destination strings are interned up to the existing destination cap. Each device reuses its open window, one idle window, and one close summary. `exportBaseline()` and the differential golden are unchanged. Fast check 155/155. After typed arrays the 16-device retained total was 398.23 KB/device; the hourly ring fell from 107.84 KB to 86.72 KB, the byte ring from 98.70 to 80.17, and the fan-out ring from 97.86 to 80.10. String interning measured 396.83 and 397.77. Window reuse measured 398.37. The 200-device run after all three: median 8.13 µs, retained 307.64 KB/device. Still over 100 KB. The budget and the device cap were not changed. Not merged to main.

## WP-9.9 — when the three rings append

Date: 2026-10-18.

`volume-spike`, `fan-out`, and `volume-spike-hourly` append a sample only while `ctx.learning` is true. `onWindowClose` returns before any push once learning is over. `lock()` sets `frozen`, and a window is learning only when the device is not frozen and the window starts before `learnStart + learnMs`. Watching closes do not append. `relearn()` replaces the detector state with a fresh `createState()`. Default `learnMs` is 7 days and `maxWindows` is 10,080, one window per minute, so a default learning span fills each ring once and does not drop an older sample. Item 2 can proceed for all three.

## WP-9.9 — streaming stats, stopped

Date: 2026-10-18.

The three detectors now keep count, Welford mean, M2, and max. `volume-spike-hourly` keeps 24 of those. Idle learning windows still enter as zero. `relearn()` replaces the state. Export is baseline version 3. A version 2 file from `test/diff/golden.json`, which matches commit `d4a742f`, imports by folding the stored samples. Version 1 still imports. The idle-window acceptance test still asks for `state.samples` to include `0` and `1000000`. That array is gone. The same scenario stays quiet at 2,100,000 bytes and fires at 5,000,000. Editing `packages/core/test/acceptance.test.js` was not approved, so the fast check cannot go green. Items 3 through 6 were not started. Not merged.

## WP-11 — Q-8 and the 7-day budget

Date: 2026-10-18. Branch `wp-11/memory`, fast-forwarded from `main` through `wip/wp-9.7` (`c6e4a8c`). D-21. The idle-window acceptance test no longer reads `state.samples`. It asserts `volume-spike` learned `count` 2 (the 1,000,000-byte window and the idle window), stays quiet at 2,100,000 bytes, and fires at 5,000,000. Nothing else in that file changed.

`node --expose-gc bench/run.js`: 1,000-device retained 11.46 KB/device, median 6.50 µs. 200 devices × 7 days: retained 67.00 KB/device, median 9.58 µs, 6,947,350 events. Under 100 KB. The gate's bench printed 66.96 KB/device. A fan-out import whose `samples` value is not an array is rejected with `samples must be an array`. The engine-api history test now checks that `volume-spike` exports the four summary numbers and no sample array. `update-over-cleartext` state is `{ fired }`.

## WP-11 gate

Date: 2026-10-18. `npm run gate` exited 0, then `npm run demo`.

Check 158/158, duration 78969 ms. Coverage lines 98.01%, branches 86.20%, functions 98.15%. Pack-check: core 152 files, 358352 bytes unpacked. `spec-coverage`: 122 rows, 109 detector files, core 0.5.0, ok. Fuzz: feed 100,000 inputs, 33,401 rejected; baseline 100,000 rejected; checkpoint 100,000 rejected; baseline mutation 54,731 accepted, 45,269 rejected, 0 invariant failures; checkpoint mutation 54,763 accepted, 45,237 rejected, 0 invariant failures. Bench median 6.58 µs, estimate 4.29 KB/device, retained 11.64 KB/device, 1,000 devices. Rich bench median 9.38 µs, retained 66.96 KB/device, 200 devices, 6,947,350 events.

`npm run demo` printed went-silent, new-destination, new-domain-family, wrong-time, fan-out, volume-spike, volume-spike-hourly, and incident stages c2, recon, impact. `beacon-change` state is the `learned` map and the `tracks` map. `upload-ratio-shift` (cap 2,048) and `failed-connection-ratio` (cap 1,024) still use sample rings. A full 7-day learn is longer than those caps, so a Welford of every window would not match the golden samples. They were not converted. Caps and the budget were not changed.

## Autopilot-2 gate

Date: 2026-10-17.

`npm run gate` exited 0. Check 151/151. Coverage lines 97.82%, branches 86.38%. Pack-check: core 152 files, 351005 bytes unpacked. `spec-coverage`: 122 rows, 109 detector files, core 0.5.0, ok. Fuzz: feed 100,000 inputs, 33,401 rejected; baseline 100,000 rejected; checkpoint 100,000 rejected; baseline mutation 58,132 accepted, 41,868 rejected, 0 invariant failures; checkpoint mutation 57,967 accepted, 42,033 rejected, 0 invariant failures. Bench median 5.83 µs, estimate 1.19 KB/device, heap 12.33 KB/device. `npm run demo` printed went-silent, new-destination, new-domain-family, wrong-time, fan-out, volume-spike, volume-spike-hourly, and incident stages c2, recon, impact.

## WP-10.1 — before

Date: 2026-10-18. Measured on `wip/wp-9.7` before the early-shadow code, from `main`'s simulator and matrix.

```
profiles camera,thermostat,plug,tv-box,hvac-controller,hub,smart-tv,printer
rich events one day 39706
flow.ttl count 0
http with path 0
--- young-domain / enabled in benign matrix ---
--- detector commits on wip ---
```

`packages/core/test/benign-matrix-tiers.test.js` did not load `young-domain` indicators and did not enable `exploit-probe-http`, `young-domain`, or `ttl-anomaly`. `git log main..HEAD` for those three detector files was empty. Benign coverage for `exploit-probe-http` was vacuous before WP-10.1. Benign coverage for `young-domain` was vacuous before WP-10.1. Benign coverage for `ttl-anomaly` was vacuous before WP-10.1.

There were no detector commits to cherry-pick. The uncommitted live versions stayed in stash `hold wip/wp-9.7 uncommitted before wp-10.1`. `wip/wp-9.7` was not reverted. This work is on `wp-10.1/early-shadow`, cut from `main`.

There is no `nas` profile. HTTP benign traffic is on `camera`, `printer`, and `hub` only. No `nas` profile is added in this WP.

The owner kept `test/diff/golden.json` (D-22). Rich mode still sets unicast `ttl` and the HTTP paths. The two daily discovery flows emit only when `simulate({ discovery: true })`. `test/diff` leaves `discovery` false, so the golden stays the WP-11 regression oracle. The all-tier benign matrix passes `discovery: true`.

## WP-10.1 — stopped on the differential golden

Date: 2026-10-18.

`exploit-probe-http`, `young-domain`, and `ttl-anomaly` are Rel 0.8, `enabled: false`, `mode: 'shadow'`, `hardRule: false`. `threat-intel-match` shares `dedupGroup` `indicator`. Rich `simulate()` adds `ttl` on existing flows, one daily flow to `224.0.0.251:5353` with ttl 255, one daily flow to `239.255.255.250:1900` with ttl 2, and three HTTP paths a day on `camera`, `printer`, and `hub`. There is no `nas` profile, so `nas` emits no HTTP. The benign matrix enables the three detectors and loads `fresh-example-1.test` through `fresh-example-5.test` as `young-domain`. That matrix passed: no anomaly at medium or above. `class-violation` treats a multicast, broadcast, or link-local destination as discovery, not an inbound LAN session. SPEC and the changelog record that.

Default `simulate()` (no `rich`) matches `main` byte for byte: SHA-256 `981c3a2e9e19177d2b8709c67ebb85961c9b8d490ca616b1e0be6b5bb9aa5b5b` over every class, 2 days, seed 2.

`test/diff/corpus.js` snapshots `simulate({ rich: true })`. Adding only `ttl`, and adding the HTTP events, leaves `benign:camera:seed1` identical to `test/diff/golden.json` (0 anomalies, every baseline key equal). The two daily discovery flows do not. On that one profile they add one `posture-listening-risky` low anomaly (listen port 1900, direction `lan`) and change the exported state of `new-destination`, `new-port`, `fan-out`, `horizontal-scan`, `lan-lateral`, `volume-spike`, `volume-spike-hourly`, `upload-ratio-shift`, `posture-listening-risky`, `protocol-mix-shift`, `connection-churn`, `new-beacon`, `long-connection`, `beacon-change`, and `fleet-wave`. The full diff reported the same detector list on every `benign:<profile>:seedN` key. Replay keys were not in that failure list. `test/diff/golden.json` was not edited. `dispatch.test.js` was not changed.

## WP-10.2 — measurement, before the skip

Date: 2026-10-18. Every rich profile, seed 1. Learn 7 days with `discovery: false`, `lock()`, then 2 days with `discovery: true` plus one flow to `ff02::fb:5353` inside that profile's first active hour, source `192.0.2.10`. Tiers T0–T5. The three early-shadow detectors were enabled. Counts are the extra anomalies versus the same 2 days without discovery.

```
camera new-destination +3 medium, new-port +2 medium, lan-lateral +3 high, posture-listening-risky +1 low
thermostat new-destination +3 medium, new-port +2 medium, lan-lateral +3 high, posture-listening-risky +1 low
plug new-destination +3 medium, new-port +2 medium, lan-lateral +3 high, posture-listening-risky +1 low
tv-box new-destination +3 medium, new-port +2 medium, lan-lateral +3 high, posture-listening-risky +1 low
hvac-controller new-destination +3 medium, new-port +2 medium, lan-lateral +3 high, posture-listening-risky +1 low
hub new-destination +3 medium, new-port +2 medium, lan-lateral +3 high, posture-listening-risky +1 low
smart-tv new-destination +3 medium, new-port +2 medium, lan-lateral +3 high, posture-listening-risky +1 low
printer new-destination +3 medium, new-port +2 medium, lan-lateral +3 high, posture-listening-risky +1 low
--- totals ---
24	medium	new-destination
24	high	lan-lateral
16	medium	new-port
8	low	posture-listening-risky
```

`fan-out`, `horizontal-scan`, `vertical-scan`, and `lan-sweep` emitted nothing on these flows. They still skip group sends. `reflection-participation`, `coap-amplification`, and `ttl-anomaly` keep their own behavior and emitted nothing here. `ttl-anomaly` was enabled for the measurement.

After the skip, `multicast-hygiene.test.js` shows no extra anomaly on any profile. The all-tier matrix with `discovery: true` printed `low/info anomalies: none`. `test/diff/` stayed byte-identical. The eval harness omits a detector whose `defaults.enabled` is false, so `eval/fixtures/golden.md` was not edited.

## WP-10.1 gate

Date: 2026-10-18. `npm run gate` exited 0, then `npm run demo`.

Check 168/168, duration 72855 ms. Coverage lines 97.85%, branches 86.30%. Pack-check: core 156 files, 369593 bytes unpacked. `spec-coverage`: 137 rows, 112 detector files, core 0.5.0, ok. Fuzz: feed 100,000 inputs, 33,401 rejected; baseline 100,000 rejected; checkpoint 100,000 rejected; baseline mutation 58,132 accepted, 41,868 rejected, 0 invariant failures; checkpoint mutation 57,967 accepted, 42,033 rejected, 0 invariant failures. Bench median 6.42 µs, estimate 5.70 KB/device, heap 12.54 KB/device, 1,000 devices.

`npm run demo` printed went-silent, new-destination, new-domain-family, wrong-time, fan-out, volume-spike, volume-spike-hourly, and incident stages c2, recon, impact.

## Integration 0.7

Date: 2026-10-18. `integrate/0.7` merged `wp-11/memory` then `wp-10.1/early-shadow`, keeping both. `npm run gate` exited 0. Check 171/171. Coverage lines 97.96%, branches 86.46%, functions 97.64%. `spec-coverage`: 137 rows, 112 detector files, core 0.5.0, ok. Fuzz: feed 100,000 inputs, 33,401 rejected; baseline 100,000 rejected; checkpoint 100,000 rejected; baseline mutation 54,731 accepted, 45,269 rejected; checkpoint mutation 54,763 accepted, 45,237 rejected. Bench median 6.04 µs, estimate 4.29 KB/device, retained 11.69 KB/device, 1,000 devices. Rich bench median 5.92 µs, retained 67.19 KB/device, 200 devices, 6,948,925 events. `npm run demo` printed the same incident stages c2, recon, impact. Merged to local main. D-23.

## WP-12 gate

Date: 2026-10-18. `npm run gate` exited 0, then `npm run demo`.

Check 175/175, duration 93812 ms. Coverage lines 98.11%, branches 86.64%, functions 97.95%. Pack-check: core 156 files, 383415 bytes unpacked. `spec-coverage`: 137 rows, 112 detector files, core 0.5.0, ok. Fuzz: feed 100,000 inputs, 33,401 rejected; baseline 100,000 rejected; checkpoint 100,000 rejected; baseline mutation 54,402 accepted, 45,598 rejected; checkpoint mutation 54,848 accepted, 45,152 rejected. Bench median 6.79 µs, estimate 4.29 KB/device, retained 11.68 KB/device, 1,000 devices. Rich bench median 13.54 µs, retained 68.07 KB/device, 200 devices, 6,948,925 events.

`npm run demo` printed went-silent, new-destination, new-domain-family, wrong-time, fan-out, volume-spike, volume-spike-hourly, and incident stages c2, recon, impact. The all-tier matrix with `discovery: true` emitted no `shadow-anomaly` at medium or above. `test/diff/` passed within D-17. D-24.

## WP-13 gate

Date: 2026-10-18. `npm run gate` exited 0, then `npm run demo`.

Check 182/182, duration 91575 ms. Coverage lines 97.88%, branches 86.02%, functions 98.04%. Pack-check: core 164 files, 407759 bytes unpacked. `spec-coverage`: 137 rows, 112 detector files, core 0.5.0, ok. Fuzz: feed 100,000 inputs, 33,401 rejected; baseline 100,000 rejected; checkpoint 100,000 rejected; baseline mutation 54,402 accepted, 45,598 rejected; checkpoint mutation 54,848 accepted, 45,152 rejected; stats `fromJSON` 100,000 rejected. Bench median 6.96 µs, estimate 4.29 KB/device, retained 11.68 KB/device, 1,000 devices. Rich bench median 10.29 µs, retained 68.06 KB/device, 200 devices, 6,948,925 events.

`npm run demo` printed went-silent, new-destination, new-domain-family, wrong-time, fan-out, volume-spike, volume-spike-hourly, and incident stages c2, recon, impact. No detector migrated.

## WP-14 gate

Date: 2026-10-18. `npm run gate` exited 0, then `npm run demo`.

Check 189/189, duration 306188 ms. Coverage lines 97.88%, branches 86.34%, functions 98.05%. Pack-check: core 164 files, 412037 bytes unpacked. `spec-coverage`: 137 rows, 112 detector files, core 0.5.0, ok. Fuzz: feed 100,000 inputs, 33,401 rejected; baseline 100,000 rejected; checkpoint 100,000 rejected; baseline mutation 54,402 accepted, 45,598 rejected; checkpoint mutation 51,937 accepted, 48,063 rejected; stats `fromJSON` 100,000 rejected. Bench median 7.08 µs, estimate 4.29 KB/device, retained 11.55 KB/device, 1,000 devices. Rich bench median 8.92 µs, retained 67.99 KB/device, 200 devices, 6,948,925 events.

`npm run demo` printed went-silent, new-destination, new-domain-family, wrong-time, fan-out, volume-spike, volume-spike-hourly, and incident stages c2, recon, impact.

The metamorphic suite found two engine bugs and one test bug. A checkpoint used to save only `exportState`, so a mid-window restore dropped open counters (`packet-flood` 806 vs 812, and `horizontal-scan` missed). `restore()` now puts the live state back, including Sets, Maps, `LruSet`s, and `SampleRing`s. `exportBaseline()` is unchanged. A mutated live tag that is not a real Set, Map, ring, or the shape `createState` built is rejected, so a later `feed` does not call `.has` on a plain object. The engine does not sort events: `reorderMs` only accepts a late event. Shuffling inside 5 seconds changes `src-spoof` (a flow can arrive before the DHCP ack), `packet-flood` (the running total at the crossing), `proxy-relay` (which event completes the set, and family order), and `supply-chain-suspect` (which cause is named first). Those four are exempted by D-25. Every other anomaly still matches. Device rename failed once because the test left `lock('cam')` on the old id. That was the test, not the engine. Time shift, attack monotonicity, benign idempotence, and shadow non-interference passed with no code change. Threshold detectors that fired and still fired after doubling: `egress-flood`, `horizontal-scan`, `packet-flood`.

## WP-14.1 gate

Date: 2026-10-18. `npm run gate` exited 0, then `npm run demo`.

Check 193/193, duration 144968 ms. Coverage lines 97.84%, branches 86.30%, functions 98.07%. Pack-check: core 164 files, 419365 bytes unpacked. `spec-coverage`: 137 rows, 112 detector files, core 0.5.0, ok. Fuzz: feed 100,000 inputs, 33,401 rejected; baseline 100,000 rejected; checkpoint 100,000 rejected; baseline mutation 54,402 accepted, 45,598 rejected; checkpoint mutation 51,937 accepted, 48,063 rejected; stats `fromJSON` 100,000 rejected. Bench median 6.42 µs, estimate 4.29 KB/device, retained 11.67 KB/device, 1,000 devices. Rich bench median 6.96 µs, retained 68.11 KB/device, 200 devices, 6,948,925 events. `test/diff/` passed inside that check. D-26. D-25 is superseded.

`npm run demo` printed went-silent, new-destination, new-domain-family, wrong-time, fan-out, volume-spike, volume-spike-hourly, and incident stages c2, recon, impact.

`node --expose-gc bench/reorder.js`: median `feed()` 6.08 µs with `reorderMs: 5000`, retained 8.63 KB/device after `lock()`, 11.34 KB/device while the buffer held events. A DHCP ack that arrives 3 seconds after the flow, with `reorderMs: 5000`, produces zero `src-spoof`. The same input with `reorderMs: 0` produces one. The bounded-reorder relation matches the timestamp-sorted stream, including `src-spoof`, `packet-flood`, `proxy-relay`, and `supply-chain-suspect`. Events that share a timestamp stay in their original relative order, because the buffer breaks ties by arrival.

## WP-15 gate

Date: 2026-10-18. `npm run gate` exited 0, then `npm run demo`.

Check 197/197, duration 123323 ms. Coverage lines 98.13%, branches 86.45%, functions 98.18%. Pack-check: core 164 files, 434695 bytes unpacked. `spec-coverage`: 137 rows, 112 detector files, core 0.5.0, `explains: 42 of 112 detectors`, ok. Fuzz: feed 100,000 inputs, 33,401 rejected; baseline 100,000 rejected; checkpoint 100,000 rejected; baseline mutation 54,402 accepted, 45,598 rejected; checkpoint mutation 51,937 accepted, 48,063 rejected; stats `fromJSON` 100,000 rejected. Bench median 6.92 µs, estimate 4.29 KB/device, retained 11.69 KB/device, 1,000 devices. Rich bench median 7.79 µs, retained 68.15 KB/device, 200 devices, 6,948,925 events. `test/diff/` passed inside that check. D-27.

`npm run demo` printed went-silent, new-destination, new-domain-family, wrong-time, fan-out, volume-spike, volume-spike-hourly, and incident stages c2, recon, impact, score 100.

`eval/fixtures/golden.md` fired seven detectors, not twenty. Hits: horizontal-scan 7, new-beacon 6, packet-flood 6, protocol-mix-shift 6, new-protocol 1, beacon-change 1. Evasion: egress-flood 1. Hard rules already include horizontal-scan, packet-flood, and egress-flood. The other four, every hard rule (35), and the three shadow detectors (`exploit-probe-http`, `young-domain`, `ttl-anomaly`) set `meta.explains`. That is 42 of 112. The first `suppressWith` entry on the mirai-like replay and the kimwolf-like replay removes that one anomaly. The rest of each replay is unchanged. The chosen detectors were `horizontal-scan` on both, because suppressing `proxy-relay` also moves `supply-chain-suspect` to a later cause.
