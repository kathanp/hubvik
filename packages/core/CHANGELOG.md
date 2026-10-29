# Changelog

## 2.3.0

Report readers. Thresholds, severities, and detector defaults are unchanged. A default engine still matches 1.6.0 live anomalies. Core pack budget is 940 KiB. The unpacked tree measured 955791 bytes.

`counts(sinceTs)` returns how often each detector fired in the report ring. `hints(sinceTs)` returns response-hint text already stored on those anomalies, and it is empty unless `responseHints` is on. Neither call applies a hint. `noisy()` lists detectors whose existing labels are already over the noisy bar. `quiet(now, quietMs)` lists seen devices with no event for that long. It does not emit `went-silent`.

`@hubvik/trail` 0.1.0 reads a local trail file. `@hubvik/decisions-file` 0.1.0 reads a local decisions file and does not apply a ban. `@hubvik/rules-file` 0.1.0 reads a local JSON rules file and rejects regular-expression keys. `@hubvik/cli` 0.1.2 adds sentences and hint lines to the HTML report.

The 0.6 false-positive gate, the Raspberry Pi 4 bench, the API freeze, the security review, and the 30-day pilot stay open.

## 2.2.0

Report helpers. Thresholds, severities, and detector defaults are unchanged. A default engine still matches 1.6.0 live anomalies.

`digest(sinceTs)` groups live anomalies at or after that timestamp into one sentence per device. `exportDecisions()` returns JSON of those destinations. Neither function opens a socket. The ring is capped by `explainCap` and is not stored in the baseline. `inventory()` lists devices already seen: last time, host-set class, identity addresses, learned ports and protocols, and app names already in detector state. `classSuggest` still only suggests. The engine does not assign a class.

`@hubvik/indicators-file` 0.1.0 reads a file the host downloaded. `@hubvik/mud` 0.1.0 parses a MUD file into `loadMud` allows. Neither package fetches or installs rules.

The 0.6 false-positive gate, the Raspberry Pi 4 bench, the API freeze, the security review, and the 30-day pilot stay open.

## 2.1.0

Faster `feed()` hot path. Thresholds and defaults are unchanged except `bogon-destination`, whose severity is `info`. A default engine otherwise matches 1.6.0 live anomalies. Core pack budget is 912 KiB.

`bogon-destination` stays on and still reports. The IoT-23 malware ablation recorded 307 medium false positives for it and zero unique detections (`eval/results/iot23-malware/iot23.md`). Info alerts are outside the medium false-positive count. The other 7 medium false positives on that capture are unchanged: `new-port` 5, `new-protocol` 1, `vpn-protocol` 1.

The engine reuses one feed context, skips canary work when none are configured, splits detectors into plain and `prepare` lists, and caches shed tiers. Rare-match detectors add `prepare()` so a typical flow or summary skips their state and check. Empty threat-intel and Tor indexes short-circuit. Gate bench on this host: 1,000-device watching median 3.58 µs (under the 12 µs gate).

## 2.0.4

Detector fixes. Thresholds, severities, and defaults are unchanged. A default engine still matches 1.6.0 live anomalies. Core pack budget is 905 KiB.

`arp-spoof` caps bindings at 5000. `egress-flood` rejects overlong learned strings. `dns-tunnel` scores names per parent. `horizontal-scan` caps learned ports at 512. `inbound-lateral` uses LAN unicast only. Nested imports reject forbidden keys and overlong strings.

## 2.0.3

Constant-time audit-chain hash compare. Thresholds unchanged.

## 2.0.2

IPv4-mapped unwrap, `fe80::/10` bogon, constant-time peer-summary MAC. Thresholds unchanged.

## 2.0.1

Shadow `h2-fanout`, `onion-name`, `proxy-fanin`, `scatter-udp`. Default stream matches 1.6.0.

## 1.6.0

Shadow `dispersed-flood`, `txt-channel`, `inbound-lateral`, `short-lived-cert`. `tls.cert.notBefore` kept when finite.

## 1.5.0

`@hubvik/adapter-conntrack` 0.3.0 reads the TCP state and the reply counters on a `conntrack -L` line. With no `direction` function, a private address chooses outbound, inbound, or LAN. `bytesOut` is the device's bytes. `SYN_SENT` is `no-response` and `ESTABLISHED` is `established`. A list of three silent inbound ports and one established session fires shadow `port-knock`. An explicit `direction` function is unchanged. The core anomaly stream is unchanged. No new detector row.

D-99 through D-101 stay proposed. The 0.6 false-positive gate is still open.

## 1.4.0

`correlate` defaults off. With `correlate: true`, a DNS query name or a TLS SNI is stored under the event's `uid` and copied onto a later flow that has the same `uid` and no `dstName`. The table holds 4,096 ids and drops a name after 120 seconds. A DNS name replaces an earlier TLS name. A second DNS name does not replace the first. The checkpoint stores the table. A default engine ignores it. A bad table throws `CHECKPOINT_CORRELATE_IS_INVALID`.

`@hubvik/adapter-zeek` 0.2.0 reads `conn_state`, `local_orig`, `local_resp`, and `uid`. Inbound flows count the device's bytes, not the initiator's. `@hubvik/adapter-suricata-eve` 0.2.0 does the same from `flow.state`, address locality, and `flow_id`. A Zeek conn log can now drive `port-knock`. A Zeek or Suricata DNS line plus the matching flow can drive `cloud-storage-exfil` when `correlate` is on. With `correlate` off, the anomaly stream is unchanged.

D-95 through D-98 stay proposed. The 0.6 false-positive gate is still open. Not published.

## 1.3.1

The new behavior is the alert gate and five shadow detectors. They report only.

`fdr` stays off. With `fdr: true`, a live anomaly is marked `discover`, `defer`, or `bypass`, and an alert waits until the discovered weight reaches the same bar as today. The incident score still counts every anomaly. `src/engine/stats/hawkes.js` is the bounded Hawkes intensity.

Shadow rows, on only when `shadow` selects them: `graph-contagion`, `doh-bypass`, `spectral-beacon`, `modbus-address-sweep`, and `mqtt-will-takeover`. `dictionary-dga` is in this version too. `src/data/words.json` is 2,000 words of 3–5 letters taken from the public-domain system word list.

`npm run check` is not the gate. `npm run gate` has to pass on the tree that gets pushed. Check does not compare the API snapshot, so a types change can go red on GitHub while check is green.

D-86 through D-94 stay proposed. The 0.6 false-positive gate is still open. Not published.

## 1.0.0

Package version `1.0.0`. Not published. The unpacked core cap is 900 KB. `npm run pack:check` measured 824522 bytes, which is over the old 750 KB cap. `npm run check` on branch `spec-3.3-b22` exited 0 on 2026-10-22: 492 tests, lint, and `tsc`. The same day's `npm run gate` passed coverage, spec-coverage, numbers-check, no-dynamic, knip, detector-lint, publint, fuzz, and bench. It failed on pack-check and the API snapshot; both are fixed in this version. Shadow detectors allocate state only for an event that can change that state, so ignored traffic does not keep an empty map. The CI bench gate is 12 µs and 120 KB per device, 20% above the 10 µs and 100 KB requirement. Node 26 measured 10.61 µs and, before the empty-state skip, 113.86 KB per device. Still a prototype, not validated on real traffic. Open: the 0.6 false-positive gate, the Raspberry Pi 4 bench, the API freeze, the security review, the 30-day pilot, Q-14, and Q-23.

Default-off options in 1.0.0: `scoring` (`additive` or `lr`), `alerts`, `drift`, `audit`, `peerSuggest`, `outlier`, `sequence`, and `flowShape`, plus `annotate`, `loadTemplates`, and `setDeviceCriticality`. With the new options off, the live anomaly stream is unchanged. `src/engine/stats/bloom.js` and `hstree.js` are the Bloom filter and half-space trees. Model memory from `node scripts/model-memory.js` is in `docs/BENCHMARKS.md`.

Shadow detectors, on only when `shadow` selects them: `dhcp-route-injection`, `wpad-hijack`, `ra-flood`, `karma-responder`, `cname-cloak`, `ja4-churn`, `lan-first-seen-domain`, `multivariate-outlier`, `sequence-surprise`, `flow-shape-change`, `dormant-reactivation`, `firmware-size-divergence`, `stun-turn-relay`, `port-knock`, `bacnet-bbmd-write`, `modbus-unit-sweep`, `mqtt-retained-command`, `rtsp-new-viewer`, and `suppression-abuse`. `dictionary-dga` has no file.

Malformed optional fields are dropped: `dhcp.options`, `dhcp.routes`, `dhcp.wpadUrl`, `flow.splt`, `app.flags`, `app.unitId`, and `ra.count`. Wifi op `probe-resp` requires `ssid`. Indicator type `tracker` is accepted. `hubvik doctor` sets `noSplt` when no event carries `splt`.

`eval/cli.js` writes anomaly false positives and, with `alerts: true`, alert false positives, each with a Wilson interval. `.github/workflows/release.yml` runs the gate and `npm publish --provenance` for changed public packages on a `v*` tag. No package has been published.

### Docs

- `docs/handoff/02-ENGINE.md`: baseline export is version 3, with version 2 and version 1 import. A bare `flush()` drains to the watermark. `multi-horizon-exfil` uses `p2.js` and `cusum.js`; `slow-scan` uses `hll.js` and `welford.js`.
- `docs/handoff/03-DETECTORS.md`: title is core 1.0.0. The ten former "not implemented" rows are "Shipped as Rel 0.9 shadow".
- `docs/handoff/04-HOW-TO-ADD.md`: next work points at SPEC 0.6.3.
- `docs/progress/RUN-STATUS.md` step 2b names `HubvikError`.
- `docs/progress/PHASES.md`: the 2026-10-16 name check is recorded as `iotwarden`, with a 2026-10-20 note for ADR 0001.

`HubvikError` is the error thrown from `packages/core/src`. `code` is stable. `docs/ERRORS.md` lists every code.

Inline `createShardedEngine` keeps each device's events, including link-layer events, on that device's shard. Shards share scratch and the campaign queues (D-37). `test/shard/equivalence.test.js` compares the anomaly multiset and the baseline with one engine.

`eval/run.mjs --fp-breakdown` writes `eval/results/<dataset>/fp-breakdown.json` and `.md`. Proposal lines are printed and are not written into those files.

`node scripts/numbers-check.mjs` is part of `npm run gate`.

`npm run coverage` requires 95% lines and 85% branches. The working-tree run on 2026-10-20 was 97.39% lines and 85.38% branches, 368 tests, 0 failures. No file was excluded to reach that.

`_optionsFor` keeps one options object per detector. It no longer allocates that object on every event. Anomalies are unchanged.

The npm name is `hubvik`. Scoped packages are `@hubvik/*`. The CLI binary is `hubvik`. The 2026-10-16 name `iotwarden` is retired. Those modules were not released as 0.9.0. The Raspberry Pi 4 bench and the real-traffic 0.6 gate are still open.

Default-off engine options: `budget`, `calibratedConfidence`, `classSuggest`, `responseHints`, `redact`. `setDeviceTimezone`, `loadMud`, `checkpointDelta`, `applyDelta`, `exportSummary`, `importPeerSummaries`, and inline-only `createShardedEngine`. Worker shards throw until a person measures a Raspberry Pi 4.

Shadow detectors, Rel 0.9: `day-of-week-drift`, `sni-ip-mismatch`, `mac-randomization-churn`, `discovery-spoof`, `mud-violation`, `fleet-baseline-poisoning`, `ot-schedule-drift`, `reverse-shell-shape`, `llmnr-nbns-poison`, `dns-answer-mismatch`, `peer-divergence-federated`. They do not run unless `shadow` selects them. `peer-divergence-federated` counts each imported summary as one peer and also counts local peers in the same group. `importPeerSummaries` rejects forbidden keys and a non-array `groups` field before it replaces the previous summaries. With `calibratedConfidence`, a detector that does not return `margin` keeps the constant in `src/data/confidence.json`. Class suggestion scores a smart TV only after a browser JA4 and more than 30 families in a day, and a thermostat only for MQTT publish under 50 KB in that hour.

New packages, each 0.1.0 and UNVERIFIED where the parser was written from documentation: `@hubvik/adapter-unbound`, `adapter-ipfix`, `adapter-openwrt`, `adapter-nftables`, `adapter-ssdp`, `export-prometheus`, `export-ecs`, `export-mqtt`, `respond-nftables`, and `cli`. `respond-nftables` returns rule text and does not execute it. `export-ocsf` maps a campaign like an incident update and copies `explain` into `finding_info.desc`.

### 1.0.0

Local release, not published. The 1.0.0 gate measured 67.86 KB retained per device on the 200-device 7-day bench with default options (rich median `feed()` 7.46 µs, 6,948,925 events). With `shadow: true` the same bench retained 74.39 KB per device (median 9.92 µs). The 1,000-device watching median was 6.92 µs, retained 11.99 KB per device. The alignment re-gate measured defaults at 9.33 µs and 68.13 KB, `shadow: true` at 10.38 µs and 74.52 KB, and a 1,000-device median of 7.29 µs. The shadow median is over 10 µs and is not a gate. Check 295/295. Coverage lines 97.70%, branches 86.04%, functions 97.83%. Fuzz stayed clean. `npm run demo` scored the same incident at 100. Still a prototype, not validated on real traffic.

`test/diff` ignores `baseline.engine.pkg`, so a version bump does not edit the golden file. The unpacked core cap is 900 KB. A packed file over 60 KB fails the check, including `src/engine/engine.js` (D-35). `src/data/` must total at most 200 KB.

Hourly horizon ring, and shadow detectors `slow-scan`, `jitter-beacon`, and `multi-horizon-exfil`. When the learned hourly deviation is 0, the exfil CUSUM limit is 1 byte (D-30).

LAN graph and shadow detectors `graph-new-bridge` and `graph-role-change`. `campaigns` defaults to false. `lan-via-proxy` is incident stage impact (D-31).

Shadow detectors `exploit-then-download`, `ssh-brute-then-session`, `cloud-storage-exfil` (`src/data/storage.json`), `nd-spoof`, `dhcpv6-rogue`, `wifi-deauth-flood`, `evil-twin`, `upnp-callstranger`, and `matter-new-controller`. Event type `wifi`. App protos `upnp` and `matter`. `ownBssids` lists mesh BSSIDs. A `learn()` return that carries `severity` and no `reason` is emitted, so a router Neighbor Advertisement can fire during learning while the detector stays shadow (D-32).

`peer-divergence-federated` is Rel 0.9 (D-33).

`loadRules(rules)` compiles declarative rules to shadow detectors `rule:<id>` after every rule validates. A failed load leaves the previous set in place. There is no regular expression operator. Caps are 256 rules and 10,000 groups per rule.

`shadow` defaults to false (D-34). A shadow detector does not run, create state, or appear in `exportBaseline()` unless `shadow` is true, its id is listed, or `detectors[id].enabled` is set. `detectors[id].mode: 'live'` still promotes one.

`multi-horizon-exfil` keeps its hourly summary in a `Float64Array`. The exported baseline fields are unchanged. A checkpoint stores that array as base64 so the bytes round-trip. That summary is the learned hourly mean and deviation, not a second copy of the F3 hour ring. `check()` still reads `ctx.horizon` for the last 24 hours.

A baseline exported with shadow detectors on imports into a default engine without throwing. The state is kept and not run, and the next export omits it. A pilot sets `shadow: true`, or a B21 row has no evidence and cannot be promoted (D-34).

## 0.7.0

Local release, not published. The 0.7 gate measured 68.69 KB retained per device on the 200-device 7-day bench (median `feed()` 6.71 µs, 6,948,925 events). Check 213/213. Coverage lines 97.99%, branches 86.48%, functions 97.90%. Fuzz stayed clean, including neighbor-discovery events, `feedback()`, and `restore()` of a reorder buffer. `test/diff/` matches. The golden baseline records `pkg` `hubvik@0.7.0`; no anomaly field changed. Still a prototype, not validated on real traffic.

Learning can warn `SUSPICIOUS_LEARNING` for `ramp`, `late-family-burst`, and `beacon-born-in-learning`. Each sets `learningQuality.ready` to false. They do not raise an anomaly.

`feedback(id or fingerprint, verdict)` stores the last 10,000 operator labels in `checkpoint()`. `exportLabels()` writes them as JSONL. `stats().precision` is the 7-day count with a Wilson interval, and `NOISY_DETECTOR` fires once when the false-positive rate is over 50% on at least 10 labels. `promote: { afterDays, minHits }` (default off) moves a watched destination family, port, JA4, or resolver into the baseline and warns `BASELINE_PROMOTED`. A high-or-above anomaly, a hard-rule anomaly, or a threat-intel, proxy-SDK, or Tor hit in that period blocks it. Hard rules, OT writes, and `cert-change` are never promoted. `eval/run.mjs --labels <file>` prints that precision after the C6.2 score.

`identity: 'auto'` re-keys an event whose device id is an IP to the MAC learned from DHCP, ARP, or neighbor discovery. The default is `'off'`. `resolve(ip)` returns that MAC. A neighbor-discovery event is `nd`. DHCPv6 may set `v6`, `duid`, and `iaid`. The table is scratch key `identity` in a checkpoint, at most 50,000 rows and 16 addresses per MAC. IPv6 rows expire after 24 hours of silence.

`explain(anomalyId)` returns why an anomaly fired: `test`, `observed`, and either `threshold` or `learned`, plus `suppressWith`. `explainCap` (default 1,000) is an engine-wide LRU. A hard-rule explanation never offers `allow()`, and `suppress` lasts at most 24 hours. `spec-coverage` prints `explains: X of Y detectors`.

When `reorderMs` is greater than 0, `feed()` holds events and delivers them in timestamp order. `reorderMs: 0` does not create a buffer. The hold is capped by `maxBuffered` (default 50,000) and is part of `checkpoint()`. Hosts that merge two log sources set `reorderMs: 5000`; alerts wait that long.

A checkpoint keeps each detector's live state, including open-window counters that `exportBaseline()` does not store, and `restore()` puts that state back.

`packages/core/src/engine/stats/` holds Welford, EWMA, P², HyperLogLog, Count-Min, Page CUSUM, Page–Hinkley, and a seeded FNV-1a/fmix32 hash. No detector reads them yet. Count-Min is LAN-wide scratch only.

`volume-spike`, `fan-out`, and `volume-spike-hourly` keep a Welford summary (count, mean, M2, max) instead of a sample ring. Baseline version 3. A version 2 baseline still imports by folding its samples. Idle learning windows still count as zero. The 200-device 7-day bench retained 66.96 KB/device.

`exploit-probe-http`, `young-domain`, and `ttl-anomaly` run in shadow mode and stay enabled. A shadow draft is a `shadow-anomaly`. It has no `incidentId`, does not count toward `alert-storm`, and is not passed to `post-update-drift` or `supply-chain-suspect`. `detectors[id].mode: 'live'` promotes one and warns `SHADOW_PROMOTED_BY_HOST` once. `detectors[id].canary` runs a second copy of a live detector in shadow, at most four per engine, and that copy is not written into a baseline or a checkpoint. The engine does not read `mode` as a no-op anymore. `http.direction` is `out` or `in`; any other value is dropped. Indicator type `young-domain` matches a name and its subdomains, and expired rows are ignored. `src/data/http-probes.json` is the path and marker list for `exploit-probe-http`. `threat-intel-match` joins `dedupGroup` `indicator`, so an incident scores that group once when `young-domain` fires on the same device in the same window. `flow.ttl` is read by `ttl-anomaly`. No shipped adapter fills it. `class-violation` does not treat a LAN flow to a multicast, broadcast, or link-local address as an inbound session. A destination in `224.0.0.0/4`, `255.255.255.255`, or `ff00::/8` is a group send. `new-destination`, `new-port`, `lan-lateral`, `horizontal-scan`, `vertical-scan`, and `lan-sweep` skip it, and `fan-out`'s per-window host count does too. `posture-listening-risky` counts a listen port only when the device is the responder: direction `in`, or direction `lan` with `dstIp` equal to the device id. Sending to port 1900 is not listening on 1900. `reflection-participation`, `coap-amplification`, and `ttl-anomaly` are unchanged.

## 0.5.0

Local release, not published. `flush()` with no argument drains every open window whose start is at or before the watermark, then ticks at the watermark. `flush(now)` still closes only windows whose end is at or before `now`. `reorderMs` defaults to 0. A backward step inside the open window is accepted. A backward step outside that window and larger than `reorderMs` is `CLOCK_JUMP`. An event that would reopen a closed window is `LATE_EVENT` and is dropped. `went-silent` alerts from `tick()`, once, while the tick time is inside a learned active hour. `answer-drift` keeps every answer key seen while learning, up to 8. `smart-tv` is a loadable class: 120 families, 50 MB uploaded per hour, no inbound LAN, and `allowsBrowserJa4`. Learning warnings use `SUSPICIOUS_LEARNING` with a `reason`. `stats().learningQuality` reports whether a device is ready to lock. `minLearnWindows` defaults to 0. `tier-silent` arms a tier on its first event. It reports that tier when the tier's own silence limit has passed and another armed tier has produced an event within `tierSilentMs` (default 6 h). T4's own limit defaults to 26 h. Anomalies carry `schema`, a stable `fingerprint` of the detector, device, and dedup key (not the display text), and `evidence` unless `evidence` is false. Shared dedup groups are `private-answer`, `reflection`, `proxy-relay`, and `flood`. `identity-change` keeps the first DHCP fingerprint per MAC, at most 5,000 MACs. A different fingerprint during learning emits `SUSPICIOUS_LEARNING` reason `identity-change` and does not replace the stored value. A different fingerprint while watching alerts. `egress-flood` reports a one-way public upload of at least 50,000 packets or 200 MB in one window, and while watching also a burst of at least 5,000 packets and ten times the learned per-destination maximum. `proxy-sdk-traffic` matches a host-supplied `proxy-sdk` indicator and is medium on `smart-tv` and `tv-box`, high otherwise. `checkpoint()` and `restore()` snapshot the baseline, LAN scratch tables, watermark, and learning progress. `restore()` rejects a known scratch table whose shape is wrong. A tier listed in `tiers` with no events by the end of `learnMs` emits warning `TIER_NEVER_SEEN` once and does not raise an anomaly. `allow(device, 'fingerprint', value)` records a DHCP fingerprint that `identity-change` will not alert on after lock. `feed()` dispatches an event only to detectors whose `meta.consumes` lists that event type. An empty `consumes` array still runs on window close and on engine signals. `stream-to-new-destination` no longer uses a `bytesIn / bytesOut` guard. It stays quiet only when `egress-flood` has already fired for the same device and destination address in that window. The library still only reports. Not validated on real traffic.

## 0.4.0

Network-layer detection: TLS metadata, proxy backconnect, peer-to-peer shape, DNS answer drift and fast-flux, building-protocol writes, MQTT topics, ONVIF changes, and fleet comparison. Zeek and Suricata parsers, plus OCSF, syslog, and webhook exporters. A `discovery` event is accepted; an unknown discovery proto is dropped with `FIELD_DROPPED`. The library still only reports. Not validated on real traffic.

## 0.3.0

Device-class priors, incidents, and the 0.3 detectors: proxy relay, chain lookups, direct-to-IP, ASN and country, UPnP mappings, Tor indicators, sweeps, brute force, slow exfil, beacons, DGA, DNS tunnels, ARP/DHCP/RA, zones, tunnels, firmware downloads, and OT on the WAN. The library still only reports. Not validated on real traffic.

## 0.2.0

Flow and DNS detectors, threat indicators, policy rules, and the two log parsers. The library still only reports. Defaults that were not in the 0.1 tables are written in `docs/SPEC.md` under "Defaults shipped in 0.2". Not validated on real traffic.

## 0.1.0

Plugin engine. The original four detectors are plugins. Adds typed events, baseline v2 with optional HMAC-SHA256, and the public methods from the spec (`feedBatch`, `lock`, `relearn`, `allow`, `suppress`, `ack`, `forget`, `setPeerGroup`, `use`, `stats`, `loadIndicators`). Version 1 baselines still import. Not validated on real traffic.

## 0.0.1

Prototype engine, kept as the regression baseline. Four detectors: `new-destination`, `fan-out`, `volume-spike`, `wrong-time`. Not validated on real traffic.
