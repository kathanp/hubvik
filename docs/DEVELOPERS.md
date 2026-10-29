# Building with hubvik

hubvik is a library for a gateway. You feed it observations. It emits events. Your product decides what to do with them. The library does not block, drop, or rewrite traffic.

Status of the code in this repo: package `hubvik@2.3.0`, prototype. It has not been validated on real traffic. npm `latest` is `hubvik@2.1.0` until the 2.3.0 tag is published. Do not publish detection rates that this repository did not measure.

## Install

The publishable package is `packages/core` (`hubvik`). It has no runtime dependencies and needs Node.js 22 or newer.

```js
const { createEngine, detectors, SEVERITY } = require('hubvik');

const engine = createEngine({
  learnMs: 7 * 24 * 3600e3,
  tiers: ['T0', 'T1', 'T2'],
});

engine.on('anomaly', (anomaly) => {
  // anomaly.detector, severity, actual, expected, data, attack, hardRule
});

engine.on('warning', (warning) => {
  // FIELD_DROPPED, CLOCK_JUMP, STATE_CAP, SUSPICIOUS_LEARNING, LISTENER_ERROR
});
```

`tiers` defaults to `['T0']`. A detector stays off until every tier it requires is enabled. `engine.stats().detectors` lists each one with `active` and `reason`.

## What to send

T0 is enough for the original four detectors plus domain family, hourly volume, silence, and integrity:

```js
engine.feed({
  device: 'aa:bb:cc:dd:ee:ff',
  dst: 'video.vendor.com',
  bytes: 2048,
  ts: Date.now(),
});
```

T1 is a flow. On a flow the engine copies `dstName` or `dstIp` into `dst`, and `bytesOut + bytesIn` into `bytes`, so the T0 detectors see the same device.

```js
engine.feed({
  type: 'flow',
  device: 'aa:bb:cc:dd:ee:ff',
  ts: Date.now(),
  srcIp: '192.0.2.10',
  srcPort: 51515,
  dstIp: '203.0.113.5',
  dstPort: 443,
  proto: 'tcp',
  direction: 'out', // 'in' toward the device, 'lan' between local devices
  bytesOut: 1000,
  bytesIn: 8000,
  pktsOut: 8,
  pktsIn: 10,
  durationMs: 400,
  tcpOutcome: 'established', // or rejected, no-response, reset
  dstName: 'video.vendor.com',
});
```

T3 HTTP carries who sent the request. `direction` `out` means the device sent it. `in` means the device received it. Any other value is dropped.

```js
engine.feed({
  type: 'http',
  device: 'aa:bb:cc:dd:ee:ff',
  ts: Date.now(),
  dstIp: '203.0.113.5',
  dstPort: 80,
  method: 'GET',
  host: 'video.vendor.com',
  path: '/api/v1/status',
  status: 200,
  direction: 'out',
});
```

T2 is a DNS message:

```js
engine.feed({
  type: 'dns',
  device: 'aa:bb:cc:dd:ee:ff',
  ts: Date.now(),
  qname: 'video.vendor.com',
  qtype: 'A',
  rcode: 'NOERROR',
  resolver: '192.0.2.1',
  answers: [{ type: 'A', value: '203.0.113.5', ttl: 60 }],
});
```

Names are lowercased, a trailing dot is removed, and IDN is punycoded. IPv4-mapped IPv6 (`::ffff:192.0.2.1`) becomes `192.0.2.1`. A bad optional field is dropped and counted as `warning` `FIELD_DROPPED`. An unknown `type` throws.

Call `flush(now)` or `tick(now)` from a timer. Do not call a bare `flush()` while the gateway is still receiving traffic. A bare `flush()` is an end-of-input drain: it closes every open window whose start is ≤ the watermark, including the window that contains the watermark, then calls `tick(watermark)`. `flush(now)` closes only windows whose end is ≤ `now`. `minLearnWindows` stays 0. 500 suits devices with a steady heartbeat; leave at 0 for devices that can be idle for days, such as printers.

## Learning

Learning starts at a device's first event and lasts `learnMs` (default 7 days), or until `lock(device)`. Hard-rule detectors still report during learning. Those shipped in this tree include threat-intel matches, telnet/ADB/TR-069 scans, packet floods, reflection, inbound telnet or ADB, policy violations, ADB on 5555, SMTP bursts, and TFTP to the WAN.

During learning the engine can emit `warning` `SUSPICIOUS_LEARNING` for a GRE flow, outbound telnet, TCP 5555, an NXDOMAIN burst (10 in one window), more than 20 new registrable domains in a day after day two, a proxy shape, or a DHCP fingerprint change on a MAC that already has one (`identity-change`). The first fingerprint is kept. Those warnings are not anomalies. Review them before `lock()`.

`importBaseline` marks the imported devices as already watching. They do not learn from the import itself.

## Indicators

The core ships no threat feed. You load indicators. Expired ones are ignored. A domain indicator matches that name and any name under it. CIDR matching is IPv4.

```js
engine.loadIndicators([
  { value: 'evil.example', type: 'domain', source: 'lab', confidence: 0.9 },
  { value: '203.0.113.0/24', type: 'cidr', source: 'lab' },
  { value: '198.51.100.20', type: 'ip', source: 'lab', expiresTs: Date.now() + 86400000 },
  { value: 't13d1516h2_8daaf6152771_b186095e22b6', type: 'ja4', source: 'lab' },
]);
```

`loadIndicators` replaces the whole set. If one item is invalid, the previous set stays.

`loadRules` does the same for declarative rules. Each compiled detector id is `rule:<id>`, mode defaults to shadow, and a failed document leaves the previous rule set in place. Operators are comparisons only: no regular expressions, `eval`, or `Function`. Caps are 256 rules and 10,000 groups per rule. Example rules live in `examples/rules/`.

## Policy

Policy rules are hard rules. Every field you set must match. `dst` entries are exact names, a registrable domain, or `*.example.com`.

```js
createEngine({
  tiers: ['T0', 'T1'],
  policy: [
    { id: 'no-telnet', severity: 'critical', match: { direction: 'out', proto: 'tcp', port: 23 } },
    { id: 'vendor-only', match: { direction: 'out', dst: ['*.vendor.com'] } },
  ],
});
```

An empty `policy` array disables `policy-violation`.

## Baselines

`exportBaseline()` writes version 3 JSON. Version 2 and version 1 baselines still import; a version 2 file is upgraded by computing streaming stats from its stored samples (D-16). Pass `{ sign: key }` to add an HMAC-SHA256 signature (`node:crypto`). `importBaseline(data, { verify: key, merge: true })` checks the whole document before it changes any device.

Do not treat a baseline as a secret store. Anyone who can edit it chooses what "normal" means. `baseline.engine.pkg` is the package version. The regression comparison ignores it.

## Adapters and exporters

Parsers live in their own packages so core stays dependency-free. None of them calls `feed`.

- `packages/adapter-conntrack` reads `conntrack -L` / `conntrack -E` lines into T1 flows.
- `packages/adapter-dnsmasq` reads `log-queries=extra` lines into T2 DNS events.
- `packages/adapter-zeek` reads Zeek JSON `conn`, `dns`, `ssl`, `http`, Modbus, DNP3, MQTT, and ICSNPP `bacnet` / `s7comm` / `enip` lines.
- `packages/adapter-suricata-eve` reads EVE `flow`, `dns`, `tls`, and `http`. An `alert` line is returned for the host and is not an engine event.
- `packages/export-ocsf` maps an anomaly to an OCSF Detection Finding (`class_uid` 2004).
- `packages/export-syslog` formats RFC 5424 with a CEF message.
- `packages/export-webhook` POSTs JSON. You pass `fetch`. Optional `sign` sets `x-hubvik-signature` to HMAC-SHA256 of the body. Failed attempts back off.

Added in the 0.9 work, each at 0.1.0 and **UNVERIFIED** (written from documentation, not run on real logs): `adapter-unbound`, `adapter-ipfix`, `adapter-openwrt`, `adapter-nftables`, `adapter-ssdp`, `export-prometheus`, `export-ecs`, `export-mqtt`, `respond-nftables` (renders rule text only, never executes), and `@hubvik/cli`.

```js
const { createParser } = require('@hubvik/adapter-conntrack');
const parser = createParser({ device: (ip) => ip });
for (const event of parser.write(line)) engine.feed(event);
```

## Caps

Defaults: 10 000 devices, 5 000 destinations per device, 5 000 alert keys, 10 080 windows of history, 5 000 destinations tracked inside one window. Passing a cap emits `warning` `STATE_CAP` and a `state-cap` anomaly once per device. The library keeps running with degraded memory for that device.

`alert-storm` starts at 1000 anomalies from one device in one minute. Later anomalies from that device are dropped until the next minute.

The unpacked core package must stay at or under 900 KB. No packed file may exceed 60 KB, `src/engine/engine.js` included (D-35). `src/data/` must total at most 200 KB.

## Clock

A backward step that stays inside the device's current open window is accepted, whatever `reorderMs` is. A backward step outside that window and larger than `reorderMs` is `warning` `CLOCK_JUMP` and a `clock-jump` anomaly, and the event is not applied. A forward step longer than 36 hours is also `clock-jump`. Overnight silence is not a clock jump.

Hosts that merge two or more log sources must set `reorderMs: 5000`. The engine then holds each event until event time has moved 5 seconds past it, and delivers the held events in timestamp order, so a flow that arrives before its DHCP ack is not a `src-spoof`. Alerts are delayed by that much. `reorderMs: 0` (the default) delivers immediately and does not allocate a buffer. `flush()` and `tick(now)` release held events up to their time before they close windows or run silence checks. A bare `flush()` releases every held event. `lock()` releases the buffer before it freezes learning.

`input-gap` reports when `tick(now)` sees 24 hours with no accepted event, and that gap is still inside the history window (7 days by default). A tick at the watermark, including after a restart that has not seen a new event, does not page.

## Device class

```js
engine.setDeviceClass('aa:bb:cc:dd:ee:ff', 'plug');
```

Classes shipped: `camera`, `tv-box`, `smart-tv`, `thermostat`, `hvac-controller`, `plug`, `hub`, `printer`, `nas`. A class violation can fire during learning. That is how a device that shipped already infected is still reported. No class means those checks stay quiet.

## Incidents

Anomalies on one device inside 30 minutes become one `incident`: `{ id, device, stages, score, severity, anomalyIds, firstTs, lastTs, summary }`. Stages are recon, c2, spread, and impact. Two stages, or a score of at least 70, is critical. `ack(anomalyId)` halves the remaining score. The score decays with a 6 hour half-life.

## Lookup, zones, and mappings

```js
createEngine({
  tiers: ['T0', 'T1', 'T2'],
  lookup: (ip) => ({ asn: 'AS15169', country: 'US' }),
  gatewayIp: '192.0.2.1',
  dhcpServers: ['192.0.2.1'],
  routers: ['fe80::1'],
  zones: [
    { id: 'iot', cidr: '10.1.0.0/16' },
    { id: 'lan', cidr: '10.2.0.0/16' },
  ],
});

engine.feed({
  type: 'mapping',
  device: 'aa:bb:cc:dd:ee:ff',
  ts: Date.now(),
  proto: 'upnp',
  port: 5555,
  externalPort: 5555,
});
```

The core does not ship an IP-to-ASN database or a Tor relay list. Pass Tor relays as indicators with `type: 'tor'`. Ad domains use `type: 'ad'`. A newly registered name uses `type: 'young-domain'`.

## Learning-poison warnings

During learning the engine also warns `SUSPICIOUS_LEARNING` with reason `ramp`, `late-family-burst`, or `beacon-born-in-learning`. `ramp` compares mean bytes per active window in the last third of `learnMs` with the first third, and needs 100 active windows in each. `late-family-burst` fires when more than half of the learned families were first seen in the last 10% of `learnMs`. The first-seen map stops at `maxDestinations`. `beacon-born-in-learning` applies the `new-beacon` periodicity test to a destination whose first flow is after half of `learnMs`. It keeps 16 such destinations. Any of the three leaves `learningQuality.ready` false.

## Feedback and promotion

`feedback(anomalyId or fingerprint, verdict, { operator, note })` appends one record. Verdicts are `tp`, `fp`, `benign-true`, and `unknown`. The ring holds 10,000 and is restored from `checkpoint().feedback`. `exportLabels()` is JSONL. `stats().precision[detector]` counts labels whose timestamp is inside the last 7 days of the watermark. `fpRate` is `fp / n`. `NOISY_DETECTOR` warns once when `fpRate > 0.5` and `n >= 10`.

`promote` defaults to `false`. `{ afterDays: 3, minHits: 10 }` counts destination families, ports, JA4 fingerprints, and resolvers while the device is watching. A value seen on enough distinct UTC days and enough times is passed to that detector's `allow()` and warned as `BASELINE_PROMOTED`. Candidates are 500 per device per detector. A high or critical anomaly, any hard-rule anomaly, or a `threat-intel-match`, `proxy-sdk-traffic`, or `tor-or-proxy` hit for that value in the same days drops the candidate.

## Streaming statistics

`packages/core/src/engine/stats/` is the Welford, EWMA, P², HyperLogLog, Count-Min, CUSUM, Page–Hinkley, and hash library. Count-Min is for one LAN-wide table, not one table per device. `multi-horizon-exfil` uses the P² and CUSUM primitives; other detectors keep their own state.

## Shadow detectors

A shadow detector learns and checks like a live one, but it emits `shadow-anomaly`, never `anomaly`. It never joins an incident or a campaign and never reaches an exporter unless you subscribe to `shadow-anomaly`.

They are off by default (D-34). They run only when `createEngine({ shadow: true })`, when `shadow` lists their ids, or when `detectors[id].enabled` is set.

Rel 0.8: `exploit-probe-http`, `young-domain`, `ttl-anomaly`, `slow-scan`, `jitter-beacon`, `multi-horizon-exfil`, `graph-new-bridge`, `graph-role-change`, `exploit-then-download`, `ssh-brute-then-session`, `cloud-storage-exfil`, `nd-spoof`, `dhcpv6-rogue`, `wifi-deauth-flood`, `evil-twin`, `upnp-callstranger`, `matter-new-controller`.

Rel 0.9: `day-of-week-drift`, `sni-ip-mismatch`, `mac-randomization-churn`, `discovery-spoof`, `mud-violation`, `fleet-baseline-poisoning`, `ot-schedule-drift`, `reverse-shell-shape`, `llmnr-nbns-poison`, `dns-answer-mismatch`, `peer-divergence-federated`.

Several of these stay quiet until the host supplies an input the core never derives:

| Detector                    | Needs                                    |
| --------------------------- | ---------------------------------------- |
| `ttl-anomaly`               | `flow.ttl`                               |
| `young-domain`              | indicators of type `young-domain`        |
| `mud-violation`             | a verified, parsed MUD ACL via `loadMud` |
| `llmnr-nbns-poison`         | `dns.port` of 5355 or 137                |
| `dns-answer-mismatch`       | `dns.from`                               |
| `peer-divergence-federated` | summaries via `importPeerSummaries`      |

`loadRules` compiles rules as shadow detectors, so a host that loads rules also sets `shadow: true` or lists `rule:<id>`. `createEngine({ detectors: { 'ttl-anomaly': { mode: 'live' } } })` promotes one and emits warning `SHADOW_PROMOTED_BY_HOST` once. A canary is `detectors[id].canary` with option overrides. The engine allows four. Canary state is not in `exportBaseline()` or `checkpoint()`.

`exportBaseline()` from a pilot engine includes shadow state. Importing that file into a default engine does not throw. The state stays on the device, the detectors do not run, and the next `exportBaseline()` leaves the shadow keys out.

## Running a pilot

A pilot that wants shadow evidence must opt in as above. Shadow anomalies are the only evidence the shadow rule accepts before a row can move to `live`. A site that leaves the default collects none.

With `shadow: true` the x86 bench median was 10.38 µs, over the 10 µs line. It is not gated. Shadow mode is not claimed budget-safe on x86, or on a Raspberry Pi 4 until it is measured there.

## TLS, building protocols, and fleets

```js
createEngine({
  tiers: ['T0', 'T1', 'T3', 'T5'],
  browserJa4: ['t13d1516h2_8daaf6152771_b186095e22b6'],
});

engine.feed({
  type: 'tls',
  device: 'aa:bb:cc:dd:ee:ff',
  ts: Date.now(),
  dstIp: '1.2.3.4',
  dstPort: 443,
  sni: 'video.vendor.com',
  ja4: 't13d1516h2_8daaf6152771_b186095e22b6',
  version: 'TLSv1.3',
  cert: { issuer: 'Vendor CA', selfSigned: false },
});

engine.feed({
  type: 'app',
  device: 'ahu-1',
  ts: Date.now(),
  proto: 'bacnet',
  role: 'server',
  peerIp: '10.0.0.2',
  op: 'WriteProperty',
  target: 'setpoint',
  value: 21,
  result: 'ok',
});

engine.setPeerGroup('aa:bb:cc:dd:ee:ff', 'cams');
```

JA4 is copied as a string. The library does not compute JA4 or JA4S. A peer comparison needs at least five other devices in the same group. A fleet wave needs three devices seeing one new destination inside ten minutes. `data.sameGroup` is true when those devices share one peer group.

`identity` defaults to `'off'`. `'auto'` rewrites a device id that is an IP to the MAC from DHCP, ARP, or an `nd` event, and stores the original on `data.observedAs`. `resolve(ip)` reads the same table. IPv6 rows drop after 24 hours without traffic.

`horizons` is on when T1 is on and `slow-scan` or `multi-horizon-exfil` is running. `horizons: false` turns the ring off. Each device keeps 24 hourly rows of bytes, flows, and a HyperLogLog (`p = 8`). A gap over 24 hours clears the ring. `ctx.horizon(dev).last(hours)` and `.sum(field, hours)` are read-only. The ring is in `checkpoint()`.

`explain(anomalyId)` returns the test, the observed value, and either a threshold or what was learned. Reading an id refreshes it. An id older than `explainCap` (default 1,000) returns `null`. For a hard rule, `suppressWith` is only `suppress`, and `untilTs` is at most 24 hours after the anomaly. Calling that `suppress` with the returned arguments mutes later drafts of that detector on that device when `match` equals `actual`.

`digest(sinceTs)` returns one sentence per device for live anomalies at or after `sinceTs`. `exportDecisions()` returns JSON `{ decisions }` for the same ring. The ring holds `explainCap` rows and is not in the checkpoint. Neither call opens a socket. `inventory()` lists devices that have been seen. `suggestions` is included only when `classSuggest` is true. The host still calls `setDeviceClass`.

`counts(sinceTs)` is the fire count per detector on that ring. `hints(sinceTs)` lists hint text already stored on those anomalies and does not apply it. With `responseHints` left off the list is empty. `noisy()` reads the same labels as `stats().precision` and returns detectors already over that bar. `quiet(now, quietMs)` lists seen devices whose last event is at least `quietMs` before `now`. It does not emit `went-silent`.

`@hubvik/indicators-file` reads a local indicator file. `@hubvik/mud` parses a local MUD file into the object `loadMud` accepts. `@hubvik/trail` reads a local one-host-per-line trail. `@hubvik/decisions-file` reads a local decisions file and does not apply a ban. `@hubvik/rules-file` reads a local JSON rules file and rejects regular-expression keys. None of these packages contact the network.

## Options added in the 0.9 work (all default off)

| Option / method                                               | What it does                                                                                                                                         |
| ------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| `budget: { perEventUs, sampleEvery, recoverWindows, clock? }` | Sheds non-hard detectors tier by tier (T5, T3, T2, T1, T0) when `feed()` is over budget. Hard rules are never shed. Warns `DEGRADED` and `RECOVERED` |
| `checkpointDelta(sinceSeq)` / `applyDelta(d)`                 | Incremental checkpoints with a hash chain. A delta out of order or with a wrong `prevHash` is rejected without changing state                        |
| `calibratedConfidence: true`                                  | Confidence from the margin over threshold instead of per-detector constants. Hard rules keep their constants                                         |
| `stats().classSuggestions`                                    | Suggested class per device and `CLASS_SUGGESTED`. The engine never calls `setDeviceClass` itself                                                     |
| `setDeviceTimezone(device, ianaZone)`                         | Local hour and day for that device, so `wrong-time` and hourly baselines follow daylight saving                                                      |
| `redact: { key, fields }`                                     | HMAC tokens in emitted objects only. Internal state is not redacted                                                                                  |
| `createShardedEngine({ shards, inline: true })`               | Inline sharding only. Worker threads wait for a Raspberry Pi 4 bench (Q-10)                                                                          |
| `exportSummary` / `importPeerSummaries`                       | Federation summaries for `peer-divergence-federated`. No device ids. Cap 1,000, stale after 7 days                                                   |
| `responseHints: true`                                         | Adds `anomaly.response` text hints. `ot-*` detectors only ever get `review`                                                                          |
| `scoring: 'lr'`                                               | Incident posterior from the seed likelihood-ratio table. Default `additive`                                                                          |
| `alerts: true`                                                | Also emits `alert`. The anomaly stream is unchanged                                                                                                  |
| `drift: true`                                                 | Daily drift series. Warning `BASELINE_DRIFT` or `incident.data.drift`. Never relearns                                                                |
| `audit: true`                                                 | Hash-chained operator log in the checkpoint. `restore` warns `AUDIT_BROKEN` when the chain fails                                                     |
| `peerSuggest: true`                                           | Suggests peer groups at `lock()`. Never calls `setPeerGroup`                                                                                         |
| `outlier: true`                                               | Per-class half-space-tree model. `multivariate-outlier` stays shadow                                                                                 |
| `sequence: true`                                              | Per-device transition model. `sequence-surprise` stays shadow                                                                                        |
| `flowShape: true`                                             | First-packet histograms. `flow-shape-change` stays shadow. `hubvik doctor` sets `noSplt` when no event carries `splt`                                |
| `fdr: true`                                                   | Alpha-investing on live anomalies. `alert` uses discovered weight only. Each anomaly gets `data.fdr`. Default false, so the stream is unchanged      |
| `correlate: true`                                             | Copies a DNS name, or a TLS SNI when no DNS name is stored, onto a later flow with the same `uid`. Cap 4,096 ids, 120 seconds. Default false         |
| `annotate` / `loadTemplates` / `setDeviceCriticality`         | Maintenance windows, attack templates, and per-device alert thresholds. All default off                                                              |

## What this tree does not do yet

`checkpoint()` and `restore()` snapshot the baseline, the LAN scratch tables, the watermark, learning progress, and each detector's live state, including open-window counters that `exportBaseline()` does not store. An anomaly `fingerprint` is a hash of the detector, the device, and a stable dedup key, not the display text. `packages/core/test/metamorphic/` checks time shift, device rename, checkpoint equivalence, bounded reorder, attack monotonicity, benign idempotence, and shadow non-interference.

`dictionary-dga` is a shadow detector. The B22, B23, B24, and B25 rows stay shadow. The package version is 2.1.0. Their notes are in `packages/core/CHANGELOG.md`. The former 1.x rows ship as Rel 0.9 shadow detectors and are not live. Host-declared physical limits on `ot-value-out-of-range` and payload-size tracking on `mqtt-publish-rate` are not built. B24 is `dispersed-flood`, `txt-channel`, `inbound-lateral`, and `short-lived-cert`. B25 is `h2-fanout`, `onion-name`, `proxy-fanin`, and `scatter-udp`.

With default options the bench gate on x86 is 12 µs median `feed()` at 1,000 devices and 120 KB per device on the 7-day line. That gate is 20% above the 10 µs and 100 KB requirement. A Raspberry Pi 4 has not been measured. IoT-23 result files are `eval/results/iot23-malware/` and `eval/results/iot23-honeypot/`. Copy figures from those files. Do not treat the roadmap's dataset names as results.
