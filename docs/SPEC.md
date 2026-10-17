# iotwarden — Package Specification (v3.0, honest gates + 2026 threat update)

|              |                                                                                                                                                                                                 |
| ------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Package      | `iotwarden` (chosen 2026-10-16; npm exact-name check CLEAR; trademark search still owed by the human)                                                                                           |
| Spec version | 3.0 draft, 2026-10-17. Adds Part 0 (reconciliation with the 0.4.0 tree and blocking defects), A2.3 event time, A4.1 new API, A7 evidence fields, B20 (2026 threats), a rewritten C6, and Part E |
| Supersedes   | 2.1. Everything in 2.1 that is not changed here still applies                                                                                                                                   |
| Covers       | Core engine 0.1 → 1.0, plus the full detector catalog through 1.x                                                                                                                               |
| Runtime      | Node.js ≥ 22 (18 and 20 are end-of-life), CommonJS + `.d.ts`, zero runtime dependencies in core                                                                                                 |
| License      | Apache-2.0                                                                                                                                                                                      |
| Author       | Kathan Patel                                                                                                                                                                                    |

**How to read this.** Part 0 says what is wrong with the current tree and must be fixed before anything new is built. Part A is the engine. Part B is every detector worth building, each tagged with the release it belongs in and the input it needs. Part C covers scoring, operations, evaluation and the roadmap. Part D lists what is deliberately left out. **Part E is the ordered work list for the coding agent.** Appendix B lists the sources behind every threat claim in this file.

**Rule for the coding agent.** Work only from Part E, one work package at a time, in order. A work package is done when its Definition of Done and the gate pass. Then stop and wait for the human. If this spec and the code disagree and Part 0 does not already say which one wins, write the question in `docs/QUESTIONS.md` and stop.

---

# PART 0 — RECONCILIATION WITH THE 0.4.0 TREE

## 0.1 Status, stated plainly

- 0.4.0 has 105 detectors and passes its unit gate (91 tests, 97 % lines, 85 % branches).
- **None of the release gates in C10 for 0.2, 0.3 and 0.4 were met.** No CICIoT2023 run, no IoT-23 run, no 30-day pilot. The code moved forward; the evidence did not.
- From 3.0 on, the C10 gate column is binding. A release whose gate is not met ships with the status line `prototype — not validated on real traffic` and **may not add new detector rows** beyond the ones listed in Part E. More detectors on an unmeasured engine add false positives faster than they add detection.

## 0.2 Blocking defects found in the 0.4.0 design

These are not new features. They are places where the shipped behavior cannot do what the spec claims. Each has a work package in Part E.

| #   | Defect                                                                                                                                                                                                                                                   | Why it matters                                                                                                                                                                    | Fix (WP) |
| --- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------- |
| D1  | The benign gates (`benign.test.js`, `benign-matrix.test.js`) run with the default `tiers: ['T0']`. Every T1–T5 detector (about 85 of 105) is **off** during them. Their false-positive behavior has never been tested on benign traffic, even simulated. | "Silent on benign" is claimed for detectors that were never turned on in a benign run.                                                                                            | WP-1     |
| D2  | `went-silent` is evaluated only when the device sends its next event.                                                                                                                                                                                    | A bricked, unplugged or attacker-silenced device never sends again, so it never alerts. The detector misses exactly the case in its own description.                              | WP-2     |
| D3  | Any backward timestamp is dropped and fires `clock-jump`.                                                                                                                                                                                                | A real gateway merges conntrack, dnsmasq and Zeek streams. They interleave a few milliseconds to seconds out of order. Real deployments would drop good events and page on noise. | WP-2     |
| D4  | Enabling a tier does not check that events of that tier arrive.                                                                                                                                                                                          | If `tiers` includes T2 and the dnsmasq adapter dies, 11 DNS detectors go blind with no signal. `input-gap` only catches total silence.                                            | WP-3     |
| D5  | `SUSPICIOUS_LEARNING` is specified in B10 but not emitted. Learning warnings go out under other codes.                                                                                                                                                   | Hosts cannot filter on the documented code. The "review before `lock()`" step has nothing stable to key on.                                                                       | WP-3     |
| D6  | One event can fire two detectors that describe the same fact (`dns-rebinding` + `private-answer-for-public-name` on `0.0.0.0`; `reflection-participation` + `coap-amplification` on 5683). Both add to the incident score.                               | Double counting inflates incident scores and makes `critical` cheaper to reach than C1 intends.                                                                                   | WP-4     |
| D7  | LAN tables on `ctx.scratch` (ARP bindings, DHCP leases, fleet-wave rows) are process memory, not baseline.                                                                                                                                               | After a gateway reboot the first ARP binding seen is learned as truth. If the attacker answers first, the spoofed binding becomes the baseline.                                   | WP-7     |
| D8  | `packet-flood` requires < 100 bytes/packet.                                                                                                                                                                                                              | Large-payload UDP and GRE floods, the shape used by Mirai-class "plain UDP" attacks, pass under it. Only the T0 `volume-spike` remains, which is not a hard rule.                 | WP-6     |
| D9  | C6 plans to convert N-BaIoT to T1/T2 events. N-BaIoT is published as 115 pre-computed statistical features per record, not as flows or PCAP.                                                                                                             | That conversion is impossible. The eval plan as written cannot run.                                                                                                               | WP-9     |
| D10 | `new-domain-family` is specified as a "bundled Public Suffix List snapshot". The code ships a curated subset because of the 500 KB pack cap.                                                                                                             | Spec and code disagree. The spec is corrected below (B1 note), not the code.                                                                                                      | WP-0     |
| D11 | The catalog total (118) is hand-counted and already disagrees with the table rows.                                                                                                                                                                       | Hand-maintained counts drift. Counts are now generated (see "Catalog total").                                                                                                     | WP-0     |
| D12 | `discovery` events are specified in A2.1 but `feed()` rejects `type: 'discovery'`.                                                                                                                                                                       | Spec promises an input the code throws on.                                                                                                                                        | WP-0     |

## 0.3 What wins when spec and code disagree

| Topic                                         | Winner                                   |
| --------------------------------------------- | ---------------------------------------- |
| Numeric defaults in "Defaults shipped in 0.x" | Code, until a WP changes both together   |
| Public suffix data                            | Code (curated subset), spec updated      |
| `anomaly.hardRule` meaning                    | Code: "emitted while device learning"    |
| Anything in 0.2 above                         | This spec. The code changes in that WP   |
| Anything else                                 | Neither. Write it in `docs/QUESTIONS.md` |

---

# PART A — ENGINE

## A1. Purpose

A library that runs on a network gateway, learns what each device behind it normally does on the network, and emits an event when a device's behavior changes or matches a known-bad pattern.

**It is a detector, not a firewall.** It never blocks, drops or modifies traffic. The host product decides the action.

**Target hosts:** IoT gateways, smart-home hubs, building-management servers, small network appliances, OpenWrt-class routers running Node.

**Core non-goals:** packet capture, payload/DPI signatures, blocking, cloud telemetry, deep-learning models in core. Rationale in Part D.

## A2. Input model — tiered

The 0.0.1 event `{ device, dst, bytes, ts }` can only drive 4 detectors. Most network-level detection needs more fields. Inputs are therefore defined in **tiers**. The host sends whatever it has; **each detector declares the tiers it needs and is disabled automatically if they are missing.** `engine.stats().detectors` reports which are active and why others are off.

| Tier   | Name                    | Typical source on a gateway                                                                                         | Adds                                                                                         |
| ------ | ----------------------- | ------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| **T0** | Summary                 | DNS log, simple conntrack                                                                                           | `device, dst, bytes, ts`                                                                     |
| **T1** | Flow                    | conntrack, NetFlow/IPFIX, nftables counters                                                                         | 5-tuple, direction, protocol, ports, bytes up/down, packets, duration, TCP outcome           |
| **T2** | DNS                     | dnsmasq / Unbound / CoreDNS logs                                                                                    | query name, qtype, rcode, answers, TTLs, resolver used                                       |
| **T3** | TLS/HTTP metadata       | Zeek, Suricata EVE, nDPI, eBPF                                                                                      | SNI, ALPN, JA4, cert subject/issuer/validity/fingerprint, HTTP host/UA                       |
| **T4** | Link layer              | ARP table, DHCP server log, mDNS/SSDP listener, IPv6 RA                                                             | MAC↔IP bindings, DHCP fingerprint (option 55 list, vendor class, hostname), RA sources       |
| **T5** | Application/OT protocol | Zeek built-in analyzers (Modbus, DNP3, MQTT), CISA's ICSNPP Zeek plugins (BACnet, S7comm, EtherNet/IP), broker logs | Protocol operation: BACnet service, Modbus function code, MQTT topic/QoS, RTSP/ONVIF actions |

```ts
// T5 — type: 'app'
{ type: 'app', device, ts, proto: 'bacnet'|'modbus'|'dnp3'|'knx'|'s7'|'enip'|'mqtt'|'coap'|'rtsp'|'onvif'|'stratum'|'smtp',
  role: 'client'|'server', peerIp, op: string,  // e.g. 'WriteProperty', 'fc16', 'SUBSCRIBE'
  target?: string,                              // object/register/topic/URI
  value?: string|number, result?: 'ok'|'error'|'reject' }
```

### A2.1 Event shapes

```ts
// T0 (unchanged, still valid)
{ device: string; dst?: string; bytes?: number; ts?: number }

// T1 flow — type: 'flow'
{ type: 'flow', device, ts,
  srcIp, srcPort, dstIp, dstPort,
  proto: 'tcp'|'udp'|'icmp'|'gre'|number,
  direction: 'out'|'in'|'lan',          // lan = device ↔ another local device
  bytesOut, bytesIn, pktsOut, pktsIn, durationMs,
  tcpOutcome?: 'established'|'rejected'|'no-response'|'reset',
  dstName?: string }                     // hostname if host already resolved it

// T2 DNS — type: 'dns'
{ type: 'dns', device, ts, qname, qtype, rcode,
  answers?: { type, value, ttl }[], resolver: string }

// T3 TLS — type: 'tls'
{ type: 'tls', device, ts, dstIp, dstPort, sni?, alpn?: string[], ja4?,
  cert?: { subject, issuer, notBefore, notAfter, sha256, selfSigned } }

// T3 HTTP — type: 'http'  (cleartext only)
{ type: 'http', device, ts, dstIp, dstPort, host?, method, path?, userAgent?, status? }

// T4 link layer — type: 'arp' | 'dhcp' | 'ra' | 'discovery'
{ type: 'arp',  ts, ip, mac, op: 'request'|'reply'|'gratuitous', iface? }
{ type: 'dhcp', ts, mac, msg: 'discover'|'request'|'ack'|'offer'|..., serverIp?,
  hostname?, vendorClass?, paramList?: number[], requestedIp? }
{ type: 'ra',   ts, srcMac, srcIp, prefixes: string[], routerLifetime }
{ type: 'discovery', device, ts, proto: 'mdns'|'ssdp'|'ws-discovery'|'coap', srcIp, direction }
```

- `dst`/`qname`/`sni` are lowercased, trailing dot removed, IDN converted to punycode.
- IPv4 and IPv6 are both first-class. IPv4-mapped IPv6 is normalized to IPv4.
- Validation: unknown `type` → `TypeError`. Malformed optional fields are dropped with a counted `warning`, not thrown, because gateway logs are messy.

### A2.1a Fields added since 2.1 (already in code unless marked)

| Event       | Field                                                                                          | Notes                                                                                                                                      |
| ----------- | ---------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| `flow`      | `icmpType?: number`                                                                            | Shipped. Used by `icmp-redirect` and `icmp-tunnel`                                                                                         |
| `flow`      | `ttl?: number`                                                                                 | **New in 0.5.** Optional. Needed later by `ttl-anomaly` (1.x). Validate 0–255                                                              |
| `tls`       | `version?: string` (≤ 32 chars)                                                                | Shipped                                                                                                                                    |
| `mapping`   | `{ type:'mapping', device, ts, proto:'upnp'\|'nat-pmp'\|'pcp', port, externalPort?, ttlSec? }` | Shipped (T1). Was missing from 2.1                                                                                                         |
| `dhcp`      | `fingerprint?: string` (≤ 255 chars)                                                           | **New in 0.5.** Opaque host-supplied DHCP fingerprint, e.g. the option-55 list joined with commas plus vendor class. Core never derives it |
| `discovery` | as in A2.1                                                                                     | **New in 0.5.** Accept and validate it. No detector consumes it until `discovery-spoof` (1.x). Until then it only updates `stats()`        |

### A2.3 Event time, ordering and the watermark (new in 0.5)

The engine runs on **event time** (`ev.ts`), never on wall-clock time, except where a host passes `now` explicitly.

- **Watermark.** The engine keeps `watermark = max(ev.ts)` over all accepted events from all devices. `stats().watermark` exposes it.
- **Reorder tolerance.** Option `reorderMs` (default `0` through 0.5). A backward step that stays inside the device's current open window is always accepted, whatever `reorderMs` is. `reorderMs` only extends tolerance before that window. A backward step outside the open window and larger than `reorderMs` is a `CLOCK_JUMP`. Hosts that merge two or more adapters must set `reorderMs: 5000`.
- An event older than the start of the device's oldest open window minus `reorderMs` is counted as `warning` `LATE_EVENT` and dropped. It never re-opens a closed window. After a drain, an event that falls in a closed window is also `LATE_EVENT`.
- **`flush()` with no argument** is an end-of-input drain. It closes every open window whose start is ≤ the watermark, including the window that contains the watermark, then calls `tick(watermark)`. `flush(now)` closes only windows whose end is ≤ `now`. A live host calls `flush(now)` or `tick(now)` from a timer, not a bare `flush()`.

### A2.2 Adapters (separate packages, not core)

Core stays zero-dependency. Parsers ship as optional packages that turn log lines into events:

`@iotwarden/adapter-conntrack`, `-dnsmasq`, `-unbound`, `-zeek`, `-suricata-eve`, `-ipfix`, `-openwrt`.

## A3. Concepts

| Term                    | Meaning                                                                                                           |
| ----------------------- | ----------------------------------------------------------------------------------------------------------------- |
| **Device**              | Opaque stable ID chosen by host (MAC recommended).                                                                |
| **Window**              | Fixed epoch-aligned bucket, `windowMs` (default 60 s).                                                            |
| **Baseline**            | Per-device, per-detector learned state.                                                                           |
| **Learning / Watching** | Per device. Learning starts at first event and lasts `learnMs`.                                                   |
| **Hard rules**          | Detectors that fire **even during learning** (§B10). Prevents a compromised device from teaching itself "normal". |
| **Peer group**          | Devices the host marks as the same model/role. Enables cross-device comparison (§B9).                             |
| **Incident**            | A correlated group of anomalies on one device (§C1).                                                              |

Lifecycle:

```
first event ─► LEARNING ─(learnMs | lock())─► WATCHING ─(relearn())─► LEARNING
                     importBaseline() ──────────┘
Hard-rule detectors run in both states.
```

## A4. Public API

```js
const { createEngine, Engine, detectors, SEVERITY } = require('iotwarden');
```

| Method                                                          | Behavior                                                                                                                                                                                  |
| --------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `createEngine(opts)`                                            | Factory.                                                                                                                                                                                  |
| `feed(event)`                                                   | Synchronous. Validates, routes to detectors by tier, emits synchronously.                                                                                                                 |
| `feedBatch(events)`                                             | Same, sorted by `ts` first.                                                                                                                                                               |
| `flush(now?)`                                                   | No argument drains open windows whose start ≤ the watermark, then `tick(watermark)`. `flush(now)` closes windows whose end ≤ `now` and does not close a window that still contains `now`. |
| `lock(device?)`                                                 | End learning for one or all devices.                                                                                                                                                      |
| `relearn(device, { detectors? })`                               | Reset baseline (all or listed detectors) and re-enter learning.                                                                                                                           |
| `allow(device, kind, value)`                                    | Add to frozen baseline: `kind` ∈ `dst`, `port`, `asn`, `country`, `ja4`, `certIssuer`, `resolver`, `peer`.                                                                                |
| `suppress(device, detector, { untilTs, match? })`               | Mute a detector for a device, optionally only for matching `actual`.                                                                                                                      |
| `ack(anomalyId)`                                                | Mark handled; used by incident scoring decay.                                                                                                                                             |
| `forget(device)`                                                | Delete all state.                                                                                                                                                                         |
| `setPeerGroup(device, groupId)`                                 | Assign peer group.                                                                                                                                                                        |
| `exportBaseline({ devices? })` / `importBaseline(b, { merge })` | §A6. Import validates fully before mutating.                                                                                                                                              |
| `use(detector)`                                                 | Register a custom detector (§A5).                                                                                                                                                         |
| `stats()`                                                       | Counters, active/disabled detectors with reasons, memory estimate.                                                                                                                        |

Events:

| Event        | Payload                               |
| ------------ | ------------------------------------- |
| `anomaly`    | `Anomaly` (§A7)                       |
| `incident`   | `Incident` (§C1), opened or escalated |
| `learned`    | `{ device, ts }`                      |
| `device-new` | `{ device, ts, firstEvent }`          |
| `warning`    | `{ code, message, device? }`          |

A throwing listener is caught and re-emitted as `warning` `LISTENER_ERROR`; engine state stays consistent.

### A4.1 API added in 0.5

| Method / option                   | Behavior                                                                                                                                                                                                                                                                                                                                              |
| --------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `tick(now?)`                      | Runs time-based checks (`went-silent`, `tier-silent`, `input-gap`) at `now`, defaulting to the watermark. `flush()` calls it. Hosts with no traffic for a while call it from a timer with an explicit `now`.                                                                                                                                          |
| `checkpoint()` → object           | JSON-safe runtime snapshot: everything `exportBaseline()` has **plus** the engine-wide LAN tables on `ctx.scratch` (ARP bindings, DHCP leases, learned DHCP servers and routers), the watermark, and per-device learning progress. Capped at 16 MB serialized; over cap → `warning` `CHECKPOINT_TRUNCATED` and the oldest LAN rows are dropped first. |
| `restore(cp, { verify? })`        | Validates fully, then replaces state. Same rejection rules as `importBaseline` plus HMAC verify when given. Unknown scratch table → reject.                                                                                                                                                                                                           |
| `stats().learningQuality[device]` | `{ windowsActive, families, suspicious: string[], ready: boolean }`. `ready` is false while any `SUSPICIOUS_LEARNING` reason is open or `windowsActive < minLearnWindows`.                                                                                                                                                                            |
| option `minLearnWindows`          | Default `0` (today's behavior). When > 0, a device stays learning after `learnMs` until it has this many windows with at least one event. 500 suits devices with a steady heartbeat; leave at 0 for devices that can be idle for days, such as printers. A device held in learning emits `warning` `LEARNING_EXTENDED` once.                          |
| option `reorderMs`                | See A2.3.                                                                                                                                                                                                                                                                                                                                             |
| option `promote`                  | Default `false`. See A6.1.                                                                                                                                                                                                                                                                                                                            |
| `loadIndicators` type `proxy-sdk` | New indicator type. Domain match like `domain`. Used only by `proxy-sdk-traffic` (B20).                                                                                                                                                                                                                                                               |

## A5. Detector plugin interface

Every built-in detector uses the same interface, so third parties can add their own.

```ts
interface Detector {
  id: string; // 'beaconing'
  version: number; // bump when state format changes
  requires: Tier[]; // ['T1']
  defaults: Record<string, unknown>; // tunables
  hardRule?: boolean; // runs during learning
  learn?(dev, ev, ctx): void;
  check?(dev, ev, ctx): AnomalyDraft | AnomalyDraft[] | void;
  onWindowClose?(dev, window, ctx): AnomalyDraft[] | void;
  exportState?(dev): unknown; // JSON-safe, size-bounded
  importState?(dev, state): void;
  memoryEstimate?(dev): number; // bytes
}
```

Per-detector options: `createEngine({ detectors: { beaconing: { enabled: true, severity: 'high', minConnections: 20 } } })`.

## A6. Baseline format (version 2)

```json
{
  "version": 2,
  "createdAt": 0,
  "engine": { "windowMs": 60000, "pkg": "iotwarden@0.4.0" },
  "devices": {
    "<id>": {
      "peerGroup": "cam-model-x",
      "detectors": { "<detectorId>": { "v": 1, "state": {} } }
    }
  }
}
```

- Version 1 baselines (0.1) are read and upgraded.
- Import rejects mismatched `windowMs`, unknown detector state versions (per detector, not whole file), keys `__proto__`/`constructor`/`prototype`, arrays over cap, strings over 255 chars.
- **Optional signing**: `exportBaseline({ sign: key })` adds an HMAC-SHA256 (`node:crypto`, still zero-dep). `importBaseline(b, { verify: key })` rejects tampered files. A baseline shipped to a fleet is an attack surface: whoever edits it decides what is "normal".

### A6.1 Baseline promotion (opt-in, new in 0.5)

A frozen baseline goes stale: vendors add CDN families, firmware adds ports. Without help, every change pages once and the operator clicks `allow()`. Promotion automates the safe part, and only when the host turns it on.

- `createEngine({ promote: { afterDays: 3, minHits: 10 } })`. Default `promote: false`.
- A value (destination family, port, JA4, resolver) seen while watching becomes a **candidate**. It is promoted into the baseline when it was seen on ≥ `afterDays` distinct UTC days and ≥ `minHits` times, **and** none of these happened on that device in the same period: an anomaly at `high` or above, any hard-rule anomaly, any `threat-intel-match`, `proxy-sdk-traffic` or `tor-or-proxy` hit for that value.
- Promotion emits `warning` `BASELINE_PROMOTED` with `{ device, detector, value }`. It never promotes for hard-rule detectors, OT write keys (`ot-write-new`, `ot-value-out-of-range`), `cert-change`, or anything in a device-class expectation.
- Candidates are capped at 500 per device per detector, LRU.
- Rationale: an attacker who stays quiet for 3 days and avoids every high-severity detector can get a destination promoted. That is why it is opt-in and why OT writes and certs are excluded.

## A7. Anomaly shape

```ts
{
  id: string;                  // unique, monotonic per engine
  device: string;
  detector: string;
  category: 'destination'|'scan'|'volume'|'timing'|'dns'|'tls'|'link'|'policy'|'fleet'|'integrity'
          | 'proxy'|'ot'|'app'|'abuse'|'tunnel'|'update'|'spoof'|'posture';
  severity: 'info'|'low'|'medium'|'high'|'critical';
  confidence: number;          // 0..1, how sure the detector is
  ts: number;
  actual: string;              // display only
  expected: string;            // display only
  data: object;                // machine-readable; schema per detector
  attack?: string[];           // MITRE ATT&CK technique IDs, e.g. ['T1046']
  hardRule: boolean;           // fired during learning?
  incidentId?: string;
}
```

### A7.1 Fields added in 0.5

```ts
{
  // ...all A7 fields
  schema: 1;                    // anomaly schema version; bump on breaking shape change
  fingerprint: string;          // stable hash of detector + device + dedup key; same fact → same value across restarts
  dedupGroup?: string;          // detectors that describe the same fact share a group (see C1)
  evidence?: {                  // bounded, for the operator and the eval harness
    events: number;             // how many events contributed
    sample: object[];           // ≤ 5 normalized events, each ≤ 1 KB serialized
    window?: { start: number; end: number };
    baseline?: string;          // one-line description of the learned value it was compared with
  };
}
```

- `fingerprint` uses `node:crypto` SHA-256, hex, first 16 chars. No new dependency.
- `evidence.sample` never includes fields the host did not send. It is dropped entirely when the host sets `createEngine({ evidence: false })`, for hosts that forward anomalies off-box and do not want event content leaving the gateway.
- Shared `dedupGroup` values shipped in 0.5: `private-answer` (`dns-rebinding`, `private-answer-for-public-name`), `reflection` (`reflection-participation`, `coap-amplification`), `proxy-relay` (`proxy-relay`, `credential-stuffing-out` when both fire within one window).

---

# PART B — DETECTOR CATALOG

Columns: **Needs** = input tier. **Rel** = release (0.1, 0.2, 0.3, 0.4, 1.0, 1.x). **FP risk** = false-positive risk on real IoT traffic, which decides default severity.

## B1. Destination and identity

| ID                        | Catches                                                                           | Needs   | Method                                                                                                                                         | Sev          | FP risk                                                                 | Rel |
| ------------------------- | --------------------------------------------------------------------------------- | ------- | ---------------------------------------------------------------------------------------------------------------------------------------------- | ------------ | ----------------------------------------------------------------------- | --- |
| `new-destination`         | Host never contacted during learning                                              | T0      | Set membership; capped per window                                                                                                              | medium       | Medium: CDNs rotate hostnames                                           | 0.1 |
| `new-domain-family`       | New **registered domain** (eTLD+1), not just new hostname                         | T0/T2   | Bundled curated multi-label public-suffix subset (not the full PSL, because of the 500 KB pack cap); single-label TLDs use the last two labels | medium       | Low: removes CDN-subdomain noise                                        | 0.2 |
| `new-port`                | Device uses a destination port it never used                                      | T1      | Per-device port set, direction-aware                                                                                                           | medium       | Low for IoT                                                             | 0.2 |
| `new-protocol`            | New IP protocol (GRE, raw ICMP bursts, IPv6-in-IPv4)                              | T1      | Protocol set                                                                                                                                   | high         | Very low; GRE from a camera is Mirai GREIP/GREETH territory             | 0.2 |
| `direct-ip`               | Connection to an IP the device never resolved via DNS                             | T1+T2   | Join flow dstIp with device's recent DNS answers (TTL-bounded)                                                                                 | medium       | Low on IoT; hard-coded C2 IPs are classic                               | 0.3 |
| `new-asn` / `new-country` | Traffic to a network or country never used                                        | T1      | Offline IP→ASN/country DB loaded by host (core ships none)                                                                                     | medium / low | Medium                                                                  | 0.3 |
| `inbound-from-wan`        | Unsolicited inbound connections reaching the device                               | T1      | `direction: 'in'` from public IP without prior outbound                                                                                        | high         | Low; means port forward/UPnP exposure                                   | 0.2 |
| `upnp-port-open`          | Device opens a WAN port mapping via UPnP-IGD / NAT-PMP / PCP                      | T1/host | Host reports mapping event; flag any new mapping                                                                                               | high         | Low                                                                     | 0.3 |
| `threat-intel-match`      | Destination on a known-bad list                                                   | T0+     | Host-supplied indicator sets (IP, CIDR, domain, JA4); loaded via `engine.loadIndicators()`                                                     | critical     | Depends on feed quality                                                 | 0.2 |
| `bogon-destination`       | Traffic to reserved/unallocated/martian space on WAN side                         | T1      | Static RFC table + host-provided bogon list                                                                                                    | medium       | Low                                                                     | 0.2 |
| `tor-or-proxy`            | Connections to Tor relays / known anonymizers                                     | T1      | Indicator set (Tor Project publishes relay lists)                                                                                              | high         | Very low for IoT                                                        | 0.3 |
| `p2p-pattern`             | Device acting as a P2P node (many residential peers, high ports, both directions) | T1      | Ratio of unique peers on ephemeral ports + inbound share                                                                                       | high         | Medium (some cameras use P2P relay legitimately; baseline catches that) | 0.4 |

**Note on threat intel.** The core ships **no feed**. Feed licensing changes: abuse.ch, for example, made authentication mandatory for its APIs from 30 June 2025. The host product chooses feeds, handles keys and terms, and passes indicators in. Each indicator carries `{ value, type, source, confidence, expiresTs }`. Expired indicators are ignored.

## B2. Scanning and propagation

| ID                        | Catches                                                     | Needs   | Method                                                                                                                | Sev      | FP risk                                                        | Rel |
| ------------------------- | ----------------------------------------------------------- | ------- | --------------------------------------------------------------------------------------------------------------------- | -------- | -------------------------------------------------------------- | --- |
| `fan-out`                 | Many unique hosts per window                                | T0      | Exists. Threshold `max(minFanout, k × learned max)`                                                                   | high     | Low                                                            | 0.1 |
| `horizontal-scan`         | Same port, many hosts (worm propagation)                    | T1      | Unique dstIps per (dstPort, window); extra weight for 23, 2323, 22, 5555 (ADB), 7547 (TR-069), 37215, 52869, 80, 8080 | critical | Very low                                                       | 0.2 |
| `vertical-scan`           | Many ports on one host (recon)                              | T1      | Unique dstPorts per (dstIp, window)                                                                                   | high     | Low                                                            | 0.2 |
| `failed-connection-ratio` | High share of SYNs with no answer or RST                    | T1      | `tcpOutcome` ratio vs baseline, min 20 attempts                                                                       | high     | Low; the most robust scan signal                               | 0.2 |
| `lan-lateral`             | Device starts talking to LAN peers it never contacted       | T1      | `direction: 'lan'` peer set                                                                                           | high     | Low on IoT (devices rarely talk east-west except hub ↔ device) | 0.2 |
| `lan-sweep`               | ARP or ICMP sweep of the local subnet                       | T1/T4   | Unique local targets per window in ARP requests or ICMP echo                                                          | high     | Low                                                            | 0.3 |
| `brute-force-out`         | Device hammering auth ports on other hosts                  | T1      | Many short connections to 22/23/3389/554/1883/8080 with similar small sizes                                           | critical | Very low                                                       | 0.3 |
| `brute-force-in`          | Something hammering the device                              | T1      | Same, reversed; reports source                                                                                        | high     | Low                                                            | 0.3 |
| `exploit-probe-http`      | Known IoT exploit paths in cleartext HTTP from or to device | T3 http | Small built-in path list (e.g. GPON `/GponForm/`, shell-injection patterns in query strings)                          | critical | Low                                                            | 1.x |

## B3. Volume and flooding

| ID                         | Catches                                                                                                 | Needs | Method                                                                               | Sev      | FP risk                  | Rel |
| -------------------------- | ------------------------------------------------------------------------------------------------------- | ----- | ------------------------------------------------------------------------------------ | -------- | ------------------------ | --- |
| `volume-spike`             | Far more bytes in a window                                                                              | T0    | Exists. Fix: count idle windows                                                      | high     | Medium for cameras       | 0.1 |
| `volume-spike-hourly`      | Spike vs the **same hour of day** baseline                                                              | T0    | Per-hour-of-day mean/std                                                             | high     | Lower than flat baseline | 0.2 |
| `upload-ratio-shift`       | Up/down ratio flips (thermostat suddenly uploading)                                                     | T1    | EWMA of bytesOut/(bytesIn+bytesOut) vs learned band                                  | high     | Low                      | 0.2 |
| `slow-exfil`               | Small but sustained upload increase over hours                                                          | T1    | CUSUM on hourly bytesOut vs learned mean                                             | high     | Medium                   | 0.3 |
| `packet-flood`             | High packet rate with tiny packets (SYN/UDP/ICMP flood)                                                 | T1    | pps vs baseline and avg bytes/pkt < 100                                              | critical | Very low                 | 0.2 |
| `protocol-mix-shift`       | UDP/ICMP/GRE share jumps                                                                                | T1    | Per-window proportion vs learned band (chi-square or simple band)                    | high     | Low                      | 0.3 |
| `reflection-participation` | Device answering SSDP/mDNS/CoAP/WS-Discovery/NTP to WAN addresses: it is being used as a DDoS reflector | T1/T4 | Outbound UDP from those service ports to public IPs, response/request byte ratio > 3 | critical | Very low                 | 0.2 |
| `connection-churn`         | Huge number of short connections (HTTP flood, Slowloris inverse)                                        | T1    | New connections/window vs baseline                                                   | high     | Low                      | 0.3 |

## B4. Timing and rhythm

| ID                  | Catches                                                                   | Needs | Method                                                                                                                      | Sev    | FP risk                                                                                                                | Rel |
| ------------------- | ------------------------------------------------------------------------- | ----- | --------------------------------------------------------------------------------------------------------------------------- | ------ | ---------------------------------------------------------------------------------------------------------------------- | --- |
| `wrong-time`        | Active in an hour never seen                                              | T0    | Exists. Fix day/hour clock mismatch                                                                                         | low    | Medium                                                                                                                 | 0.1 |
| `new-beacon`        | **New** periodic communication to a non-baseline destination              | T1    | Per (device, dst) inter-arrival times: low dispersion (MAD/median), low skew, ≥ 20 connections, consistent sizes. Score 0–1 | high   | **High if applied to everything**: IoT devices beacon to vendors all day. Only score destinations outside the baseline | 0.3 |
| `beacon-change`     | A known vendor beacon changes period or size sharply                      | T1    | Compare learned period/size to current                                                                                      | medium | Medium (firmware updates)                                                                                              | 0.4 |
| `long-connection`   | New long-lived session (reverse shell, tunnel)                            | T1    | durationMs above learned p99 to a non-baseline dst                                                                          | high   | Low                                                                                                                    | 0.3 |
| `went-silent`       | Device stops all traffic (bricked, unplugged, wiped, blocked by attacker) | T0    | No events for `k ×` learned max gap during its active hours                                                                 | medium | Medium                                                                                                                 | 0.2 |
| `day-of-week-drift` | Weekend/weekday pattern change                                            | T0    | Per-weekday activity profile                                                                                                | low    | Medium; needs ≥ 2 weeks learning                                                                                       | 1.x |

## B5. DNS

| ID                | Catches                                                                                                         | Needs        | Method                                                                                                                              | Sev      | FP risk                                                                       | Rel |
| ----------------- | --------------------------------------------------------------------------------------------------------------- | ------------ | ----------------------------------------------------------------------------------------------------------------------------------- | -------- | ----------------------------------------------------------------------------- | --- |
| `dga`             | Algorithmically generated domains                                                                               | T2           | Per-label entropy + bigram score against bundled English/brand n-gram table + vowel/digit ratio; fire on a burst, not a single name | high     | Medium per name, low per burst                                                | 0.3 |
| `nxdomain-burst`  | Many NXDOMAIN answers (DGA trying names, misconfig)                                                             | T2           | NXDOMAIN rate vs baseline, min count                                                                                                | high     | Low                                                                           | 0.2 |
| `dns-tunnel`      | Data hidden in DNS queries                                                                                      | T2           | Long labels (> 40 chars), high entropy, many unique subdomains under one parent, TXT/NULL/CNAME share, query volume vs baseline     | critical | Low with the combined score                                                   | 0.3 |
| `resolver-bypass` | Device stops using the gateway resolver: direct UDP/TCP 53 to outside, DoT (853), or DoH to known DoH endpoints | T1/T2        | Resolver set in baseline; DoH endpoint list as indicators                                                                           | high     | Low on IoT, though some devices hard-code 8.8.8.8, which the baseline absorbs | 0.2 |
| `answer-drift`    | A known vendor name suddenly resolves into a different ASN/country                                              | T2 (+ASN DB) | Learned answer ASNs per qname                                                                                                       | high     | Medium (CDN changes); could indicate DNS hijack or spoofing                   | 0.4 |
| `dns-rebinding`   | Public domain resolving to a private/loopback address                                                           | T2           | RFC1918/loopback/link-local in answers for a public name                                                                            | high     | Low                                                                           | 0.2 |
| `fast-flux`       | Many A records, very low TTL, many ASNs                                                                         | T2           | Answer diversity × TTL score                                                                                                        | high     | Medium                                                                        | 0.4 |
| `young-domain`    | Domain registered recently                                                                                      | T2           | Host-supplied newly-registered-domain indicator set                                                                                 | medium   | Medium                                                                        | 1.x |

## B6. Encrypted-traffic metadata (TLS/QUIC)

These read handshake metadata only. Nothing is decrypted.

| ID                       | Catches                                                                                    | Needs | Method                             | Sev    | FP risk                                                  | Rel |
| ------------------------ | ------------------------------------------------------------------------------------------ | ----- | ---------------------------------- | ------ | -------------------------------------------------------- | --- |
| `new-client-fingerprint` | Device starts using a TLS client stack it never used (new malware process, firmware swap)  | T3    | Per-device JA4 set                 | high   | Low on single-purpose IoT, medium after firmware updates | 0.4 |
| `cert-change`            | Known SNI now presents a cert from a different issuer, self-signed, or expired             | T3    | Learned issuer/fingerprint per SNI | high   | Low; strong MITM signal                                  | 0.4 |
| `sni-missing`            | TLS without SNI to a non-baseline destination                                              | T3    | Flag                               | medium | Medium                                                   | 0.4 |
| `sni-ip-mismatch`        | SNI claims a vendor name but the IP never resolved for it (domain fronting, hard-coded C2) | T2+T3 | Join                               | high   | Medium (CDNs)                                            | 1.x |
| `tls-on-odd-port`        | TLS to a port the device never used for TLS                                                | T1+T3 | Port set per protocol              | medium | Low                                                      | 0.4 |
| `cleartext-regression`   | Device that always used TLS starts sending HTTP/MQTT/Telnet in clear                       | T1/T3 | Learned per-dst TLS share          | high   | Low; downgrade attack or tampered firmware               | 0.4 |

**Fingerprint licensing.** JA4 (TLS client) is BSD-3-Clause. JA4S, JA4H, JA4X, JA4SSH, JA4T and JA4D carry the FoxIO License 1.1, which is aimed at academic, internal business and research use. Core accepts any JA4 string the host supplies and never computes the other JA4+ variants itself. **Before shipping a commercial product that computes JA4+ beyond JA4, get legal review.**

**ECH caveat.** Encrypted Client Hello hides SNI. As ECH spreads, `sni-*` detectors lose coverage; `cert-change` and `new-client-fingerprint` remain.

## Network layers

Detection is layered by what the gateway can actually see. The library does not decrypt TLS, does not inject packets, and does not block traffic. Each row stays off until the host enables that tier and sends that event type. Default tiers are still `['T0']`.

| Layer                          | Host sends                    | 0.4 reports                                                                                                                                                                                                                                                               |
| ------------------------------ | ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Link (T4)                      | `arp`, `dhcp`, `ra`           | Address claims, rogue DHCP or router advertisements, discover floods                                                                                                                                                                                                      |
| Flow (T1)                      | `flow`                        | Scans, volume, beacons, tunnels, brute force, peer-to-peer shape, a long control session followed by short bursts, LAN traffic that follows inbound bytes                                                                                                                 |
| DNS (T2)                       | `dns`                         | Name generation, tunnels, rebinding, fast-flux, an answer that moves to a new ASN, ad-network names the host listed                                                                                                                                                       |
| TLS metadata (T3)              | `tls`, `http`                 | A new JA4 string, a certificate issuer change, a handshake with no SNI, TLS on a new port, a return to cleartext, a browser JA4 on a device that is not a browser, TLS 1.0/1.1 or a self-signed or expired certificate. JA4 is an opaque string. Core does not compute it |
| Building and app (T5)          | `app`                         | A new master, a new write target, a stop or silence command, a setpoint outside the learned range, write and error bursts, Who-Is sweeps, a second owner for a BACnet instance, MQTT wildcards and new topics, ONVIF user or firmware changes                             |
| Fleet (T0, needs many devices) | summaries plus `setPeerGroup` | One device using a domain family the rest of its group does not, or three devices hitting the same new destination inside 10 minutes                                                                                                                                      |

`browserJa4` is a host-supplied list of browser JA4 strings, at most 32. Ad domains are indicators of type `ad`. Neither list ships inside the package.

## B7. Link layer and local network

Needs T4. These protect the network, not just one device's traffic, so many report the **attacker MAC**, not the victim.

| ID                        | Catches                                                                                    | Method                                                              | Sev      | FP risk                                           | Rel |
| ------------------------- | ------------------------------------------------------------------------------------------ | ------------------------------------------------------------------- | -------- | ------------------------------------------------- | --- |
| `new-device`              | Unknown MAC joins                                                                          | First event for unseen ID after engine has been running `> learnMs` | medium   | Low                                               | 0.2 |
| `arp-spoof`               | IP ↔ MAC binding changes, or one MAC claims many IPs, or gateway IP claimed by another MAC | Binding table with history                                          | critical | Low (DHCP reassignments handled via lease events) | 0.3 |
| `gratuitous-arp-flood`    | Gratuitous ARP storm                                                                       | Rate                                                                | high     | Low                                               | 0.3 |
| `rogue-dhcp`              | DHCP OFFER/ACK from a server that is not the configured one                                | Allowed server set                                                  | critical | Very low                                          | 0.3 |
| `dhcp-starvation`         | Many DISCOVERs from random MACs                                                            | Unique MAC rate                                                     | high     | Low                                               | 0.3 |
| `rogue-ra`                | IPv6 Router Advertisement from an unexpected router                                        | Allowed RA sources                                                  | critical | Very low                                          | 0.3 |
| `identity-change`         | Same MAC, different DHCP fingerprint (option 55 list, vendor class, hostname) or JA4T      | Learned host-supplied `dhcp.fingerprint` per MAC                    | high     | Low; signals MAC cloning or firmware swap         | 0.5 |
| `mac-randomization-churn` | Many short-lived MACs with the same DHCP fingerprint                                       | Fingerprint → MAC set                                               | info     | Phones do this legitimately; report, don't alarm  | 1.x |
| `discovery-spoof`         | mDNS/SSDP announcements claiming another device's name                                     | Name ↔ MAC table                                                    | high     | Low                                               | 1.x |

## B8. Policy and allowlists

| ID                 | Catches                                                                    | Needs | Method                                                                                           | Sev      | Rel |
| ------------------ | -------------------------------------------------------------------------- | ----- | ------------------------------------------------------------------------------------------------ | -------- | --- |
| `policy-violation` | Host-declared rules broken, e.g. "camera: WAN only to *.vendor.com:443"    | any   | Declarative rule set: allow/deny by dst, domain family, port, proto, direction, hours            | per rule | 0.2 |
| `mud-violation`    | Traffic outside the device's **Manufacturer Usage Description** (RFC 8520) | T1+T2 | Host fetches and verifies the MUD file and passes the parsed ACL; engine checks flows against it | high     | 1.0 |
| `zone-violation`   | Device crosses a network zone boundary (IoT VLAN → main LAN)               | T1    | Host tags IP ranges as zones                                                                     | high     | 0.3 |

**MUD reality check.** MUD is a published IETF standard, but deployments are still early: a survey of real implementations found mostly proof-of-concept systems, with gaps such as no rules for lateral movement within a network, and MUD URLs that a compromised device could forge over DHCP or LLDP. Treat MUD as an extra input when available, never as the main detection method.

## B9. Fleet and peer comparison

These need the host to aggregate events from many devices (one big gateway, or a central service fed by many gateways).

| ID                         | Catches                                                                       | Method                                                                                        | Sev                                                                                                                                                                   | Rel |
| -------------------------- | ----------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --- |
| `peer-divergence`          | One device behaves unlike others of the same model                            | Compare device's destination families, ports, volume band to peer-group consensus (≥ 5 peers) | high                                                                                                                                                                  | 0.4 |
| `fleet-wave`               | Many devices hit the same new destination within minutes                      | Count devices per new dst per 10 min                                                          | **Ambiguous by design.** Vendor update (suppress) or worm (escalate). Output `fleet-wave` with `data.peersAffected`, `data.sameGroup`; host decides. Default `medium` | 0.4 |
| `fleet-baseline-poisoning` | An imported fleet baseline contains destinations no peer ever learned locally | Compare import vs local peers                                                                 | high                                                                                                                                                                  | 1.x |

## B10. Hard rules — fire during learning too

The biggest weakness of learn-then-watch is that a device compromised before or during learning teaches the engine that the compromise is normal. These detectors ignore learning state:

`threat-intel-match`, `horizontal-scan` on telnet/ADB/TR-069 ports, `packet-flood`, `reflection-participation`, `brute-force-out`, `dns-tunnel`, `rogue-dhcp`, `rogue-ra`, `arp-spoof` on the gateway IP, `inbound-from-wan` on telnet/ADB, `policy-violation`, `adb-exposure`, `proxy-relay`, `blockchain-c2`, `supply-chain-suspect`, `ot-dangerous-op`, `ot-wan-exposure`, `onvif-config-change`, `cryptomining`, `spam-relay`, `tftp-activity`, `src-spoof`, `class-violation`.

In addition, during learning the engine emits **learning quality warnings** with the exact code `SUSPICIOUS_LEARNING` and `{ device, reason, ts }`, at most once per device per reason. Reasons and defaults (new in 0.5; the existing ad-hoc learning warnings are renamed to this code):

| `reason`         | Fires when                                                                                   |
| ---------------- | -------------------------------------------------------------------------------------------- |
| `family-churn`   | more than 20 new destination families in one UTC day, after the device's second learning day |
| `gre`            | any GRE flow                                                                                 |
| `telnet-out`     | any outbound TCP 23 or 2323                                                                  |
| `nxdomain-burst` | the `nxdomain-burst` condition is met while learning                                         |
| `adb`            | any TCP 5555 connection to or from the device                                                |
| `proxy-shape`    | `proxy-relay`, `proxy-backconnect` or `p2p-pattern` conditions met while learning            |

These do not alert. They set `stats().learningQuality[device].ready = false`. `lock()` on a device that is not `ready` still works but emits `warning` `LOCKED_UNREVIEWED`, so a host UI can ask the operator to confirm.

## B11. Engine integrity

| ID            | Catches                                                                                                                                                                                                                                  | Sev    | Rel |
| ------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ | --- |
| `input-gap`   | Whole input pipeline goes quiet (log rotation broke, adapter died). A silent detector is worse than none because everyone assumes it is watching                                                                                         | high   | 0.2 |
| `clock-jump`  | Event timestamps jump backward, or forward by more than `maxForwardMs` (default 36 h). A 1 h forward threshold would flag every device that sleeps overnight, so the shipped default is the gap that is longer than a normal off period. | medium | 0.2 |
| `state-cap`   | A device hit memory caps; detection degraded for it                                                                                                                                                                                      | medium | 0.2 |
| `alert-storm` | > N anomalies/minute per device; further anomalies from that device are not emitted until the next minute. Default N is 1000.                                                                                                            | medium | 0.2 |
| `tier-silent` | A tier listed in `tiers` has produced no events engine-wide for `tierSilentMs` (default 6 h) while other tiers still produce events. Reports which detectors are blind. New in 0.5. Evaluated in `tick()`                                | high   | 0.5 |

**`went-silent` fix (0.5).** Evaluation moves to `tick()`. At each tick, for each watching device: if the watermark is inside one of the device's learned active hours, and `watermark - lastEventTs > factor × learnedMaxGap`, alert once until the device sends again. Because the clock is the watermark, not `Date.now()`, a process restarted months later does not page every device. The old event-based path is removed. The benign matrix must still pass (WP-2).

### Defaults shipped in 0.2

These are the tunables the 0.2 detectors use when the host does not override them. Changing one is a minor version bump.

| Detector                                          | Default                                                                                           | Meaning                                                                                   |
| ------------------------------------------------- | ------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| `new-domain-family`                               | 3 new families / window                                                                           | Same cap shape as `new-destination`                                                       |
| `horizontal-scan`                                 | 20 hosts, or 10 on ports 23, 2323, 5555, 7547 during learning                                     | Unique destinations per port per window                                                   |
| `vertical-scan`                                   | 15 ports                                                                                          | Unique ports per destination per window                                                   |
| `failed-connection-ratio`                         | 20 attempts and 80% failed                                                                        | TCP outcomes `rejected`, `no-response`, `reset`                                           |
| `packet-flood`                                    | 500 packets and under 100 bytes/packet                                                            | Hard rule                                                                                 |
| `reflection-participation` / `coap-amplification` | reply/request byte ratio > 3 and at least 300 bytes out                                           | UDP source ports 123, 1900, 3702, 5353, 5683 toward a public address                      |
| `went-silent`                                     | 3 × the longest learned gap that is under 6 h and does not skip an active hour                    | `tick()`: once, when `now` is inside a learned active hour and the gap exceeds that limit |
| `nxdomain-burst`                                  | 10, or 3 × the learned maximum                                                                    | Per window                                                                                |
| `spam-relay`                                      | more than 10 outbound SMTP connections in an hour, or any SMTP from a device that never sent mail | Hard rule for the burst                                                                   |
| `input-gap`                                       | 24 h with no events, and the gap is still inside the history window                               | Evaluated in `tick()`. A tick at the watermark does not page                              |
| `clock-jump`                                      | backward by more than `reorderMs` (default 0), or forward more than 36 h                          | See the table above                                                                       |
| `alert-storm`                                     | 1000 anomalies / device / minute                                                                  |                                                                                           |

`bogon-destination` uses the IANA special-purpose ranges (private, loopback, link-local, CGNAT, documentation, multicast, reserved) and only when `direction` is `out`. `new-domain-family` uses a bundled multi-label public-suffix snapshot; single-label TLDs use the last two labels. An address, and any name that starts with four dotted decimal octets, has no family. Refresh the snapshot with `scripts/update-psl.mjs`. `went-silent` prints the limit in minutes when it is under an hour.

### Defaults shipped in 0.3

| Detector                             | Default                                                                                        | Meaning                                                                                                                                   |
| ------------------------------------ | ---------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| `class-violation`                    | class JSON in `src/data/classes/`                                                              | A plug is over 6 registrable domains or 2 MB uploaded in an hour. A thermostat is over 1 MB/hour. No class is set until `setDeviceClass`. |
| `proxy-relay`                        | 6 consumer domains and 2 categories in one hour                                                | Shopping, social, and ticketing names shipped in `consumer.json`                                                                          |
| `brute-force-out` / `brute-force-in` | 15 short connections                                                                           | Ports 22, 23, 3389, 554, 1883, 8080, under 2 s and under 2 KB                                                                             |
| `lan-sweep`                          | 20 local targets / window                                                                      | ICMP to a local address, or ARP requests                                                                                                  |
| `slow-exfil`                         | CUSUM after 6 hourly samples, limit `max(5 × mean, 1 MB)`                                      | Grows when an hour is more than twice the learned upload                                                                                  |
| `connection-churn`                   | 50 connections, or 3 × the learned max                                                         | Per window                                                                                                                                |
| `new-beacon`                         | 20 connections, MAD/median ≤ 0.25, size ratio ≤ 3                                              | Only destinations absent from the baseline                                                                                                |
| `long-connection`                    | 10 minutes, or the learned 99th percentile                                                     | To a destination that was not learned                                                                                                     |
| `dga`                                | 5 suspicious labels / window                                                                   | Entropy, English bigrams, and vowel or digit ratio. One odd name does not alert                                                           |
| `dns-tunnel`                         | combined score ≥ 3                                                                             | Long label, high entropy, many names under one parent, TXT/NULL/CNAME, or > 30 queries                                                    |
| `gratuitous-arp-flood`               | 30 / window                                                                                    |                                                                                                                                           |
| `dhcp-starvation`                    | 20 discovering MACs / window                                                                   | Counted across the LAN, not per device                                                                                                    |
| `arp-spoof`                          | gateway claim always; other binding changes after learning; 8 addresses per MAC after learning | One LAN table. A DHCP ack updates the binding                                                                                             |
| `icmp-tunnel`                        | ≥ 200 bytes/packet                                                                             | ICMP redirects are `icmp-redirect` (`icmpType` 5)                                                                                         |
| `update-from-new-source`             | inbound > max(5 MB, learned 99th percentile) from a new host                                   |                                                                                                                                           |
| `update-over-cleartext`              | inbound ≥ 1 MB on port 80, 21, or 69                                                           |                                                                                                                                           |
| incidents                            | 30 min window, 6 h half-life                                                                   | Score weights: info 5, low 10, medium 25, high 50, critical 80. Two stages, or a score ≥ 70, is critical. `ack` halves the score          |

`setDeviceClass` accepts `camera`, `tv-box`, `thermostat`, `hvac-controller`, `plug`, `hub`, `printer`, `nas`. `lookup(ip)` is a host function; the core ships no ASN or country database. Tor relays are indicators of type `tor`. A WAN mapping is a `mapping` event (`upnp`, `nat-pmp`, or `pcp`). Chain RPC names, mining pools, and tunnel services are small static lists in `src/data/`, not a threat feed.

### Defaults shipped in 0.4

| Detector                  | Default                                                                                                                                                     | Meaning                                                                                          |
| ------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| `new-client-fingerprint`  | a JA4 string absent from the learned set                                                                                                                    | High. The string is supplied by the host                                                         |
| `cert-change`             | the issuer for a known SNI changes                                                                                                                          | High                                                                                             |
| `sni-missing`             | a handshake with no SNI to an address that never presented one                                                                                              | Medium                                                                                           |
| `tls-on-odd-port`         | TLS to a destination port that was not learned                                                                                                              | Medium                                                                                           |
| `cleartext-regression`    | HTTP, FTP, Telnet, or MQTT cleartext to a destination that previously used TLS                                                                              | High. Ports 21, 23, 80, 1883 versus 443 and 8883                                                 |
| `browser-mimic`           | JA4 is in `browserJa4` and the class is set and is not `tv-box`, `nas`, or `hub`                                                                            | High. No class, or an empty browser list, stays quiet                                            |
| `posture-weak-tls`        | `TLSv1.0`, `TLSv1.1`, `SSLv3`, `SSLv2`, a self-signed certificate, or `notAfter` before the event time                                                      | Low. This is posture, not an attack                                                              |
| `proxy-backconnect`       | one flow lasting at least 60 s, then at least 8 flows of at most 2 s within 5 s                                                                             | Critical                                                                                         |
| `lan-via-proxy`           | a LAN flow within 1 s of an inbound flow that carried bytes                                                                                                 | Critical                                                                                         |
| `p2p-pattern`             | at least 30 peers on a port above 1024, and at least 30% of them inbound, in one window                                                                     | High                                                                                             |
| `credential-stuffing-out` | at least 15 short port-443 sessions to different names in one window                                                                                        | High. Duration at most 3 s                                                                       |
| `ad-fraud`                | at least 5 names in one window that match an `ad` indicator                                                                                                 | Medium. No indicator list means no alert                                                         |
| `quic-new`                | UDP port 443 to a destination that was not learned                                                                                                          | Medium                                                                                           |
| `beacon-change`           | the last 8 gaps have a median more than twice the learned median                                                                                            | Medium. Learning stores a median after 4 gaps                                                    |
| `answer-drift`            | a name's answer ASN, or the address when no lookup is set, changes. Keys seen while learning accumulate, up to 8, instead of keeping only the latest lookup | High                                                                                             |
| `fast-flux`               | at least 8 distinct A answers for one name in one window, and a TTL of at most 60 s                                                                         | High                                                                                             |
| `ot-value-out-of-range`   | a numeric write outside the learned min/max after 3 samples                                                                                                 | Critical                                                                                         |
| `ot-write-rate`           | more writes in a window than `max(10, 3 × learned max)`                                                                                                     | High                                                                                             |
| `ot-recon`                | more than 10 discovery targets in a window                                                                                                                  | High. `Who-Is`, `Who-Has`, Modbus `fc43`, or a flow to 47808, 502, 102, 44818, 20000, 1911, 4911 |
| `ot-error-burst`          | more than 10 `error` or `reject` results in a window                                                                                                        | Medium                                                                                           |
| `mqtt-publish-rate`       | more than 30 publishes in a window                                                                                                                          | Medium                                                                                           |
| `peer-divergence`         | a domain family held by fewer than half of at least 5 peers in the same group                                                                               | High. No group means no alert                                                                    |
| `fleet-wave`              | 3 devices see the same destination for the first time inside 10 minutes                                                                                     | Medium. `data.peersAffected` and `data.sameGroup`. One device never alerts                       |

`ot-new-master`, `ot-write-new`, `ot-dangerous-op`, `ot-spoof`, `mqtt-wildcard-subscribe`, `mqtt-topic-new`, and `onvif-config-change` alert on the first new master, write key, dangerous op, second owner, wildcard subscription, topic prefix, or ONVIF `SetUser` / `SetNetworkInterfaces` / `SetSystemFactoryDefault` / `UpgradeSystemFirmware`. Dangerous operations and ONVIF config changes also fire during learning.

## B12. Residential proxy and "proxyware" — the main IoT threat of 2025–26

The threat has moved past Mirai-style DDoS. Today, compromised IoT devices are mostly rented out as **residential proxies**:

- In June 2025, the FBI warned that BADBOX 2.0 had put millions of TV boxes, projectors, car infotainment units and picture frames into a botnet. Infection happened **before purchase** or during setup, and the devices are sold as proxy endpoints.
- In 2026, Kimwolf spread through proxy networks **back into the victims' own LANs**, reaching Android boxes that leave ADB open on port 5555. To get around proxy providers' private-address blocks, it pointed DNS names at private or 0.0.0.0 addresses.

| ID                               | Catches                                                                                                                                                 | Needs | Method                                                                                                                     | Sev      | Rel |
| -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- | ----- | -------------------------------------------------------------------------------------------------------------------------- | -------- | --- |
| `proxy-relay`                    | Device relays third-party traffic: destination diversity explodes into popular consumer sites (shopping, social, ticketing) unrelated to its function   | T1/T2 | Unique registered domains per hour vs baseline × category entropy; inbound control session + outbound fan-out to web ports | critical | 0.3 |
| `browser-mimic`                  | A non-browser device (camera, thermostat, TV box backend) emits browser-class TLS fingerprints                                                          | T3    | JA4 matched against a host-supplied set of browser fingerprints; flag when device class ≠ browser-capable                  | high     | 0.4 |
| `proxy-backconnect`              | Long-lived control connection to a proxy-provider endpoint, followed by many short outbound flows that track its activity                               | T1    | Correlate: 1 persistent session + bursts of new flows within seconds of control traffic                                    | critical | 0.4 |
| `lan-via-proxy`                  | Traffic **from WAN-originated sessions** reaching LAN devices (proxy tunneling into the home)                                                           | T1    | Flows to `direction: 'lan'` targets that start within ms of inbound bytes on a proxy session                               | critical | 0.4 |
| `adb-exposure`                   | Any connection to TCP 5555 on a LAN device, from LAN or WAN                                                                                             | T1    | Hard rule. Plus `posture` report if device listens on 5555                                                                 | critical | 0.2 |
| `private-answer-for-public-name` | Public domain resolves to RFC 1918 / 0.0.0.0 (Kimwolf's blocklist bypass)                                                                               | T2    | Same as `dns-rebinding`, includes 0.0.0.0 and `::`                                                                         | high     | 0.2 |
| `blockchain-c2`                  | IoT device queries Ethereum/other chain RPC endpoints or ENS resolution services (C2 address lookup that survives domain takedowns, used by Kimwolf v7) | T2/T3 | Indicator set of public RPC endpoints; any hit from a device whose class is not wallet/node                                | high     | 0.3 |
| `supply-chain-suspect`           | Device begins proxy/ad/C2 behavior **from its very first hour** (preinstalled malware)                                                                  | T1–T3 | Hard-rule evaluation of B12 detectors during learning + `device-class` priors (§B19)                                       | critical | 0.3 |

## B13. Building automation and OT protocols

Building-management servers are a stated target market, so this group is not optional. BACnet and Modbus have **no authentication** in common deployments: anyone who can send packets can write setpoints, stop equipment or reflash controllers.

| ID                      | Catches                                                                                                                                                                       | Needs | Method                                                             | Sev      | Rel |
| ----------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----- | ------------------------------------------------------------------ | -------- | --- |
| `ot-new-master`         | A host that never talked to a controller now does (new Modbus master, new BACnet client)                                                                                      | T1/T5 | Per-controller client set                                          | critical | 0.4 |
| `ot-write-new`          | Write operation from a client that only ever read, or to an object/register never written: Modbus FC 5/6/15/16, BACnet `WriteProperty` / `WritePropertyMultiple`              | T5    | Learned (client, op, target) set                                   | high     | 0.4 |
| `ot-dangerous-op`       | `ReinitializeDevice`, `DeviceCommunicationControl` (silences a controller), `AtomicWriteFile` (program/firmware write), Modbus FC 8 diagnostics, S7 STOP/PLC program download | T5    | Hard rule, always alert; host can allow during maintenance windows | critical | 0.4 |
| `ot-value-out-of-range` | Setpoint written outside learned min/max (e.g. chiller setpoint to 40 °C)                                                                                                     | T5    | Per (target) learned range + host-declared physical limits         | critical | 0.4 |
| `ot-write-rate`         | Sudden burst of writes (rapid on/off cycling can damage motors and compressors)                                                                                               | T5    | Writes/window vs baseline                                          | high     | 0.4 |
| `ot-recon`              | BACnet `Who-Is` / `Who-Has` sweeps, Modbus FC 43 (read device identification), scans of 47808/502/102/44818/20000/1911/4911                                                   | T1/T5 | Unique targets per window                                          | high     | 0.4 |
| `ot-spoof`              | BACnet `I-Am` for a device instance ID already owned by another MAC/IP                                                                                                        | T5    | Instance ID ↔ address table                                        | critical | 0.4 |
| `ot-wan-exposure`       | OT protocol traffic crossing to/from WAN, BACnet BBMD foreign-device registration from a public IP                                                                            | T1    | Direction + port                                                   | critical | 0.3 |
| `ot-error-burst`        | Spike in protocol exceptions/rejects (fuzzing, wrong-register probing)                                                                                                        | T5    | Error rate vs baseline                                             | medium   | 0.4 |
| `ot-schedule-drift`     | Writes outside the learned operating schedule                                                                                                                                 | T5    | Hour-of-week profile per (client, op)                              | medium   | 1.x |

## B14. IoT application protocols (MQTT, CoAP, RTSP/ONVIF)

| ID                          | Catches                                                                                                                               | Needs | Method                                                | Sev      | Rel |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- | ----- | ----------------------------------------------------- | -------- | --- |
| `mqtt-new-broker`           | Device connects to an MQTT broker it never used (1883/8883)                                                                           | T1    | Destination set by port                               | high     | 0.2 |
| `mqtt-wildcard-subscribe`   | `SUBSCRIBE` to `#` or broad `+/…` wildcards (harvesting every device's messages)                                                      | T5    | Topic pattern check                                   | high     | 0.4 |
| `mqtt-topic-new`            | Publish/subscribe to topics outside the learned set, especially `cmd`/`ota`/`config` paths                                            | T5    | Topic-prefix set                                      | medium   | 0.4 |
| `mqtt-publish-rate`         | Publish flood or sudden payload-size jump                                                                                             | T5    | Rate/size bands                                       | medium   | 0.4 |
| `coap-amplification`        | Device answering CoAP (5683/udp) from WAN with large responses                                                                        | T1    | Reflection logic of `reflection-participation`        | critical | 0.2 |
| `stream-to-new-destination` | Camera media stream (RTSP 554, RTP, or sustained high-rate upload) starts going to a non-baseline host — someone is watching the feed | T1/T5 | Upload rate > learned media rate threshold to new dst | critical | 0.3 |
| `onvif-config-change`       | ONVIF `SetUser`, `SetNetworkInterfaces`, `SetSystemFactoryDefault`, firmware upgrade from non-baseline client                         | T5    | Hard rule                                             | critical | 0.4 |

## B15. Device monetization abuse

| ID                        | Catches                                                                                                                  | Needs    | Method                                                                                                                                                                        | Sev    | Rel |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------ | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ | --- |
| `cryptomining`            | Device joins a mining pool                                                                                               | T1/T2/T5 | Stratum JSON-RPC (`mining.subscribe` / `mining.authorize`) when cleartext; pool-domain indicators; long-lived low-volume session with steady small periodic upstream messages | high   | 0.3 |
| `spam-relay`              | Outbound SMTP (25) from a device that never sent mail                                                                    | T1       | Port set; hard rule above 10 connections/hour                                                                                                                                 | high   | 0.2 |
| `ad-fraud`                | Hidden ad traffic: many ad-network / tracker domains from a device with no screen, or at night from a TV box that is off | T2       | Host-supplied ad-domain indicator set × activity hours                                                                                                                        | medium | 0.4 |
| `credential-stuffing-out` | Many login POSTs to many different sites (device used as a stuffing proxy)                                               | T1/T3    | Short TLS sessions with similar sizes to many unrelated domains                                                                                                               | high   | 0.4 |

## B16. Remote access, tunnels and covert channels

| ID                    | Catches                                                                                                                                                   | Needs | Method                                 | Sev    | Rel |
| --------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- | ----- | -------------------------------------- | ------ | --- |
| `tunnel-service`      | Device connects to tunnel/remote-access services (ngrok, Cloudflare Tunnel, Tailscale/ZeroTier coordinators, remote-desktop relays) never in its baseline | T2    | Indicator domain families              | high   | 0.3 |
| `vpn-protocol`        | New WireGuard (UDP, fixed 148-byte handshake initiation), OpenVPN, IPsec (500/4500, ESP), or SSH session from a device that never used one                | T1    | Port/proto + handshake-size heuristics | high   | 0.3 |
| `icmp-tunnel`         | ICMP echo with large or highly variable payloads, or ICMP volume far over ping norms                                                                      | T1    | Bytes/packet and variance on ICMP      | high   | 0.3 |
| `ipv6-tunnel`         | 6in4 (IP proto 41), Teredo (UDP 3544), 6to4 appearing on an IPv4-only device                                                                              | T1    | Protocol set                           | high   | 0.3 |
| `quic-new`            | QUIC (UDP 443) from a device that never used it, to a non-baseline host                                                                                   | T1    | Port+proto set                         | medium | 0.4 |
| `ntp-rogue`           | Device syncs time from a non-baseline NTP server (time manipulation breaks cert checks and logs)                                                          | T1    | UDP 123 destination set                | medium | 0.3 |
| `reverse-shell-shape` | Interactive-looking session: small packets both directions, human-paced timing, to a non-baseline host                                                    | T1    | Packet size / inter-arrival profile    | high   | 1.x |

## B17. Firmware updates and supply chain

| ID                       | Catches                                                                                                                                    | Needs       | Method                                                                                           | Sev    | Rel |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------ | ----------- | ------------------------------------------------------------------------------------------------ | ------ | --- |
| `update-from-new-source` | Large inbound download (> learned p99) from a host outside the baseline                                                                    | T1          | Size × destination                                                                               | high   | 0.3 |
| `update-over-cleartext`  | Large binary-sized download over plain HTTP/FTP/TFTP (tamperable in transit)                                                               | T1/T3       | Port + size                                                                                      | medium | 0.3 |
| `post-update-drift`      | Many detectors fire within 24 h after a large download: either a legitimate firmware update (offer one-click `relearn`) or a malicious one | correlation | Incident rule: `update-*` anomaly + ≥ 3 new-behavior anomalies → incident with both explanations | high   | 0.3 |
| `tftp-activity`          | Any TFTP (69/udp) to WAN — common malware download path on routers/cameras                                                                 | T1          | Hard rule                                                                                        | high   | 0.2 |

## B18. IP-layer spoofing and integrity

| ID                    | Catches                                                                                             | Needs                | Method                                 | Sev      | Rel |
| --------------------- | --------------------------------------------------------------------------------------------------- | -------------------- | -------------------------------------- | -------- | --- |
| `src-spoof`           | Packets from a device with a source IP that is not its lease (spoofed floods)                       | T1+T4                | Flow srcIp vs DHCP lease / ARP binding | critical | 0.3 |
| `ttl-anomaly`         | Device's outbound TTL/hop-limit changes (different OS stack or packets crafted by raw-socket tools) | T1 (needs TTL field) | Learned TTL set                        | medium   | 1.x |
| `llmnr-nbns-poison`   | Device answering LLMNR (5355) / NBNS (137) / mDNS queries for names it does not own                 | T4                   | Name ownership table                   | high     | 1.x |
| `icmp-redirect`       | ICMP redirects on the LAN from a non-router host                                                    | T1                   | Hard rule                              | high     | 0.3 |
| `dns-answer-mismatch` | Device receives DNS answers from an IP other than the resolver it queried (off-path spoofing)       | T2                   | Query/answer source join               | high     | 1.x |

## B19. Posture and device-class priors

Posture findings are **not attacks**. They report weaknesses that make attacks likely. Severity `info`/`low`. They are cheap and very useful to a product selling to homeowners or building managers.

| ID                        | Reports                                                                                  | Needs | Rel |
| ------------------------- | ---------------------------------------------------------------------------------------- | ----- | --- |
| `posture-listening-risky` | Device accepts connections on 23, 2323, 5555, 7547, 1900 (UPnP), 502, 47808 from the LAN | T1    | 0.2 |
| `posture-cleartext-auth`  | Logins over Telnet/FTP/HTTP Basic to or from device                                      | T1/T3 | 0.3 |
| `posture-weak-tls`        | TLS 1.0/1.1, expired or self-signed certs on the device's own services                   | T3    | 0.4 |
| `posture-wan-exposed`     | Device reachable from WAN (port forward / UPnP)                                          | T1    | 0.2 |

**Device-class priors** fix the poisoned-learning problem that BADBOX-style supply-chain malware creates. A device that ships infected has no clean baseline to learn from. The host can tag each device with a class (`camera`, `tv-box`, `thermostat`, `hvac-controller`, `plug`, `hub`, `printer`, `nas`). The engine then applies **class expectations** from day one, independent of what the device learned:

- A plug never needs more than a handful of destination families.
- A thermostat never uploads more than ~1 MB/hour.
- Nothing except `tv-box`/`nas`/`hub`/`smart-tv` has a reason to emit browser-class JA4.
- No class except `hub`/`nas` needs inbound LAN connections.

Class files are plain JSON shipped in `src/data/classes/` and editable by the host. A violation of a class expectation is reported as `class-violation` (high) even during learning.

| ID                | Catches                                                      | Needs | Sev  | FP risk                                      | Rel |
| ----------------- | ------------------------------------------------------------ | ----- | ---- | -------------------------------------------- | --- |
| `class-violation` | Traffic outside the host-assigned device class, from day one | T0    | high | Low. No class is set until `setDeviceClass`. | 0.3 |

---

## B20. 2026 threat update (new rows for 0.5)

`identity-change` (B7) moves from 0.4 to 0.5 and `tier-silent` is in B11; both are listed there, not here, so each id has exactly one row.

What changed since spec 2.1, and what the package does about it:

- **Proxyware went mainstream on consumer TVs.** A June 2026 study of 6,038 LG webOS and Samsung Tizen apps found residential proxy SDKs in 2,058 of them (42.5 % of webOS apps, 26.9 % of Tizen apps), with Bright Data the largest SDK supplier. The SDK keeps running after the app is closed. LG and Samsung both announced restrictions in July 2026, but installed apps update slowly. Consequence: on a smart TV, proxy traffic may be user-consented and still be a LAN risk, because Kimwolf showed proxy endpoints can be used to reach the rest of the home network.
- **The big IoT botnets were disrupted but the model survived.** In March 2026 US, Canadian and German authorities took down infrastructure for Aisuru, Kimwolf, JackSkid and Mossad. In July 2026 the FBI and partners seized the NetNut residential proxy platform tied to the Popa botnet of at least two million devices. Aisuru had already shifted from DDoS-for-hire toward renting infected devices as proxies, and its C2 moved quickly under takedown pressure. Consequence: indicator lists go stale in days; behavior detectors carry the load.
- **Floods got shorter and bigger.** Aisuru peaked at 31.4 Tbps in December 2025. Arelion's 2026 report puts average attack duration at 8.9 minutes. Consequence: a flood must be detected inside one 60 s window, and the flood detector cannot assume tiny packets (D8).

| ID                  | Catches                                                                                 | Needs | Method                                                                                                                                                                                                                                                                                                                                   | Sev                                           | FP risk                                             | Rel |
| ------------------- | --------------------------------------------------------------------------------------- | ----- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------- | --------------------------------------------------- | --- |
| `egress-flood`      | Device floods one external destination at any packet size (UDP plain, GRE, TCP ACK/SYN) | T1    | Hard rule. Per (device, dstIp) per window: `pktsOut ≥ minPkts` (default 50,000) **or** `bytesOut ≥ minBytesOut` (default 200 MB, about 27 Mbit/s for 60 s), **and** `dstIp` is public, **and** `bytesIn / bytesOut < 0.05` (one-way). While watching, also fires at `10 ×` the learned per-destination max with a floor of 5,000 packets | critical                                      | Low. Camera upload is ~15 MB/window and two-way TCP | 0.5 |
| `proxy-sdk-traffic` | Device contacts a known residential-proxy SDK control endpoint                          | T2    | Hard rule. `qname`, `dstName` or SNI matches an indicator of type `proxy-sdk` (host-supplied; core ships none). `data.consentPossible = true` when class is `smart-tv` or `tv-box`                                                                                                                                                       | medium on `smart-tv`/`tv-box`, high otherwise | Depends on the host's list                          | 0.5 |

**New device class `smart-tv`** in `src/data/classes/smart-tv.json`: browser-class JA4 allowed, inbound LAN connections not expected, up to 120 destination families per day, upload cap 50 MB/hour (same number as `tv-box`), proxy-relay and lan-via-proxy still alert. Kept separate from `tv-box` because webOS/Tizen sets and AOSP boxes have different supply-chain risk. `browser-mimic` reads `allowsBrowserJa4` from the class file. That flag is true for `tv-box`, `nas`, `hub`, and `smart-tv`.

**Changed: `packet-flood`.** Unchanged thresholds. Its `data` gains `bytesPerPacket` so an operator can see why `egress-flood` and not `packet-flood` fired. Both share `dedupGroup: 'flood'`.

### Catalog total

Counts are **generated**, never typed. `scripts/spec-coverage.mjs` parses every table in Part B whose first column is a backticked id and whose header has a `Rel` column, and writes the per-group and total counts into `docs/DETECTORS.md`. It fails when:

- a row with `Rel ≤` the current core minor has no `packages/core/src/detectors/<id>.js`;
- a detector file exists with no spec row;
- a detector's `meta.rel` or default severity differs from its row.

Each detector file exports `meta: { rel, fpRisk, attack?: string[], stage?: string, dedupGroup?: string }` so the script can compare without parsing code.

---

# PART C — SCORING, OPERATIONS, EVALUATION

## C1. Correlation into incidents

Single anomalies are noisy. Operators act on incidents.

- An **incident** groups anomalies on one device within `incidentWindowMs` (default 30 min, sliding).
- Each anomaly maps to a stage: **recon** (scans, sweeps) → **c2** (new-beacon, dga, direct-ip, threat-intel, tor) → **spread** (horizontal-scan, lan-lateral, brute-force-out) → **impact** (floods, reflection, slow-exfil, dns-tunnel).
- **Risk score** 0–100 = sum of `severityWeight × confidence`, ×1.5 for each additional distinct stage, with exponential decay (half-life 6 h). `ack()` halves the remaining score.
- Incident severity: ≥ 2 stages or score ≥ 70 → `critical`.
- **Dedup groups (0.5).** Anomalies with the same `dedupGroup` on the same device inside one window count once in the score: the highest `severityWeight × confidence` among them. All of their ids stay in `anomalyIds`.
- Emitted `incident` payload: `{ id, device, stages, score, severity, anomalyIds, firstTs, lastTs, summary }` where `summary` is a one-line plain-English story, e.g. _"cam-1 contacted a never-seen domain at 03:00, then scanned 400 hosts on port 23, then sent 80 MB to that domain."_

The 0.0.1 demo is exactly a 3-stage incident. Today it prints 6 separate lines.

## C2. MITRE ATT&CK mapping

Every anomaly carries `attack` IDs where a clear mapping exists. Examples: `T1046` network service discovery (scans), `T1110` brute force, `T1071.004` DNS application protocol, `T1568.002` DGA, `T1572` protocol tunneling, `T1041` exfiltration over C2, `T1498` network DoS, `T1557.002` ARP cache poisoning, `T1090.003` multi-hop proxy (Tor). Mappings live in one table so they can be corrected without touching detectors.

## C3. Output formats

Core emits native objects. Optional packages convert:

`@iotwarden/export-ocsf` (OCSF Detection Finding), `-syslog` (RFC 5424 / CEF), `-webhook`, and later `-ecs` (Elastic) and `-mqtt` (for home-automation hubs). Only the first three exist.

**OCSF version is an option, not a constant.** Consumers pin versions: Cisco XDR's findings intake accepts OCSF 1.4.0 Detection Findings, and AWS Security Hub uses OCSF 1.6. `export-ocsf` takes `{ ocsfVersion: '1.4.0' }` (default `'1.4.0'`) and writes it into `metadata.version`. Fixed mapping:

| iotwarden                | OCSF                                                                          |
| ------------------------ | ----------------------------------------------------------------------------- |
| anomaly                  | `class_uid` 2004 Detection Finding, `activity_id` 1 Create, `type_uid` 200401 |
| incident escalated       | same class, `activity_id` 2 Update, `type_uid` 200402                         |
| `severity` info…critical | `severity_id` 1…5                                                             |
| `fingerprint`            | `finding_info.uid`                                                            |
| `attack[]`               | `finding_info.attacks[]` with technique uid                                   |
| `evidence.sample`        | `evidences[]` (omitted when `evidence: false`)                                |

A test validates one anomaly and one incident against a vendored JSON copy of the 1.4.0 Detection Finding required fields, stored under `packages/export-ocsf/test/fixtures/` (test-only, not packed).

## C4. Resource limits

| Limit                          | Default                                                     |
| ------------------------------ | ----------------------------------------------------------- |
| Devices                        | 10 000                                                      |
| Destinations per device        | 5 000                                                       |
| Alert-dedup entries per device | 5 000 (LRU)                                                 |
| History windows                | 10 080                                                      |
| Indicators                     | 1 000 000, stored as sorted arrays / CIDR tree, not objects |
| Per-window dst set             | Stops growing after fan-out fires; count only               |

Budgets: **< 100 KB per watching device with all 0.x detectors on; < 30 µs median `feed()` on a Raspberry Pi 4.** Measured by `bench/` in the repo every release.

## C5. Feedback loop

- `ack` / `suppress` / `allow` calls are recorded with operator ID if supplied.
- `stats().precision` estimates per-detector false-positive rate from suppress/allow vs ack. A detector whose estimated FP rate passes 50 % over 7 days emits `warning` `NOISY_DETECTOR`.

## C6. Evaluation (binding from 0.5)

Unit tests and simulated benign runs prove the code runs. They do not prove detection works. This section says how to get numbers that can go in a README.

### C6.1 Datasets: what each one can and cannot do

| Dataset                                                    | Raw form usable by the engine                                     | Use it for                                                                               | Do not use it for                              |
| ---------------------------------------------------------- | ----------------------------------------------------------------- | ---------------------------------------------------------------------------------------- | ---------------------------------------------- |
| **CICIoT2023** (UNB CIC; 33 attacks, 105 devices)          | PCAP published → Zeek → `adapter-zeek`                            | T1/T2/T3 detectors: scans, floods, brute force, Mirai, spoofing                          | Proxyware, OT                                  |
| **IoT-23** (Stratosphere Lab)                              | PCAP and Zeek `conn.log` published → `adapter-zeek`               | Real malware C2 and propagation; long benign captures                                    | OT, TLS fingerprint detectors (no JA4 in logs) |
| **IoT network intrusion dataset** (IEEE DataPort, 42 PCAP) | PCAP including ARP-spoofing, SYN flood, scans, Mirai brute force  | `arp-spoof` and other T4 checks, after the host-side ARP/DHCP extraction is scripted     | Long-run FP estimates (captures are short)     |
| **CICIoMT2024** (UNB CIC)                                  | PCAP for Wi-Fi/MQTT traffic                                       | MQTT detectors (`mqtt-*`), floods against brokers                                        | Non-MQTT devices                               |
| **CIC IoT-DIAD 2024**                                      | Published as extracted features. Raw PCAP availability unverified | Nothing until the human confirms raw PCAP is downloadable                                | —                                              |
| **N-BaIoT**                                                | 115 pre-computed statistics per record. No flows, no PCAP         | **Nothing.** The engine consumes events, not feature vectors. Removed from the plan (D9) | Any engine metric                              |

No public dataset found covers BADBOX/Kimwolf-style proxyware or BACnet/Modbus writes against a building. Those detectors stay on **synthetic replay only**, and every place they are described says so.

### C6.2 Protocol

1. Per device, sort events by `ts`. Learn on the benign prefix, at least 24 h when the capture has it; otherwise record the actual learning span next to every result.
2. `lock()`, then replay the rest including attacks, with all tiers the source provides.
3. **Detection** = at least one anomaly at `medium` or above on the attacking device inside the labeled attack interval plus 5 minutes. **Time to detect** = first such anomaly minus attack start.
4. **False positives** = anomalies at `medium` or above on benign intervals, divided by benign device-days.
5. Report every rate with its count and a 95 % Wilson interval. A rate from fewer than 20 attack instances is printed as "n too small", not as a percentage.
6. **Ablation.** For each detector, recompute detection with it disabled. A detector with zero unique detections and a false-positive rate above its C6.3 gate gets a spec change proposal: default `enabled: false` or severity `info`. The harness writes the proposal; the human decides.
7. **Evasion suite** (synthetic, in `eval/evasion/`): slow scan at 1 host per window, beacon with 40 % jitter, exfil at 0.9 × the `slow-exfil` limit, flood split across 10 destinations. The results are published as **known blind spots**. Do not tune thresholds against this suite.

Short lab captures make FP-per-day estimates weak. They support the 0.6 gate. They do not replace the 30-day pilot for 1.0.

### C6.3 Gates

| Severity | Max false positives     |
| -------- | ----------------------- |
| ≥ high   | < 1 per device per week |
| medium   | < 1 per device per day  |

- `eval/run.mjs --dataset <name> --zeek-logs <dir>` writes `eval/results/<dataset>.json` and `.md`. README numbers are copied from those files only. **The human runs the datasets; the agent writes the harness.**
- **Publish the misses** next to the hits.

## C7. Security of the package itself

- Zero runtime dependencies in core. Adapters and exporters pin exact versions.
- `npm publish --provenance` from CI; 2FA on the npm account.
- `SECURITY.md` with a disclosure address and response time.
- Fuzz `feed()` and `importBaseline()` with random input (built-in `node:test` + a seeded generator).
- First npm publish is manual with 2FA; later releases use npm trusted publishing (OIDC) from GitHub Actions. No long-lived npm tokens anywhere.
- **Regulation.** If you sell iotwarden, or a gateway containing it, into the EU, it is a product with digital elements under the Cyber Resilience Act. Article 14 reporting has applied since **11 September 2026**: actively exploited vulnerabilities and severe incidents go through ENISA's Single Reporting Platform, which went live that day and routes one submission to the coordinating CSIRT and ENISA. It is staged: early warning within 24 h, then notification, then a final report. At launch the platform takes web forms, not an API, so plan a human step. Reporting also covers products already on the EU market. Most other CRA obligations apply from **11 December 2027**. Whether a free open-source library falls under manufacturer or steward rules is a legal question; ask a lawyer before the first EU sale.

## C8. Package layout

```
iotwarden/                 (core, npm tarball)
  src/index.js  src/index.d.ts
  src/engine/   src/detectors/<id>.js   src/data/psl.json  src/data/attack-map.json
  README.md LICENSE CHANGELOG.md SECURITY.md
repo only (not published): test/ eval/ bench/ examples/ fuzz/
separate packages: @iotwarden/adapter-*, @iotwarden/export-*
```

`package.json`: `exports` with `types` + `require`; `files` whitelist; `repository`, `bugs`, `homepage`; `engines.node >= 22`; `sideEffects: false`. Check with `npm pack --dry-run` before each publish.

## C9. Versioning

Semver. While 0.x, minor may break API. Changing any threshold formula or default is a minor bump because it changes which alerts fire. Baseline format change bumps baseline `version`.

## C10. Roadmap

Rows 0.1–0.4 are history. Their gate column records what was planned; the **Met?** column records what happened.

| Release | Scope                                                                                                                                                                                                                                                         | Gate                                                                                                                              | Met?             |
| ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- | ---------------- |
| **0.1** | Engine fixes, original 4 detectors, plugin interface                                                                                                                                                                                                          | All v1 acceptance tests                                                                                                           | Yes              |
| **0.2** | T1/T2, hard rules, 0.2 detectors, conntrack + dnsmasq adapters                                                                                                                                                                                                | CICIoT2023 Recon/DDoS/Mirai ≥ 90 %, FP gates                                                                                      | **No — not run** |
| **0.3** | 0.3 detectors, T4, incidents, proxyware, class priors                                                                                                                                                                                                         | IoT-23 results published; BADBOX/Kimwolf replay                                                                                   | Replay only      |
| **0.4** | T3, T5, OT, MQTT/ONVIF, fleet, Zeek/Suricata adapters, exporters                                                                                                                                                                                              | 30-day pilot, home + building                                                                                                     | **No**           |
| **0.5** | Part E WP-0 to WP-8: defects D1–D12, learning quality, evidence/dedup, checkpoint, `identity-change`, B20 rows, fuzz, bench                                                                                                                                   | `npm run gate` with the all-tier benign matrix; fuzz 100,000 inputs clean; bench budgets met; `spec-coverage` clean               | —                |
| **0.6** | WP-9, WP-10: eval harness, OCSF version option. Detector dispositions from ablation                                                                                                                                                                           | CICIoT2023 and IoT-23 results files exist and are in the README, misses included; C6.3 FP gates met for every default-on detector | —                |
| **1.0** | MUD input, API freeze, security review                                                                                                                                                                                                                        | 0.6 gate met; 30-day pilot on ≥ 1 home and ≥ 1 building with FP per device-day published; one minor release with no API change    | —                |
| **1.x** | `exploit-probe-http`, `day-of-week-drift`, `sni-ip-mismatch`, `young-domain`, `discovery-spoof`, `fleet-baseline-poisoning`, `mac-randomization-churn`, `ot-schedule-drift`, `reverse-shell-shape`, `ttl-anomaly`, `llmnr-nbns-poison`, `dns-answer-mismatch` | Each one: benign all-tier run + an eval or replay result                                                                          | —                |

---

# PART D — DELIBERATELY NOT INCLUDED

| Idea                                 | Why not                                                                                                                                                                                                                                                                                                                 |
| ------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Payload signatures / DPI             | Suricata and Snort already do this with thousands of maintained rules. Use their output as T3 input instead of competing.                                                                                                                                                                                               |
| Deep-learning anomaly models in core | Need training data per device type, are hard to explain to an operator, and would break the zero-dependency and small-memory goals. If wanted later: a separate `@iotwarden/ml` package that consumes the same events and emits `anomaly` with `confidence`. Must beat the statistical detectors on C6 metrics to ship. |
| Packet capture                       | Needs native bindings and root. The gateway already has better tools (conntrack, eBPF, Zeek).                                                                                                                                                                                                                           |
| Automatic blocking                   | A false positive on a lock, alarm or medical device can cause real harm. Hosts may block; the library never does.                                                                                                                                                                                                       |
| TLS interception                     | Breaks device certificate pinning, creates a huge liability, and is unnecessary for metadata detection.                                                                                                                                                                                                                 |
| Bundled threat feeds                 | License terms and API key rules change. A stale feed baked into an npm package is worse than none.                                                                                                                                                                                                                      |

---

# Appendix — v1 acceptance tests (still required for 0.1)

1. `flush()` offset 30 s from window boundaries yields the same alerts as boundary-aligned flushes.
2. Idle-heavy learning period: volume threshold counts silent windows.
3. 1 M distinct `dst` values keep heap growth bounded.
4. `importBaseline` with `__proto__`, oversize arrays or mismatched `windowMs` throws and leaves state unchanged.
5. `allow()` suppresses further `new-destination` for that host.
6. `relearn()` emits nothing until `learnMs` passes, then emits `learned`.
7. A throwing listener does not stop processing.
8. Non-UTC `hourOf`: `wrong-time` fires once per local day.
9. Realistic camera volume (~15 MB/window) produces no `volume-spike` in a normal week.

Added for 0.2+: one test per detector for "fires on attack", "silent on benign", "respects caps", and "survives export/import". Hard-rule detectors also get a "fires during learning" test.

---

# PART E — WORK PACKAGES FOR THE CODING AGENT

Do these in order. One WP per session unless the human says otherwise. Each WP: write the SPEC/CHANGELOG lines it needs first (most are already in this file), implement, test, run the gate, write `docs/progress/WP-<n>.md` with the real gate output, then **stop**.

Standing rules from `01-PROJECT.md` and `04-HOW-TO-ADD.md` still apply: zero runtime deps, no `Date.now()`/`Math.random()` in tests, caps with a test that hits them, no invented metrics, no publish/push/commit unless asked, no JA4 computation, no bundled feeds.

Gate for every WP:

```
export PATH="$HOME/.nvm/versions/node/v24.21.0/bin:$PATH"
npm run gate && npm run demo
```

### WP-0 — Spec/code reconciliation tooling (D10, D11, D12)

- `scripts/spec-coverage.mjs` as described under "Catalog total". Add to `npm run gate`.
- Add `meta` to every detector file. Values come from the SPEC rows; where a row and the code disagree, the code wins only for numbers listed in "Defaults shipped in 0.x"; anything else goes to `docs/QUESTIONS.md`.
- Accept `type: 'discovery'` in `validate.js` (A2.1a). Test: valid event accepted, bad `proto` dropped as `FIELD_DROPPED`.
- Generate `docs/DETECTORS.md` from `meta` + `defaults`.
- **Done when:** `spec-coverage` passes and lists `identity-change` and the B20 rows as "Rel 0.5, not yet implemented" without failing (they become failures once core is bumped to 0.5.0).

### WP-1 — All-tier benign matrix (D1). Highest-value item in this spec.

- New `packages/core/test/benign-matrix-tiers.test.js`: `tiers: ['T0','T1','T2','T3','T4','T5']`, every class in `test/fixtures/profiles.js` plus the new `smart-tv` profile, 14 days × 3 seeds, simulator emitting every tier the profile has. Assertion: zero anomalies at `medium` or above; anomalies at `low`/`info` are listed in the test output.
- Extend `sim.js` so every profile emits realistic T1–T5 events (flows with both directions and TCP outcomes, DNS with answers and TTLs, TLS with stable JA4 and issuer, ARP/DHCP renewals with lease changes, BACnet reads and scheduled writes for `hvac-controller`, MQTT publishes for `thermostat`). Profiles must include the ordinary noise that breaks naive detectors: DHCP lease renewals with a new IP, CDN answers rotating within one family, NTP to two pool servers, a firmware download of 30 MB once in 14 days.
- **Expect failures.** For each failing detector: fix the detector logic if it is wrong; if a threshold must move, change SPEC "Defaults shipped" + CHANGELOG in the same commit and record the before/after in `docs/progress/WP-1.md`. Never weaken the assertion, never exclude a detector from the run.
- **Done when:** the new test passes with no detector excluded, and `docs/progress/WP-1.md` lists every threshold that changed and why.

### WP-2 — Event time (D2, D3)

- Watermark, `reorderMs`, `LATE_EVENT`, `flush()` to watermark, `tick()` (A2.3, A4.1).
- Move `went-silent` to `tick()` (B11 fix). Tests: unplugged camera alerts once after the learned limit at a `tick(now)` inside its active hours; no alert at a tick outside active hours; no alert after `forget()`; a restart that ticks months later at the watermark does not alert.
- Reorder tests: two adapters' events interleaved with ≤ 2 s skew and `reorderMs: 5000` → no `clock-jump`, same anomalies as the sorted stream; skew 10 s → one `clock-jump`.
- **Done when:** the six prototype tests and both benign matrices pass unchanged.

### WP-3 — Silent-blindness and learning quality (D4, D5)

- `tier-silent` (B11, B20). `SUSPICIOUS_LEARNING` with the reason table in B10; rename the existing learning warnings to it (CHANGELOG: breaking warning-code change). `stats().learningQuality`, `minLearnWindows`, `LEARNING_EXTENDED`, `LOCKED_UNREVIEWED`.
- **Done when:** a test with T2 enabled and DNS events stopping for 6 h fires `tier-silent` naming the DNS detectors; each `SUSPICIOUS_LEARNING` reason has a firing test and the benign matrices emit none.

### WP-4 — Anomaly evidence, fingerprint, dedup (D6)

- A7.1 fields, C1 dedup rule, `evidence: false` option, `index.d.ts` update.
- **Done when:** the `0.0.0.0` answer still yields both detector anomalies (existing test unchanged) but the incident score counts one; fingerprint is identical across an `exportBaseline`/`importBaseline` restart for the same fact.

### WP-5 — `identity-change`

- B20 row. `dhcp.fingerprint` field (A2.1a). Learn per MAC, alert while watching. Cap 5,000 MACs on `ctx.scratch`, included in `checkpoint()` once WP-7 lands.
- **Done when:** the standard four detector tests exist (fires, silent on benign all-tier, cap, export/import).

### WP-6 — B20 detectors and `smart-tv` class (D8)

- `egress-flood`, `proxy-sdk-traffic`, `proxy-sdk` indicator type, `smart-tv` class JSON and profile, `packet-flood` `data.bytesPerPacket`, `dedupGroup: 'flood'`.
- Replay test `test/replay/large-udp-flood.test.js`: 1,400-byte UDP at 60,000 packets per window to one public address → `egress-flood` fires, during learning too.
- Replay test `test/replay/smart-tv-proxy-sdk.test.js`: smart TV contacts a `proxy-sdk` indicator, then `lan-via-proxy` shape → medium `proxy-sdk-traffic` with `consentPossible: true`, then critical `lan-via-proxy`, one incident.
- **Done when:** both replays pass and the all-tier benign matrix still passes.

### WP-7 — Checkpoint and restore (D7)

- `checkpoint()` / `restore()` (A4.1) including scratch tables. HMAC via the same key path as baselines.
- Test: learn ARP bindings, checkpoint, new engine, restore, attacker claims the gateway IP first → `arp-spoof` fires (it would not without the restore).
- Fuzz-style test: 1,000 seeded corrupt checkpoints are rejected and leave state unchanged.

### WP-8 — Phase 5 hardening (from `CURSOR_BUILD.md`)

- Fuzz (`fuzz/feed.fuzz.js`, `fuzz/baseline.fuzz.js`, add `fuzz/checkpoint.fuzz.js`), 100,000 seeded inputs each.
- Bench with **all tiers on** (the 2.1 bench measured T0 only by default). Proxy budgets on x86 CI: median `feed()` < 10 µs, < 100 KB per watching device. Raspberry Pi 4 numbers are run by the human and pasted into `docs/BENCHMARKS.md`.
- Bump core to `0.5.0` only after WP-0 to WP-8 pass. Stop.

### WP-9 — Evaluation harness (0.6). Requires the human's explicit "go".

- `eval/run.mjs`, label joiners for CICIoT2023 and IoT-23 first, then the IEEE DataPort ARP set and CICIoMT2024. C6.2 protocol exactly, including Wilson intervals, ablation and the evasion suite.
- The agent never downloads datasets and never writes a number into a README. The human runs it.

### WP-10 — `export-ocsf` version option (0.6)

- C3 table. Test against the vendored 1.4.0 required-field fixture.

### Questions to put in `docs/QUESTIONS.md` before WP-1 starts

- **Q-1** WP-1 will move thresholds. Should a moved threshold bump core to 0.5.0 immediately or wait for WP-8? (Spec default: wait.)
- **Q-2** Is `minLearnWindows: 500` the right production recommendation for low-traffic devices like plugs (a heartbeat every 30 s gives 1,440 active windows a day, so yes), and for printers that may be idle for days (likely no)? Per-class value instead?
- **Q-3** When should the `reorderMs` default flip from 0 to 5000? Spec proposal: in 0.6, after WP-2 has run on real adapter output.
- **Q-4** Should `proxy-sdk-traffic` on a `smart-tv` be `medium` (consent possible) or `high` (Kimwolf showed the LAN risk regardless of consent)? Spec default: medium plus the `lan-via-proxy` escalation path.

---

# Appendix B — Sources behind the threat and standards claims (checked 2026-10-17)

| Claim in this spec                                                                 | Source                                                                                                                                                                                                                                         |
| ---------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Kimwolf spread to >2 M devices via residential proxy networks, mainly IPIDEA       | https://krebsonsecurity.com/2026/01/kimwolf-botnet-lurking-in-corporate-govt-networks/ ; https://securityaffairs.com/?p=186559                                                                                                                 |
| Aisuru, Kimwolf, JackSkid and Mossad infrastructure dismantled March 2026          | https://krebsonsecurity.com/tag/rebecca-day/                                                                                                                                                                                                   |
| Aisuru shifted toward renting devices as proxies                                   | https://krebsonsecurity.com/tag/aisuru/                                                                                                                                                                                                        |
| Aisuru 31.4 Tbps peak (Dec 2025); fast C2 movement                                 | https://fastnetmon.com/2026/02/01/aisuru-botnet-sets-a-new-ddos-record-at-31-4-tbps/                                                                                                                                                           |
| ~33 % of DDoS traffic on AS1299 from Aisuru; average duration 8.9 min              | https://www.lightreading.com/security/arelion-s-2026-ddos-report-shows-aisuru-botnet-responsible-for-nearly-one-third-of-ddos-attacks ; https://threatcluster.io/cluster/aisuru-botnet-drives-one-third-of-global-ddos-attacks-in-202-ff2470bd |
| NetNut / Popa botnet domains seized July 2026                                      | https://krebsonsecurity.com/tag/ipidea/                                                                                                                                                                                                        |
| 2,058 of 6,038 webOS/Tizen apps carry proxy SDKs; 42.5 % / 26.9 %; Bright Data     | https://www.helpnetsecurity.com/2026/06/23/tv-residential-proxy-sdk/ ; https://spur.us/blog/smart-tv-apps-residential-proxy-sdks                                                                                                               |
| SDK keeps running after the app closes; LG and Samsung restrictions                | https://ppc.land/samsung-bans-proxy-sdks-as-a-quarter-of-tizen-apps-route-strangers-traffic/ ; https://krebsonsecurity.com/2026/07/lg-to-ban-residential-proxies-from-smart-tv-apps/                                                           |
| BADBOX 2.0 pre-installed on uncertified AOSP devices; >10 M per Google's complaint | https://thehackernews.com/2025/07/google-sues-25-chinese-entities-over.html                                                                                                                                                                    |
| N-BaIoT is 115-feature records, not flows                                          | https://ieee-dataport.org/documents/n-baiot ; https://huggingface.co/datasets/codymlewis/nbaiot                                                                                                                                                |
| CICIoT2023 publishes PCAP                                                          | https://www.unb.ca/cic/datasets/iotdataset-2023.html                                                                                                                                                                                           |
| CIC IoT-DIAD 2024 published as extracted features                                  | https://unb.ca/cic/datasets/iot-diad-2024.html                                                                                                                                                                                                 |
| CICIoMT2024 Wi-Fi/MQTT PCAP                                                        | https://www.unb.ca/cic/datasets/iomt-dataset-2024.html                                                                                                                                                                                         |
| IEEE DataPort IoT network intrusion dataset, 42 PCAP incl. ARP spoofing            | https://ieee-dataport.org/open-access/iot-network-intrusion-dataset                                                                                                                                                                            |
| OCSF Detection Finding 2004, type_uid 200401–200403                                | https://docs.tenzir.com/reference/ocsf/1-4-0/classes/detection_finding                                                                                                                                                                         |
| Cisco XDR ingests OCSF 1.4.0; AWS Security Hub uses OCSF 1.6                       | https://developer.cisco.com/docs/cisco-xdr/findings-intake-api-guide/ ; https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-ocsf.md                                                                                           |
| CRA Article 14 from 11 Sep 2026 via ENISA SRP; web forms at launch                 | https://digital-strategy.ec.europa.eu/en/policies/cra-reporting ; https://developer.espressif.com/blog/2026/09/esp32-cra-obligations-and-deadlines/                                                                                            |

Re-check these before each minor release. Threat facts age faster than code.
